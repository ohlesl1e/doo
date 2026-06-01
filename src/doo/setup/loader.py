"""Engagement loader — idempotent create-or-reattach per ADR-0019.

Reads a YAML file, validates as `EngagementConfig`, computes the Scope
content_hash, and upserts the Engagement + Scope subgraph in Neo4j with full
cross-cutting properties (ADR-0005) and `source = "manual"`, `confidence = 1.0`.

The "graph state" abstraction here is a small Protocol so the loader can be
tested without a live Neo4j: callers pass any object that implements
`fetch_engagement_state` and `apply_mutations`.

`load_engagement(config, state, *, apply=False, stdin=None, stdout=None)`:

- If the engagement doesn't exist → create it; return `created=True`.
- If it exists and nothing changed → no-op; return `noop=True`.
- If it exists and only cosmetic fields changed (description, scope notes) →
  apply silently; return `cosmetic=True`.
- If it exists and *material* changes are present (scope content_hash differs,
  kill-switch differs, engagement.id differs) → print a unified diff to stdout
  and require confirmation from stdin, unless `apply=True` bypasses.
- If the YAML's `engagement.id` differs from a prior load of the same YAML
  file path → raise `EngagementMismatchError` (immutable id, ADR-0019).
"""

from __future__ import annotations

import dataclasses
import difflib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any, Protocol

from doo.ids import EngagementId, ScopeContentHash
from doo.observability.logging import get_logger
from doo.setup.config import (
    EngagementConfig,
    compute_scope_content_hash,
)

log = get_logger(__name__)


class EngagementSetupError(Exception):
    """Base for loader-side errors."""


class EngagementMismatchError(EngagementSetupError):
    """A prior `start` against this YAML file path used a different engagement.id.

    Per ADR-0019, `engagement.id` is immutable; changing it means starting a
    new campaign, which is a new YAML file.
    """


class ScopeChangeRequiresConfirmation(EngagementSetupError):
    """Material change detected and confirmation was refused or unavailable."""


# ---------------------------------------------------------------------------
# Graph state abstraction.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class CurrentEngagementState:
    """Snapshot of the current Engagement subgraph relevant to the loader."""

    engagement_id: EngagementId
    engagement_name: str
    engagement_description: str | None
    scope_content_hash: ScopeContentHash
    kill_switch_ttl_seconds: int
    kill_switch_refresh_seconds: int


@dataclasses.dataclass(frozen=True, slots=True)
class PlannedMutation:
    """One write the loader intends to apply to the graph.

    The concrete Cypher writer (slice 1 / T2) translates these into MERGE
    statements; the loader stays IO-agnostic so it's testable without Neo4j.
    """

    kind: str  # "engagement_create", "engagement_update", "scope_create", ...
    properties: dict[str, Any]


class GraphState(Protocol):
    """Minimal duck-type for the loader's graph dependency.

    A real Neo4j-backed implementation lives in T2; in slice 1 the tests use a
    fake. Keeping this a Protocol means the loader's logic is pure data
    flow + IO injection.
    """

    def fetch_engagement_state(
        self, engagement_id: EngagementId
    ) -> CurrentEngagementState | None: ...

    def apply_mutations(self, mutations: tuple[PlannedMutation, ...]) -> None: ...


# ---------------------------------------------------------------------------
# YAML file -> EngagementConfig with the id-immutability ledger.
# ---------------------------------------------------------------------------


class FileLedger(Protocol):
    """Tracks which engagement_id was last loaded from each YAML file path.

    Per ADR-0019 the loader refuses to apply a YAML whose engagement.id differs
    from any prior load of the same YAML file path. The ledger is the storage
    behind that check. In slice 1 we persist it as a small JSON file alongside
    the project so the check survives restarts.
    """

    def get(self, yaml_path: Path) -> EngagementId | None: ...

    def set(self, yaml_path: Path, engagement_id: EngagementId) -> None: ...


@dataclasses.dataclass
class JsonFileLedger:
    """Default ledger persisted as `~/.doo/engagement_ledger.json` (or override)."""

    ledger_path: Path

    def _read(self) -> dict[str, str]:
        if not self.ledger_path.exists():
            return {}
        try:
            return json.loads(self.ledger_path.read_text())
        except json.JSONDecodeError:
            log.warning(
                "engagement_ledger.unreadable", path=str(self.ledger_path), action="treat_as_empty"
            )
            return {}

    def _write(self, data: dict[str, str]) -> None:
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.ledger_path.write_text(json.dumps(data, indent=2, sort_keys=True))

    def get(self, yaml_path: Path) -> EngagementId | None:
        data = self._read()
        v = data.get(str(yaml_path.resolve()))
        return EngagementId(v) if v else None

    def set(self, yaml_path: Path, engagement_id: EngagementId) -> None:
        data = self._read()
        data[str(yaml_path.resolve())] = engagement_id
        self._write(data)


# ---------------------------------------------------------------------------
# Result objects.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class EngagementLoadResult:
    """Outcome of one `load_engagement` call."""

    engagement_id: EngagementId
    scope_content_hash: ScopeContentHash
    created: bool
    noop: bool
    cosmetic_only: bool
    material_changes_applied: bool
    mutations: tuple[PlannedMutation, ...]


# ---------------------------------------------------------------------------
# Core loader.
# ---------------------------------------------------------------------------


def _scope_view(config: EngagementConfig) -> dict[str, Any]:
    """Material Scope view used for diffing (cosmetic fields stripped)."""
    s = config.scope
    return {
        "host_patterns": sorted(s.host_patterns),
        "allowed_methods": sorted(s.allowed_methods),
        "allowed_path_patterns": list(s.allowed_path_patterns),
        "payload_class_denylist": sorted(s.payload_class_denylist),
        "rate_limit": s.rate_limit.model_dump() if s.rate_limit else None,
        "time_window": s.time_window.model_dump() if s.time_window else None,
        "required_headers": sorted(s.required_headers),
    }


def _build_diff(
    *,
    engagement_id: EngagementId,
    current: CurrentEngagementState,
    desired_scope_view: dict[str, Any],
    desired_kill_switch: dict[str, Any],
    current_scope_view: dict[str, Any] | None,
) -> str:
    """Human-readable unified diff of the changes the loader would apply."""

    def render(view: dict[str, Any], label: str) -> list[str]:
        body = json.dumps(view, indent=2, sort_keys=True).splitlines(keepends=True)
        return [f"# {label}\n", *body, "\n"]

    current_view = {
        "scope": current_scope_view
        if current_scope_view is not None
        else {"content_hash": current.scope_content_hash, "rules": "<not re-derivable; only hash known>"},
        "kill_switch": {
            "lease_ttl_seconds": current.kill_switch_ttl_seconds,
            "refresh_interval_seconds": current.kill_switch_refresh_seconds,
        },
    }
    desired_view = {
        "scope": desired_scope_view,
        "kill_switch": desired_kill_switch,
    }

    current_lines = render(current_view, f"engagement {engagement_id} (current)")
    desired_lines = render(desired_view, f"engagement {engagement_id} (proposed)")
    return "".join(
        difflib.unified_diff(
            current_lines,
            desired_lines,
            fromfile="current",
            tofile="proposed",
            n=3,
        )
    )


def load_engagement_from_yaml(
    yaml_path: Path,
    state: GraphState,
    ledger: FileLedger,
    *,
    apply: bool = False,
    stdin: IO[str] | None = None,
    stdout: IO[str] | None = None,
    now: datetime | None = None,
) -> EngagementLoadResult:
    """Parse YAML, then delegate to `load_engagement`."""

    import yaml  # imported here so the package's tests can skip without PyYAML installed

    raw = yaml.safe_load(yaml_path.read_text())
    if not isinstance(raw, dict):
        raise EngagementSetupError(
            f"YAML root must be a mapping, got {type(raw).__name__} in {yaml_path}"
        )
    config = EngagementConfig.model_validate(raw)

    # ADR-0019 immutability check.
    prior_id = ledger.get(yaml_path)
    if prior_id is not None and prior_id != config.engagement.id:
        raise EngagementMismatchError(
            f"engagement.id changed for {yaml_path}: was {prior_id!r}, now "
            f"{config.engagement.id!r}. Per ADR-0019 engagement.id is immutable; "
            "start a new campaign in a new YAML file."
        )

    result = load_engagement(
        config,
        state,
        apply=apply,
        stdin=stdin,
        stdout=stdout,
        now=now,
    )

    if prior_id is None:
        ledger.set(yaml_path, config.engagement.id)
    return result


def load_engagement(
    config: EngagementConfig,
    state: GraphState,
    *,
    apply: bool = False,
    stdin: IO[str] | None = None,
    stdout: IO[str] | None = None,
    now: datetime | None = None,
) -> EngagementLoadResult:
    """Idempotent create-or-reattach.

    No filesystem / no YAML — caller has already turned a YAML file into a
    validated config. Suitable for direct programmatic use and for tests.
    """

    if now is None:
        now = datetime.now(UTC)

    scope_content_hash = compute_scope_content_hash(config.scope)
    desired_scope_view = _scope_view(config)
    desired_kill_switch: dict[str, Any] = {
        "backend": config.kill_switch.backend,
        "lease_ttl_seconds": config.kill_switch.lease_ttl_seconds,
        "refresh_interval_seconds": config.kill_switch.refresh_interval_seconds,
    }

    current = state.fetch_engagement_state(config.engagement.id)
    mutations: list[PlannedMutation] = []

    if current is None:
        # First load — full create.
        mutations.append(
            PlannedMutation(
                kind="scope_create",
                properties={
                    "content_hash": scope_content_hash,
                    "rules": desired_scope_view,
                    # Cross-cutting fields per ADR-0005.
                    "source": "manual",
                    "source_id": None,
                    "confidence": 1.0,
                    "confidence_method": "manual",
                    "first_seen": now,
                    "last_seen": now,
                    "ingested_at": now,
                    "status": "active",
                },
            )
        )
        mutations.append(
            PlannedMutation(
                kind="engagement_create",
                properties={
                    "id": config.engagement.id,
                    "name": config.engagement.name,
                    "description": config.engagement.description,
                    "time_window": config.engagement.time_window.model_dump()
                    if config.engagement.time_window
                    else None,
                    "kill_switch": desired_kill_switch,
                    # Cross-cutting fields per ADR-0005.
                    "source": "manual",
                    "source_id": None,
                    "confidence": 1.0,
                    "confidence_method": "manual",
                    "first_seen": now,
                    "last_seen": now,
                    "ingested_at": now,
                    "status": "active",
                },
            )
        )
        mutations.append(
            PlannedMutation(
                kind="engagement_under_scope",
                properties={
                    "engagement_id": config.engagement.id,
                    "scope_content_hash": scope_content_hash,
                },
            )
        )
        state.apply_mutations(tuple(mutations))
        log.info(
            "engagement.created",
            engagement_id=config.engagement.id,
            scope_content_hash=scope_content_hash,
        )
        return EngagementLoadResult(
            engagement_id=config.engagement.id,
            scope_content_hash=scope_content_hash,
            created=True,
            noop=False,
            cosmetic_only=False,
            material_changes_applied=False,
            mutations=tuple(mutations),
        )

    # Re-attach path. Decide what kind of change this is.
    scope_changed = current.scope_content_hash != scope_content_hash
    killswitch_changed = (
        current.kill_switch_ttl_seconds != desired_kill_switch["lease_ttl_seconds"]
        or current.kill_switch_refresh_seconds != desired_kill_switch["refresh_interval_seconds"]
    )
    name_changed = current.engagement_name != config.engagement.name
    description_changed = current.engagement_description != config.engagement.description

    material = scope_changed or killswitch_changed
    cosmetic = name_changed or description_changed

    if not material and not cosmetic:
        log.info("engagement.noop", engagement_id=config.engagement.id)
        return EngagementLoadResult(
            engagement_id=config.engagement.id,
            scope_content_hash=scope_content_hash,
            created=False,
            noop=True,
            cosmetic_only=False,
            material_changes_applied=False,
            mutations=(),
        )

    if material:
        # ADR-0019: material changes require confirmation unless --apply.
        diff = _build_diff(
            engagement_id=config.engagement.id,
            current=current,
            desired_scope_view=desired_scope_view,
            desired_kill_switch=desired_kill_switch,
            current_scope_view=None,
        )
        if stdout is not None:
            stdout.write(diff)
            stdout.write("\n")
        if not apply:
            if stdin is None:
                raise ScopeChangeRequiresConfirmation(
                    f"Material change detected for engagement {config.engagement.id} but "
                    "no stdin available for confirmation and `apply=False`. "
                    "Pass `apply=True` (CLI `--apply`) to bypass."
                )
            if stdout is not None:
                stdout.write("Apply these changes? [y/N]: ")
                stdout.flush() if hasattr(stdout, "flush") else None
            answer = stdin.readline().strip().lower()
            if answer not in ("y", "yes"):
                raise ScopeChangeRequiresConfirmation(
                    f"Material change for engagement {config.engagement.id} not confirmed."
                )

    # Build mutations for the changes.
    if scope_changed:
        mutations.append(
            PlannedMutation(
                kind="scope_create_or_attach",
                properties={
                    "content_hash": scope_content_hash,
                    "rules": desired_scope_view,
                    "source": "manual",
                    "source_id": None,
                    "confidence": 1.0,
                    "confidence_method": "manual",
                    "first_seen": now,
                    "last_seen": now,
                    "ingested_at": now,
                    "status": "active",
                },
            )
        )
        mutations.append(
            PlannedMutation(
                kind="engagement_rebind_scope",
                properties={
                    "engagement_id": config.engagement.id,
                    "old_scope_content_hash": current.scope_content_hash,
                    "new_scope_content_hash": scope_content_hash,
                },
            )
        )

    if killswitch_changed or name_changed or description_changed:
        mutations.append(
            PlannedMutation(
                kind="engagement_update",
                properties={
                    "id": config.engagement.id,
                    "name": config.engagement.name,
                    "description": config.engagement.description,
                    "kill_switch": desired_kill_switch,
                    "last_seen": now,
                },
            )
        )

    state.apply_mutations(tuple(mutations))
    log.info(
        "engagement.updated",
        engagement_id=config.engagement.id,
        material=material,
        cosmetic_only=not material and cosmetic,
        scope_content_hash=scope_content_hash,
    )
    return EngagementLoadResult(
        engagement_id=config.engagement.id,
        scope_content_hash=scope_content_hash,
        created=False,
        noop=False,
        cosmetic_only=not material and cosmetic,
        material_changes_applied=material,
        mutations=tuple(mutations),
    )
