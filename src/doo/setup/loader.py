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
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any, Protocol

import jwt

from doo.canonical.identity import (
    auth_context_id,
    compute_auth_hash,
    declared_principal_identity_key,
    principal_id,
)
from doo.ids import EngagementId, ScopeContentHash, Sha256Hex
from doo.observability.logging import get_logger
from doo.setup.config import (
    DeclaredPrincipal,
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


class MissingTokenEnvVarError(EngagementSetupError):
    """A declared `auth_contexts[].token` env-var reference is unset at load time."""


class JwtSubjectMismatchError(EngagementSetupError):
    """A declared JWT's decoded `sub` disagrees with `known_signals.jwt_sub`.

    Per the T4 spec this fails loudly at load time, naming both values — a
    declared Principal whose token doesn't match its stated identity is a setup
    error the tester must fix before any traffic is attributed.
    """


# ---------------------------------------------------------------------------
# Graph state abstraction.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class CurrentEngagementState:
    """Snapshot of the current Engagement subgraph relevant to the loader.

    `declared_principals` is the material view of the engagement's declared
    Principals (keyed by label) as currently stored in the graph — used to diff
    principal adds/removes/mods (ADR-0019). Each value is the same shape produced
    by `_principal_view`, so the diff is a plain dict comparison.
    """

    engagement_id: EngagementId
    engagement_name: str
    engagement_description: str | None
    scope_content_hash: ScopeContentHash
    kill_switch_ttl_seconds: int
    kill_switch_refresh_seconds: int
    session_cookie_names: tuple[str, ...] = ()
    declared_principals: dict[str, dict[str, Any]] = dataclasses.field(default_factory=dict)


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
            data: dict[str, str] = json.loads(self.ledger_path.read_text())
            return data
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


@dataclasses.dataclass(frozen=True, slots=True)
class _ResolvedAuthContext:
    """A declared AuthContext after env-var resolution + JWT cross-check.

    Carries only the secret-free derived material: the `auth_hash`, the kind,
    decoded (unverified) JWT claims, and a derived `validity_window`. The raw
    token is *never* stored here — it is hashed and discarded.
    """

    auth_hash: Sha256Hex
    kind: str
    bearer_claims: dict[str, str | int | float | bool | None]
    validity_window: dict[str, Any] | None


def _resolve_env_token(env_var_name: str, *, principal_label: str, env: dict[str, str]) -> str:
    value = env.get(env_var_name)
    if value is None or value == "":
        raise MissingTokenEnvVarError(
            f"declared principal {principal_label!r}: token env-var ${{{env_var_name}}} "
            "is unset or empty at load time (ADR-0012: tokens come from the "
            "environment, never the YAML)"
        )
    return value


def _decode_jwt_unverified(token: str) -> dict[str, Any]:
    """Decode a JWT without verification; `{}` if it isn't a JWT (ADR-0015)."""

    try:
        decoded = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
    except jwt.PyJWTError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _resolve_auth_context(
    decl: Any,
    *,
    principal: DeclaredPrincipal,
    env: dict[str, str],
) -> _ResolvedAuthContext:
    """Resolve one declared AuthContext: env token -> hash, JWT cross-check, exp.

    Raw token resolved here is hashed and immediately dropped — only the hash and
    derived metadata escape this function (ADR-0015).
    """

    token = _resolve_env_token(decl.env_var_name, principal_label=principal.label, env=env)
    auth_hash = compute_auth_hash(decl.kind, token)

    bearer_claims: dict[str, str | int | float | bool | None] = {}
    validity_window: dict[str, Any] | None = None

    if decl.kind == "bearer":
        decoded = _decode_jwt_unverified(token)
        # Cross-check decoded `sub` vs declared `known_signals.jwt_sub`.
        declared_sub = principal.known_signals.jwt_sub
        token_sub = decoded.get("sub")
        if declared_sub is not None and token_sub is not None and str(token_sub) != declared_sub:
            raise JwtSubjectMismatchError(
                f"declared principal {principal.label!r}: token `sub` claim "
                f"{str(token_sub)!r} disagrees with known_signals.jwt_sub "
                f"{declared_sub!r}. Fix the token or the declared signal before loading."
            )
        # Keep only scalar claims (cue/graph carry scalars only).
        for key, value in decoded.items():
            if isinstance(value, str | int | float | bool) or value is None:
                bearer_claims[str(key)] = value
        exp = decoded.get("exp")
        if isinstance(exp, int | float):
            validity_window = {
                "exp": datetime.fromtimestamp(float(exp), tz=UTC).isoformat()
            }

    # The raw `token` goes out of scope here and is never persisted.
    return _ResolvedAuthContext(
        auth_hash=auth_hash,
        kind=decl.kind,
        bearer_claims=bearer_claims,
        validity_window=validity_window,
    )


def _principal_view(
    principal: DeclaredPrincipal, resolved: tuple[_ResolvedAuthContext, ...]
) -> dict[str, Any]:
    """Material view of a declared Principal for diffing (ADR-0019).

    Secret-free by construction: only `auth_hash`es and known-signal values,
    never raw tokens. A change to any field (token reference -> different hash,
    known_signals, auth-context kinds) is a material diff.
    """

    auth_contexts: list[dict[str, Any]] = sorted(
        (
            {
                "kind": r.kind,
                "auth_hash": r.auth_hash,
                "validity_window": r.validity_window,
            }
            for r in resolved
        ),
        key=lambda a: str(a["auth_hash"]),
    )
    return {
        "label": principal.label,
        "description": principal.description,
        "auth_contexts": auth_contexts,
        "known_signals": {
            "jwt_sub": principal.known_signals.jwt_sub,
            "me_user_id": principal.known_signals.me_user_id,
            "email": principal.known_signals.email,
            "headers": dict(sorted(principal.known_signals.headers.items())),
        },
    }


def _resolve_principals(
    config: EngagementConfig, *, env: dict[str, str]
) -> dict[str, tuple[DeclaredPrincipal, tuple[_ResolvedAuthContext, ...], dict[str, Any]]]:
    """Resolve every declared Principal: env tokens, JWT cross-checks, views.

    Returns a label-keyed map of `(principal, resolved_auth_contexts, view)`.
    Raises `MissingTokenEnvVarError` / `JwtSubjectMismatchError` loudly.
    """

    out: dict[str, tuple[DeclaredPrincipal, tuple[_ResolvedAuthContext, ...], dict[str, Any]]] = {}
    for principal in config.principals:
        resolved = tuple(
            _resolve_auth_context(ac, principal=principal, env=env)
            for ac in principal.auth_contexts
        )
        view = _principal_view(principal, resolved)
        out[principal.label] = (principal, resolved, view)
    return out


def _build_diff(
    *,
    engagement_id: EngagementId,
    current: CurrentEngagementState,
    desired_scope_view: dict[str, Any],
    desired_kill_switch: dict[str, Any],
    desired_session_cookie_names: list[str],
    current_scope_view: dict[str, Any] | None,
    desired_principal_views: dict[str, dict[str, Any]] | None = None,
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
        "session_cookie_names": list(current.session_cookie_names),
        "principals": current.declared_principals,
    }
    desired_view = {
        "scope": desired_scope_view,
        "kill_switch": desired_kill_switch,
        "session_cookie_names": desired_session_cookie_names,
        "principals": desired_principal_views if desired_principal_views is not None else {},
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
    env: dict[str, str] | None = None,
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
        env=env,
    )

    if prior_id is None:
        ledger.set(yaml_path, config.engagement.id)
    return result


def _principal_mutations(
    *,
    engagement_id: EngagementId,
    principal: DeclaredPrincipal,
    resolved: tuple[_ResolvedAuthContext, ...],
    view: dict[str, Any],
    now: datetime,
) -> list[PlannedMutation]:
    """Emit the `principal_declare` + `auth_context_declare` mutations (ADR-0010).

    Declared Principal: `tier="declared"`, `source="manual"`, `confidence=1.0`,
    `confidence_method="manual"`. Each AuthContext is engagement-scoped and joined
    by an `OF_PRINCIPAL` edge. The mutation properties carry only secret-free
    derived material (hashes, claims, validity window).
    """

    identity_key = declared_principal_identity_key(principal.label)
    p_id = principal_id(engagement_id, identity_key)
    cross = {
        "source": "manual",
        "source_id": None,
        "confidence": 1.0,
        "confidence_method": "manual",
        "first_seen": now,
        "last_seen": now,
        "ingested_at": now,
        "status": "active",
    }
    out: list[PlannedMutation] = [
        PlannedMutation(
            kind="principal_declare",
            properties={
                "engagement_id": engagement_id,
                "id": p_id,
                "identity_key": identity_key,
                "tier": "declared",
                "label": principal.label,
                "description": principal.description,
                "known_signals": view["known_signals"],
                **cross,
            },
        )
    ]
    for r in resolved:
        ac_id = auth_context_id(engagement_id, r.auth_hash)
        out.append(
            PlannedMutation(
                kind="auth_context_declare",
                properties={
                    "engagement_id": engagement_id,
                    "id": ac_id,
                    "auth_hash": r.auth_hash,
                    "token_kind": r.kind,
                    "tier": "declared",
                    "is_anonymous": False,
                    "validity_window": r.validity_window,
                    "bearer_claims": r.bearer_claims,
                    "principal_identity_key": identity_key,
                    **cross,
                },
            )
        )
    return out


def _principal_removal_mutations(
    *, engagement_id: EngagementId, label: str
) -> list[PlannedMutation]:
    """Retract a declared Principal that was removed from the YAML (ADR-0019)."""

    return [
        PlannedMutation(
            kind="principal_retract",
            properties={
                "engagement_id": engagement_id,
                "identity_key": declared_principal_identity_key(label),
            },
        )
    ]


def load_engagement(
    config: EngagementConfig,
    state: GraphState,
    *,
    apply: bool = False,
    stdin: IO[str] | None = None,
    stdout: IO[str] | None = None,
    now: datetime | None = None,
    env: dict[str, str] | None = None,
) -> EngagementLoadResult:
    """Idempotent create-or-reattach.

    No filesystem / no YAML — caller has already turned a YAML file into a
    validated config. Suitable for direct programmatic use and for tests.

    `env` is the environment used to resolve `${VAR}` token references; defaults
    to `os.environ`. Injectable so tests need not mutate the real environment.
    """

    if now is None:
        now = datetime.now(UTC)
    if env is None:
        env = dict(os.environ)

    scope_content_hash = compute_scope_content_hash(config.scope)
    desired_scope_view = _scope_view(config)
    desired_kill_switch: dict[str, Any] = {
        "backend": config.kill_switch.backend,
        "lease_ttl_seconds": config.kill_switch.lease_ttl_seconds,
        "refresh_interval_seconds": config.kill_switch.refresh_interval_seconds,
    }

    # Resolve declared Principals up front (env tokens, JWT cross-check, exp).
    # Raises loudly on a missing env var or a sub/jwt_sub mismatch.
    resolved_principals = _resolve_principals(config, env=env)
    desired_principal_views = {
        label: view for label, (_p, _r, view) in resolved_principals.items()
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
                    "session_cookie_names": list(config.auth.session_cookie_names),
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
        for principal, resolved, view in resolved_principals.values():
            mutations.extend(
                _principal_mutations(
                    engagement_id=config.engagement.id,
                    principal=principal,
                    resolved=resolved,
                    view=view,
                    now=now,
                )
            )
        state.apply_mutations(tuple(mutations))
        log.info(
            "engagement.created",
            engagement_id=config.engagement.id,
            scope_content_hash=scope_content_hash,
            declared_principals=len(resolved_principals),
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
    session_cookies_changed = tuple(current.session_cookie_names) != tuple(
        config.auth.session_cookie_names
    )

    # Principal diff (ADR-0019): adds, removes, and mods are material. The
    # comparison is over the secret-free `_principal_view` dicts.
    current_principal_views = current.declared_principals
    principals_added = sorted(
        set(desired_principal_views) - set(current_principal_views)
    )
    principals_removed = sorted(
        set(current_principal_views) - set(desired_principal_views)
    )
    principals_modified = sorted(
        label
        for label in set(desired_principal_views) & set(current_principal_views)
        if desired_principal_views[label] != current_principal_views[label]
    )
    principals_changed = bool(
        principals_added or principals_removed or principals_modified
    )

    material = (
        scope_changed or killswitch_changed or principals_changed or session_cookies_changed
    )
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
            desired_session_cookie_names=list(config.auth.session_cookie_names),
            current_scope_view=None,
            desired_principal_views=desired_principal_views,
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

    if killswitch_changed or name_changed or description_changed or session_cookies_changed:
        mutations.append(
            PlannedMutation(
                kind="engagement_update",
                properties={
                    "id": config.engagement.id,
                    "name": config.engagement.name,
                    "description": config.engagement.description,
                    "kill_switch": desired_kill_switch,
                    "session_cookie_names": list(config.auth.session_cookie_names),
                    "last_seen": now,
                },
            )
        )

    # Principal adds + mods: (re-)declare. Removes: retract. Unrelated declared
    # Principals (neither added/removed/modified) emit no mutation.
    for label in (*principals_added, *principals_modified):
        principal, resolved, view = resolved_principals[label]
        mutations.extend(
            _principal_mutations(
                engagement_id=config.engagement.id,
                principal=principal,
                resolved=resolved,
                view=view,
                now=now,
            )
        )
    for label in principals_removed:
        mutations.extend(
            _principal_removal_mutations(engagement_id=config.engagement.id, label=label)
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
