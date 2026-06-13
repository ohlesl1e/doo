"""OPA bundle generator: `Scope` node → `data.json` (ADR-0046).

The dispatcher's Rego is a small **fixed** ruleset checked into the repo; the
per-engagement *facts* are this generated `data` document. Generation keeps one
source of truth — the `Scope` node the planner's `is_in_scope` reads — so
planner-side and dispatcher-side scope checks agree by construction
(ADR-0020/0038/0046).

Per-engagement `.rego` overlay (tester-authored extra deny rules) is supported
but optional: a path under the engagement's bundle dir, loaded alongside the
fixed rules.

The bundle is **regenerated** at every `doo dispatch run` (cheap: one graph
read + one JSON dump) so a Scope change applied via `engagement start` is
immediately authoritative without a separate "rebuild bundle" step.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
from doo.setup.config import Environment, ScopeRules

log = get_logger(__name__)

# The fixed Rego ruleset, checked in alongside this module.
_REGO_DIR = Path(__file__).resolve().parent
FIXED_REGO_PATH = _REGO_DIR / "scope.rego"


def generate_data(scope: ScopeRules, *, environment: Environment) -> dict[str, object]:
    """Build the OPA `data` document for one engagement (ADR-0046).

    `data.scope = {allowed_hosts, method_allowlist, path_globs,
    payload_class_denylist, time_windows, environment}`. Deterministic: the same
    `ScopeRules` always produces the same document (sorted where order is not
    semantic, mirroring the canonicaliser in `setup/config.py`). The Rego rules
    read **only** this; no graph access inside policy (ADR-0003).

    Host patterns are pre-parsed into `(scheme|null, hostname, port|null,
    is_glob, suffix)` so the Rego's host-match is a plain comparison, not a
    string-parse — keeping the Rego ruleset simple and exactly mirroring
    `policy.scope._parse_host_pattern`.
    """

    from doo.policy.scope import _parse_host_pattern

    hosts: list[dict[str, object]] = []
    for pattern in sorted(scope.host_patterns):
        scheme, hostname, port = _parse_host_pattern(pattern)
        is_glob = hostname.startswith("*.")
        hosts.append(
            {
                "raw": pattern,
                "scheme": scheme,
                "hostname": hostname,
                "port": port,
                "is_glob": is_glob,
                # `suffix` is the `.example.com` part of `*.example.com`; the Rego
                # does an `endswith(host, suffix)` instead of string surgery.
                "suffix": hostname[1:] if is_glob else None,
            }
        )

    tw = None
    if scope.time_window is not None:
        tw = {
            "start_hour_utc": scope.time_window.start_hour_utc,
            "end_hour_utc": scope.time_window.end_hour_utc,
            "weekdays": sorted(scope.time_window.weekdays),
        }

    return {
        "scope": {
            "allowed_hosts": hosts,
            "method_allowlist": sorted(m.upper() for m in scope.allowed_methods),
            "path_globs": list(scope.allowed_path_patterns),
            "payload_class_denylist": sorted(scope.payload_class_denylist),
            "time_window": tw,
            "environment": environment,
        }
    }


@dataclass(frozen=True, slots=True)
class Bundle:
    """One engagement's OPA bundle: the data + the rego file paths to load.

    `rego_paths` always includes the fixed ruleset; an overlay (when present)
    is appended. The OPA client passes each as a `-d` arg to `opa eval`.
    """

    engagement_id: EngagementId
    data: dict[str, object]
    rego_paths: tuple[Path, ...]
    bundle_dir: Path | None = None


def load_scope_for_engagement(
    client: Neo4jClient, engagement_id: EngagementId
) -> tuple[ScopeRules, Environment]:
    """Read the engagement's `Scope` rules + `environment` from the graph.

    Reuses the coverage layer's `_load_scope_rules` (the same reader the
    planner's `is_in_scope` consumes) so generation cannot drift from it.
    """

    from doo.coverage.queries import _load_scope_rules

    scope = _load_scope_rules(client, engagement_id)
    rows = client.execute_read(
        "MATCH (e:Engagement {id: $eid}) RETURN e.environment AS env LIMIT 1",
        eid=engagement_id,
    )
    env = rows[0].get("env") if rows else None
    if env not in ("staging", "production"):
        raise ValueError(
            f"engagement {engagement_id!r} has no valid `environment` "
            f"(got {env!r}); re-run `doo engagement start` with the slice-4 "
            "config (ADR-0042)"
        )
    return scope, env  # type: ignore[return-value]


def build_bundle(
    client: Neo4jClient,
    engagement_id: EngagementId,
    *,
    bundle_dir: Path | None = None,
    overlay_rego: Path | None = None,
) -> Bundle:
    """Generate + (optionally) materialise the engagement's OPA bundle on disk.

    When `bundle_dir` is given, writes `data.json` + copies the fixed rego (+
    overlay) there — the layout an OPA sidecar / `opa eval -b` expects. When
    `None`, the bundle is in-memory only (the `OpaEvalClient` passes `data` via
    `--stdin-input` and the rego via `-d <path>`, so a disk dir is optional).
    """

    scope, environment = load_scope_for_engagement(client, engagement_id)
    data = generate_data(scope, environment=environment)
    rego_paths: list[Path] = [FIXED_REGO_PATH]
    if overlay_rego is not None:
        if not overlay_rego.exists():
            raise FileNotFoundError(
                f"per-engagement overlay {overlay_rego} not found"
            )
        rego_paths.append(overlay_rego)

    if bundle_dir is not None:
        bundle_dir.mkdir(parents=True, exist_ok=True)
        (bundle_dir / "data.json").write_text(
            json.dumps(data, indent=2, sort_keys=True)
        )
        for p in rego_paths:
            shutil.copy(p, bundle_dir / p.name)
        log.info(
            "policy.bundle.written",
            engagement_id=engagement_id,
            bundle_dir=str(bundle_dir),
            rego_files=[p.name for p in rego_paths],
        )

    return Bundle(
        engagement_id=engagement_id,
        data=data,
        rego_paths=tuple(rego_paths),
        bundle_dir=bundle_dir,
    )
