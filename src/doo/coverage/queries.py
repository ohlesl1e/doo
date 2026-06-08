"""The shared coverage query library (ADR-0034) — slice 2, C1 first.

Each `run_*` function is a thin consumer of the same discipline:

1. **Cypher does traversal only.** It fetches the active `Endpoint`s for one
   engagement (scoped via `for_engagement`, ADR-0017), each with its `Host`'s
   identity fields and whether it carries *any* `HIT` edge. It does **not**
   decide scope, decay confidence, or rank — those are Python.
2. **Python does the judgement.** `is_in_scope` (ADR-0020) decides scope on the
   same helper the dispatcher uses; `effective_confidence` (ADR-0005) decays;
   ranking/filtering happen here. This keeps the security-relevant predicates in
   one auditable place rather than re-expressed per query string.

C1 — *dead endpoints* — lists in-scope `Endpoint`s with no `HIT` edge of any
kind (ADR-0033: "hit" is asymmetric from C2's "reached" — any `HIT` regardless
of `response_status` or `source` proves the endpoint is not dead).

**Settle-point assumption (ADR-0022).** Coverage reads at a settle point and
assumes ingestion has drained and the deferred endpoint inference has flushed
(`CommitOrchestrator.flush`). Run after the L3 worker has drained; the CLI
documents this and may trigger a flush first. Coverage writes nothing back.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from doo.canonical.value_objects import Scheme
from doo.coverage.decay import effective_confidence
from doo.coverage.models import C1Result, C2Result, PrincipalEvidence
from doo.coverage.reached import ReachedEvidence, reached_map
from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
from doo.ontology.queries import for_engagement
from doo.policy.scope import is_in_scope
from doo.setup.config import ScopeRules

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Lightweight scope-evaluable adapters.
#
# `is_in_scope` accepts any object exposing the EndpointLike / HostLike
# attributes (structural Protocols, not the L3 node classes). These frozen
# dataclasses wrap the plain Cypher row so the pure helper can judge it without
# the ontology layer leaking into coverage.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _HostView:
    scheme: Scheme
    canonical_hostname: str
    port: int | None
    is_ip_literal: bool


@dataclass(frozen=True, slots=True)
class _EndpointView:
    method: str
    host: _HostView
    path_template: str


def _load_scope_rules(client: Neo4jClient, engagement_id: EngagementId) -> ScopeRules:
    """Reconstruct the engagement's `ScopeRules` from its `Scope` node.

    The loader stores the material scope view as a JSON string on `Scope.rules`
    (`graph_state._scope_create`). We read it back and validate it into the same
    `ScopeRules` model so `is_in_scope` runs against exactly the program's
    declared rules. Engagement-scoped via the `Engagement`->`Scope` edge, so no
    cross-engagement leak.
    """

    rows = client.execute_read(
        """
        MATCH (e:Engagement {id: $engagement_id})-[:UNDER_SCOPE]->(s:Scope)
        RETURN s.rules AS rules
        """,
        engagement_id=engagement_id,
    )
    if not rows or rows[0]["rules"] is None:
        raise ValueError(
            f"engagement {engagement_id!r} has no Scope.rules; cannot evaluate "
            "coverage (run `doo engagement start` first)"
        )
    raw = rows[0]["rules"]
    rules_dict = json.loads(raw) if isinstance(raw, str) else raw
    return ScopeRules.model_validate(rules_dict)


def _to_aware(value: Any, *, fallback: datetime) -> datetime:
    """Coerce a Neo4j temporal / python datetime to a tz-aware datetime.

    Neo4j returns `neo4j.time.DateTime`; `.to_native()` gives a python
    `datetime`. Naive values are assumed UTC. A missing `last_seen` decays from
    `fallback` (now), i.e. no decay.
    """

    if value is None:
        return fallback
    native = value.to_native() if hasattr(value, "to_native") else value
    if not isinstance(native, datetime):
        return fallback
    if native.tzinfo is None:
        return native.replace(tzinfo=UTC)
    return native


def run_c1(
    client: Neo4jClient,
    engagement_id: EngagementId,
    *,
    min_confidence: float = 0.0,
    now: datetime | None = None,
) -> list[C1Result]:
    """C1 — in-scope active `Endpoint`s with no `HIT` edge of any kind.

    Cypher fetches every active endpoint for the engagement with its host
    identity and a `HIT`-existence flag (traversal only). Python then keeps the
    rows that are (a) in scope per `is_in_scope` and (b) have no `HIT`, decays
    confidence per ADR-0005, and drops rows below `min_confidence` (default 0 =
    keep everything; low-confidence leads are surfaced, never silently hidden).

    `now` is injectable for deterministic tests; defaults to the wall clock.
    """

    run_at = now or datetime.now(UTC)
    scope = _load_scope_rules(client, engagement_id)

    frag = for_engagement(engagement_id, var="e")
    cypher = f"""
        MATCH (e:Endpoint)-[:ON_HOST]->(h:Host)
        {frag.and_("e.status = 'active'")}
        RETURN e.id AS endpoint_id,
               e.method AS method,
               e.path_template AS path_template,
               e.confidence AS confidence,
               e.last_seen AS last_seen,
               h.scheme AS scheme,
               h.canonical_hostname AS canonical_hostname,
               h.port AS port,
               h.is_ip_literal AS is_ip_literal,
               EXISTS {{ (:RequestObservation)-[:HIT]->(e) }} AS has_hit
        ORDER BY h.canonical_hostname, e.path_template, e.method
    """

    rows = client.execute_read(cypher, **frag.parameters)

    results: list[C1Result] = []
    for row in rows:
        if row["has_hit"]:
            # Any HIT — even a 401 — proves the endpoint is not dead (ADR-0033).
            continue

        endpoint = _EndpointView(
            method=str(row["method"]),
            host=_HostView(
                scheme=row["scheme"],
                canonical_hostname=str(row["canonical_hostname"]),
                port=row["port"],
                is_ip_literal=bool(row["is_ip_literal"]),
            ),
            path_template=str(row["path_template"]),
        )
        if not is_in_scope(endpoint, scope):
            continue

        stored = float(row["confidence"]) if row["confidence"] is not None else 1.0
        last_seen = _to_aware(row["last_seen"], fallback=run_at)
        eff = effective_confidence(stored, last_seen, now=run_at)
        if eff < min_confidence:
            continue

        host_label = endpoint.host.canonical_hostname
        if endpoint.host.port is not None:
            host_label = f"{host_label}:{endpoint.host.port}"

        results.append(
            C1Result(
                engagement_id=engagement_id,
                generated_at=run_at,
                endpoint_id=str(row["endpoint_id"]),
                method=endpoint.method,
                host=host_label,
                path_template=endpoint.path_template,
                effective_confidence=eff,
            )
        )

    log.info(
        "coverage.c1.complete",
        engagement_id=engagement_id,
        dead_endpoints=len(results),
        min_confidence=min_confidence,
    )
    return results


# ---------------------------------------------------------------------------
# C2 — presence-differential authz coverage (ADR-0033).
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _PrincipalView:
    """One active Principal with its CLI/display label.

    `label` is the handle the `--as` / `--not-as` flags pin and the table prints:
    the anonymous singleton reads `anon`; a declared Principal uses its manual
    `label`; a discovered Principal falls back to its `identity_key`
    (`discovered:sub:…`). All three tiers participate in pairing (ADR-0033).
    """

    principal_id: str
    label: str


def _principal_label(*, is_anonymous: bool, label: object, identity_key: str) -> str:
    """Resolve a Principal's display / pin label across the three tiers."""

    if is_anonymous:
        return "anon"
    if label is not None and str(label) != "":
        return str(label)
    return identity_key


def _load_principals(
    client: Neo4jClient, engagement_id: EngagementId
) -> list[_PrincipalView]:
    """Fetch every active Principal for the engagement with a display label.

    Declared + discovered tiers + the anonymous singleton (ADR-0033). Scoped via
    `for_engagement` (ADR-0017) and filtered to `status = 'active'` so retracted
    Principals (e.g. collapsed synthetics, ADR-0029) never appear as a pairing
    side.
    """

    frag = for_engagement(engagement_id, var="p")
    rows = client.execute_read(
        f"""
        MATCH (p:Principal)
        {frag.and_("p.status = 'active'")}
        RETURN p.id AS principal_id,
               p.is_anonymous AS is_anonymous,
               p.label AS label,
               p.identity_key AS identity_key
        ORDER BY p.identity_key
        """,
        **frag.parameters,
    )
    return [
        _PrincipalView(
            principal_id=str(row["principal_id"]),
            label=_principal_label(
                is_anonymous=bool(row["is_anonymous"]),
                label=row["label"],
                identity_key=str(row["identity_key"]),
            ),
        )
        for row in rows
    ]


def _host_label(host: _HostView) -> str:
    label = host.canonical_hostname
    if host.port is not None:
        label = f"{label}:{host.port}"
    return label


def _load_in_scope_endpoints(
    client: Neo4jClient,
    engagement_id: EngagementId,
    scope: ScopeRules,
    *,
    run_at: datetime,
) -> dict[str, dict[str, Any]]:
    """Return `{endpoint_id: {method, host_label, path_template, eff_conf}}`.

    Active engagement endpoints (with host identity) filtered through the same
    `is_in_scope` helper the dispatcher uses (ADR-0020); confidence decayed per
    ADR-0005. Shared by C2 so the authz differential is computed only over the
    endpoints the policy layer would allow.
    """

    frag = for_engagement(engagement_id, var="e")
    rows = client.execute_read(
        f"""
        MATCH (e:Endpoint)-[:ON_HOST]->(h:Host)
        {frag.and_("e.status = 'active'")}
        RETURN e.id AS endpoint_id,
               e.method AS method,
               e.path_template AS path_template,
               e.confidence AS confidence,
               e.last_seen AS last_seen,
               h.scheme AS scheme,
               h.canonical_hostname AS canonical_hostname,
               h.port AS port,
               h.is_ip_literal AS is_ip_literal
        """,
        **frag.parameters,
    )

    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        endpoint = _EndpointView(
            method=str(row["method"]),
            host=_HostView(
                scheme=row["scheme"],
                canonical_hostname=str(row["canonical_hostname"]),
                port=row["port"],
                is_ip_literal=bool(row["is_ip_literal"]),
            ),
            path_template=str(row["path_template"]),
        )
        if not is_in_scope(endpoint, scope):
            continue
        stored = float(row["confidence"]) if row["confidence"] is not None else 1.0
        last_seen = _to_aware(row["last_seen"], fallback=run_at)
        out[str(row["endpoint_id"])] = {
            "method": endpoint.method,
            "host": _host_label(endpoint.host),
            "path_template": endpoint.path_template,
            "effective_confidence": effective_confidence(stored, last_seen, now=run_at),
        }
    return out


def _evidence(
    label: str, reached: ReachedEvidence | None
) -> PrincipalEvidence | None:
    if reached is None:
        return None
    return PrincipalEvidence(
        principal_id=reached.principal_id,
        label=label,
        status=reached.status,
        response_size_bytes=reached.response_size_bytes,
        response_body_sha256=reached.response_body_sha256,
    )


def run_c2(
    client: Neo4jClient,
    engagement_id: EngagementId,
    *,
    as_label: str | None = None,
    not_as_label: str | None = None,
    min_confidence: float = 0.0,
    now: datetime | None = None,
) -> list[C2Result]:
    """C2 — endpoints reached as principal A but not as B (ADR-0033).

    For each ordered active-principal pair `(A, B)`, `A != B`, emit the in-scope
    endpoints where `reached(e, A) ∧ ¬reached(e, B)`. `reached` is the 2xx-only
    predicate from `coverage.reached` — deliberately asymmetric from C1's any-
    `HIT` "hit": a 401/403/404/5xx (or no request) on the B side counts as *not*
    reached, so a possibly-bypassable boundary surfaces instead of being hidden.

    `as_label` / `not_as_label` pin A / B by their display label (`--as` /
    `--not-as`); unset means "all". Each row carries A's success evidence and B's
    evidence-or-null `(status, response_size_bytes, response_body_sha256)`.
    Engagement-scoped (ADR-0017), `status='active'` throughout, effective
    confidence decayed (ADR-0005) with opt-in `min_confidence`. No
    `dispatch_status` filter (slice 4). `now` is injectable for tests.
    """

    run_at = now or datetime.now(UTC)
    scope = _load_scope_rules(client, engagement_id)
    principals = _load_principals(client, engagement_id)
    endpoints = _load_in_scope_endpoints(client, engagement_id, scope, run_at=run_at)
    reached = reached_map(client, engagement_id)

    a_candidates = [p for p in principals if as_label is None or p.label == as_label]
    b_candidates = [p for p in principals if not_as_label is None or p.label == not_as_label]

    results: list[C2Result] = []
    for a in a_candidates:
        for b in b_candidates:
            if a.principal_id == b.principal_id:
                continue
            for endpoint_id, ep in endpoints.items():
                ev_a = reached.get((endpoint_id, a.principal_id))
                if ev_a is None:
                    continue  # A must have genuine 2xx access (ADR-0033 A side).
                ev_b = reached.get((endpoint_id, b.principal_id))
                if ev_b is not None:
                    continue  # B reached it too — not a differential.

                eff = ep["effective_confidence"]
                if eff < min_confidence:
                    continue

                evidence_a = _evidence(a.label, ev_a)
                assert evidence_a is not None  # ev_a is not None here.
                results.append(
                    C2Result(
                        engagement_id=engagement_id,
                        generated_at=run_at,
                        endpoint_id=endpoint_id,
                        method=str(ep["method"]),
                        host=str(ep["host"]),
                        path_template=str(ep["path_template"]),
                        principal_a_label=a.label,
                        principal_b_label=b.label,
                        evidence_a=evidence_a,
                        evidence_b=_evidence(b.label, ev_b),
                        effective_confidence=eff,
                    )
                )

    results.sort(
        key=lambda r: (
            r.principal_a_label,
            r.principal_b_label,
            r.host,
            r.path_template,
            r.method,
        )
    )
    log.info(
        "coverage.c2.complete",
        engagement_id=engagement_id,
        gaps=len(results),
        principals=len(principals),
        min_confidence=min_confidence,
    )
    return results
