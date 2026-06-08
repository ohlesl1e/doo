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
from doo.coverage.models import C1Result
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
