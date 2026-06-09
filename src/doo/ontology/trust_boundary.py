"""Flush-time `TrustBoundary` inference pass (ADR-0039, the ADR-0022 seam).

The graph-touching boundary *applier*, mirroring `ontology/tenant.py` /
`ontology/promotion.py`. It runs at flush (ADR-0022) after tenant inference and
value promotion: there is no mid-drain reader, so boundaries appear at flush
alongside the rest of the inference layer. No LLM (CLAUDE.md hard rule).

Two boundary kinds are inferred (ADR-0039); both are **evidence-gated**:

- **capability** (`scope` / `mfa` / `freshness`) — between two `AuthContext`s of
  the *same* `Principal` whose decoded `bearer_claims` (ADR-0025) show a claim
  delta in `scope` / `acr` / `amr` / `auth_time`. The pure delta decision lives
  in `canonical/trust_boundary.py`. Absent any distinguishing claim → no boundary
  (no synthesised tiers).
- **tenant** — between two `Tenant`s that share ≥1 `Endpoint` (both have
  observations on the same template). One undirected node per unordered pair.

Each boundary is a node (ADR-0002) with **exactly two** `BETWEEN` edges
(polymorphic by `kind`: capability → `AuthContext`, tenant → `Tenant`),
`DERIVED_FROM` edges to the evidencing `RequestObservation`s (so a future
boundary test reads its concrete endpoint from evidence — ADR-0039 preserves the
`TestCase` target XOR; **no endpoint edge on the boundary**), and the full
cross-cutting fields plus `inferred_at` / `code_version` (ADR-0005). Identity is
`(engagement_id, kind, between_a_id, between_b_id)` with the endpoint ids in
canonical (`min`/`max`) order, so the pass is **idempotent across re-flushes**:
the same evidence converges to the same node with no duplicates.

Role / ownership boundaries are **not** inferred (ADR-0039, deferred). The Step-5
invariants (exactly-two `BETWEEN`; kind-matched endpoint types; capability
endpoints share one Principal) are enforced here in code before any write, and a
post-write verification raises if a write somehow produced a violating shape.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from itertools import combinations

from doo.canonical.identity import trust_boundary_id
from doo.canonical.trust_boundary import (
    TENANT_KIND,
    capability_kind_for_delta,
    differing_capability_claims,
)
from doo.ids import EngagementId, TrustBoundaryId
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.resolve import cross_cutting

# TrustBoundary inference provenance tag (deterministic, no LLM).
_BOUNDARY_SOURCE = "deterministic-trustboundary"

# `code_version` for the boundary inference algorithm (ADR-0005).
_BOUNDARY_CODE_VERSION = "trustboundary-inference/1"

# How many evidencing observations to attach per side via `DERIVED_FROM`. One per
# side is enough for a boundary test to recover a concrete endpoint to replay
# (ADR-0039); capping keeps the lineage bounded on high-traffic boundaries.
_EVIDENCE_PER_SIDE = 1


class TrustBoundaryInvariantError(RuntimeError):
    """A would-be boundary violates a Step-5 invariant; the write is refused.

    Raised *before* any graph write when the inputs do not satisfy the ADR-0002 /
    ADR-0008 / Step-5 invariants (exactly two endpoints, kind-matched endpoint
    types, capability endpoints sharing one Principal). Surfacing this as an
    exception keeps a malformed boundary out of the graph entirely.
    """


@dataclass(frozen=True, slots=True)
class InferredBoundary:
    """One `TrustBoundary` MERGEd by the pass, for result reporting / L3 events."""

    boundary_node_id: TrustBoundaryId
    kind: str
    between_a_id: str
    between_b_id: str
    derived_from: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TrustBoundaryResult:
    """Outcome of one engagement's boundary inference pass."""

    capability: tuple[InferredBoundary, ...] = ()
    tenant: tuple[InferredBoundary, ...] = ()

    @property
    def boundaries(self) -> tuple[InferredBoundary, ...]:
        return self.capability + self.tenant


def infer_trust_boundaries(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    observed_at: datetime,
    ingested_at: datetime,
) -> TrustBoundaryResult:
    """Infer capability + tenant `TrustBoundary`s for one engagement (ADR-0039).

    Idempotent + re-runnable (identity-keyed MERGEs over canonical-ordered
    endpoint pairs). Returns the boundaries MERGEd, split by kind.
    """

    capability = _infer_capability_boundaries(
        client,
        engagement_id=engagement_id,
        observed_at=observed_at,
        ingested_at=ingested_at,
    )
    tenant = _infer_tenant_boundaries(
        client,
        engagement_id=engagement_id,
        observed_at=observed_at,
        ingested_at=ingested_at,
    )
    return TrustBoundaryResult(capability=tuple(capability), tenant=tuple(tenant))


# --- capability boundaries ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _AuthContextRow:
    """One AuthContext of a Principal, with its decoded claims + an evidence obs."""

    auth_context_id: str
    principal_id: str
    claims: dict[str, object]
    evidence_observations: tuple[str, ...]


def _infer_capability_boundaries(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    observed_at: datetime,
    ingested_at: datetime,
) -> list[InferredBoundary]:
    """Capability boundaries between same-Principal AuthContexts with a claim delta."""

    rows = _read_auth_contexts(client, engagement_id)
    # Group AuthContexts by their Principal (the same-Principal constraint).
    by_principal: dict[str, list[_AuthContextRow]] = {}
    for row in rows:
        by_principal.setdefault(row.principal_id, []).append(row)

    out: list[InferredBoundary] = []
    for _principal_id, acs in sorted(by_principal.items()):
        if len(acs) < 2:
            continue
        # Every unordered pair of this Principal's AuthContexts; draw a boundary
        # only where the decoded claims actually differ on a capability axis.
        for a, b in combinations(sorted(acs, key=lambda r: r.auth_context_id), 2):
            differing = differing_capability_claims(a.claims, b.claims)
            kind = capability_kind_for_delta(differing)
            if kind is None:
                continue  # evidence-gated: no distinguishing claim → no boundary
            lo, hi = sorted((a.auth_context_id, b.auth_context_id))
            lo_row = a if a.auth_context_id == lo else b
            hi_row = b if b.auth_context_id == hi else a
            # One evidencing observation from each side (so a boundary test can
            # recover a concrete endpoint for either AuthContext; ADR-0039).
            evidence = _evidence_pair(
                lo_row.evidence_observations, hi_row.evidence_observations
            )
            # Step-5 invariant guard (capability): both endpoints are AuthContexts
            # of the *same* Principal. Refuse before writing if not.
            if lo_row.principal_id != hi_row.principal_id:
                raise TrustBoundaryInvariantError(
                    "capability boundary endpoints must share one Principal: "
                    f"{lo_row.principal_id!r} != {hi_row.principal_id!r}"
                )
            b_id = trust_boundary_id(engagement_id, kind, lo, hi)
            _merge_boundary(
                client,
                engagement_id=engagement_id,
                boundary_node_id=b_id,
                kind=kind,
                between_label="AuthContext",
                between_a_id=lo,
                between_b_id=hi,
                evidence_observation_ids=evidence,
                observed_at=observed_at,
                ingested_at=ingested_at,
            )
            out.append(
                InferredBoundary(
                    boundary_node_id=b_id,
                    kind=kind,
                    between_a_id=lo,
                    between_b_id=hi,
                    derived_from=tuple(evidence),
                )
            )
    return out


def _read_auth_contexts(
    client: Neo4jClient, engagement_id: EngagementId
) -> list[_AuthContextRow]:
    """Read each non-anonymous AuthContext, its Principal, decoded claims + evidence.

    `bearer_claims` is stored as a JSON string on the AuthContext (ADR-0025); it is
    parsed in Python. The evidence observations are the `RequestObservation`s made
    under that AuthContext — capped per side downstream so a boundary test can
    recover a concrete endpoint (ADR-0039).
    """

    import json

    rows = client.execute_read(
        """
        MATCH (ac:AuthContext {engagement_id: $engagement_id})-[:OF_PRINCIPAL]->
              (p:Principal {engagement_id: $engagement_id})
        WHERE (ac.is_anonymous IS NULL OR ac.is_anonymous = false)
          AND (ac.status IS NULL OR ac.status = 'active')
        OPTIONAL MATCH (r:RequestObservation {engagement_id: $engagement_id})
                       -[:OBSERVED_UNDER]->(ac)
        WITH ac, p, collect(DISTINCT r.id) AS obs
        RETURN ac.id AS auth_context_id, p.id AS principal_id,
               ac.bearer_claims AS bearer_claims, obs AS evidence
        """,
        engagement_id=engagement_id,
    )
    out: list[_AuthContextRow] = []
    for row in rows:
        raw = row["bearer_claims"]
        claims: dict[str, object] = {}
        if raw:
            parsed = json.loads(str(raw))
            if isinstance(parsed, dict):
                claims = parsed
        evidence = tuple(str(o) for o in (row["evidence"] or []) if o is not None)
        out.append(
            _AuthContextRow(
                auth_context_id=str(row["auth_context_id"]),
                principal_id=str(row["principal_id"]),
                claims=claims,
                evidence_observations=evidence,
            )
        )
    return out


# --- tenant boundaries ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _TenantPairRow:
    """Two Tenants that share ≥1 Endpoint, with evidencing observations per side."""

    tenant_a_id: str
    tenant_b_id: str
    evidence_observations: tuple[str, ...]


def _infer_tenant_boundaries(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    observed_at: datetime,
    ingested_at: datetime,
) -> list[InferredBoundary]:
    """Tenant boundaries between Tenant pairs that share ≥1 Endpoint (ADR-0039)."""

    pairs = _read_shared_endpoint_tenant_pairs(client, engagement_id)
    out: list[InferredBoundary] = []
    for pair in pairs:
        lo, hi = sorted((pair.tenant_a_id, pair.tenant_b_id))
        b_id = trust_boundary_id(engagement_id, TENANT_KIND, lo, hi)
        _merge_boundary(
            client,
            engagement_id=engagement_id,
            boundary_node_id=b_id,
            kind=TENANT_KIND,
            between_label="Tenant",
            between_a_id=lo,
            between_b_id=hi,
            evidence_observation_ids=pair.evidence_observations,
            observed_at=observed_at,
            ingested_at=ingested_at,
        )
        out.append(
            InferredBoundary(
                boundary_node_id=b_id,
                kind=TENANT_KIND,
                between_a_id=lo,
                between_b_id=hi,
                derived_from=pair.evidence_observations,
            )
        )
    return out


def _read_shared_endpoint_tenant_pairs(
    client: Neo4jClient, engagement_id: EngagementId
) -> list[_TenantPairRow]:
    """Find unordered Tenant pairs sharing ≥1 Endpoint, with per-side evidence.

    Two tenants share an `Endpoint` when each has a Principal (`OF_TENANT`) that
    made an observation (`OBSERVED_UNDER` ← `RequestObservation` `HIT` →
    `Endpoint`) on the same Endpoint. Returns one row per unordered pair
    (`a.id < b.id`), carrying one evidencing observation from each side so a
    boundary test can recover a concrete endpoint (ADR-0039).
    """

    rows = client.execute_read(
        """
        MATCH (ta:Tenant {engagement_id: $engagement_id})<-[:OF_TENANT]-
              (:Principal)<-[:OF_PRINCIPAL]-(:AuthContext)<-[:OBSERVED_UNDER]-
              (ra:RequestObservation)-[:HIT]->(e:Endpoint {engagement_id: $engagement_id})
        MATCH (tb:Tenant {engagement_id: $engagement_id})<-[:OF_TENANT]-
              (:Principal)<-[:OF_PRINCIPAL]-(:AuthContext)<-[:OBSERVED_UNDER]-
              (rb:RequestObservation)-[:HIT]->(e)
        WHERE ta.id < tb.id
          AND (ta.status IS NULL OR ta.status = 'active')
          AND (tb.status IS NULL OR tb.status = 'active')
          AND (e.status IS NULL OR e.status = 'active')
        WITH ta, tb, collect(DISTINCT ra.id)[0] AS ev_a, collect(DISTINCT rb.id)[0] AS ev_b
        RETURN ta.id AS tenant_a_id, tb.id AS tenant_b_id, ev_a, ev_b
        """,
        engagement_id=engagement_id,
    )
    out: list[_TenantPairRow] = []
    for row in rows:
        # One evidencing observation from each side of the shared endpoint.
        seen: set[str] = set()
        evidence: list[str] = []
        for o in (row["ev_a"], row["ev_b"]):
            if o is not None and str(o) not in seen:
                seen.add(str(o))
                evidence.append(str(o))
        out.append(
            _TenantPairRow(
                tenant_a_id=str(row["tenant_a_id"]),
                tenant_b_id=str(row["tenant_b_id"]),
                evidence_observations=tuple(evidence),
            )
        )
    return out


# --- shared write + invariant guards -------------------------------------------


def _merge_boundary(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    boundary_node_id: TrustBoundaryId,
    kind: str,
    between_label: str,
    between_a_id: str,
    between_b_id: str,
    evidence_observation_ids: tuple[str, ...],
    observed_at: datetime,
    ingested_at: datetime,
) -> None:
    """MERGE one `TrustBoundary` + its two `BETWEEN` + `DERIVED_FROM` edges.

    Identity `(engagement_id, kind, between_a_id, between_b_id)` with the endpoint
    ids in canonical order, so the boundary is one undirected node per unordered
    pair and re-flushes converge (idempotent). The two `BETWEEN` edges point at the
    kind-matched endpoint nodes (`AuthContext` for capability, `Tenant` for
    tenant); the `DERIVED_FROM` edges point at the evidencing observations. **No**
    endpoint edge is written (ADR-0039: boundary tests read their endpoint from
    evidence, preserving the `TestCase` target XOR).

    Step-5 invariants are guarded *before* the write (two distinct endpoints, ≥1
    evidence) and *verified* after it (exactly two `BETWEEN`, kind-matched types).
    """

    if between_a_id == between_b_id:
        raise TrustBoundaryInvariantError(
            f"a TrustBoundary needs two distinct endpoints; got {between_a_id!r} twice"
        )
    if not evidence_observation_ids:
        raise TrustBoundaryInvariantError(
            "every inference node needs ≥1 DERIVED_FROM evidence (Step-5); "
            f"boundary {kind!r} between {between_a_id!r} and {between_b_id!r} had none"
        )

    props = cross_cutting(
        source=_BOUNDARY_SOURCE,
        source_id=None,
        observed_at=observed_at,
        ingested_at=ingested_at,
    )
    props["inferred_at"] = ingested_at
    props["code_version"] = _BOUNDARY_CODE_VERSION
    # The `BETWEEN`-endpoint label is interpolated (not parameterisable in Cypher),
    # so it is constrained to our two known labels — never user input.
    if between_label not in ("AuthContext", "Tenant"):
        raise TrustBoundaryInvariantError(
            f"unexpected BETWEEN endpoint label {between_label!r}"
        )
    client.execute_write(
        f"""
        MATCH (a:{between_label} {{engagement_id: $engagement_id, id: $between_a_id}})
        MATCH (b:{between_label} {{engagement_id: $engagement_id, id: $between_b_id}})
        MERGE (tb:TrustBoundary {{engagement_id: $engagement_id, kind: $kind,
                                 between_a_id: $between_a_id, between_b_id: $between_b_id}})
        ON CREATE SET tb.id = $boundary_id, tb += $props
        ON MATCH SET tb.last_seen = $props.last_seen, tb.status = 'active'
        MERGE (tb)-[ba:BETWEEN]->(a)
        ON CREATE SET ba.engagement_id = $engagement_id
        MERGE (tb)-[bb:BETWEEN]->(b)
        ON CREATE SET bb.engagement_id = $engagement_id
        WITH tb
        UNWIND $evidence AS oid
        MATCH (r:RequestObservation {{engagement_id: $engagement_id, id: oid}})
        MERGE (tb)-[df:DERIVED_FROM]->(r)
        ON CREATE SET df.engagement_id = $engagement_id
        """,
        engagement_id=engagement_id,
        kind=kind,
        between_a_id=between_a_id,
        between_b_id=between_b_id,
        boundary_id=boundary_node_id,
        evidence=list(evidence_observation_ids),
        props=props,
    )
    _verify_boundary_shape(
        client,
        engagement_id=engagement_id,
        boundary_node_id=boundary_node_id,
        kind=kind,
        between_label=between_label,
    )


def _verify_boundary_shape(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    boundary_node_id: TrustBoundaryId,
    kind: str,
    between_label: str,
) -> None:
    """Post-write Step-5 invariant check: exactly two kind-matched `BETWEEN` edges.

    Reads the just-written boundary back and asserts it has **exactly two**
    `BETWEEN` edges, both to nodes of the expected label, and (for capability) both
    AuthContexts' `OF_PRINCIPAL` targets are the same Principal. A violation raises
    `TrustBoundaryInvariantError` — the boundary is malformed and must not stand.
    """

    rows = client.execute_read(
        """
        MATCH (tb:TrustBoundary {engagement_id: $engagement_id, id: $boundary_id})
        OPTIONAL MATCH (tb)-[:BETWEEN]->(x)
        WITH tb, collect(x) AS endpoints
        RETURN size(endpoints) AS between_count,
               [n IN endpoints | head(labels(n))] AS labels,
               size([(tb)-[:DERIVED_FROM]->(:RequestObservation) | 1]) AS derived_count
        """,
        engagement_id=engagement_id,
        boundary_id=boundary_node_id,
    )
    if not rows:
        raise TrustBoundaryInvariantError(
            f"boundary {boundary_node_id!r} vanished after write"
        )
    between_count = int(rows[0]["between_count"])
    labels = list(rows[0]["labels"])
    derived_count = int(rows[0]["derived_count"])
    if between_count != 2:
        raise TrustBoundaryInvariantError(
            f"boundary {boundary_node_id!r} ({kind}) has {between_count} BETWEEN "
            "edges; Step-5 requires exactly two"
        )
    if any(label != between_label for label in labels):
        raise TrustBoundaryInvariantError(
            f"boundary {boundary_node_id!r} ({kind}) BETWEEN endpoints {labels!r} "
            f"do not all match expected label {between_label!r}"
        )
    if derived_count < 1:
        raise TrustBoundaryInvariantError(
            f"boundary {boundary_node_id!r} ({kind}) has no DERIVED_FROM evidence"
        )
    if kind in ("scope", "mfa", "freshness"):
        prow = client.execute_read(
            """
            MATCH (tb:TrustBoundary {engagement_id: $engagement_id, id: $boundary_id})
                  -[:BETWEEN]->(ac:AuthContext)-[:OF_PRINCIPAL]->(p:Principal)
            RETURN count(DISTINCT p) AS principals
            """,
            engagement_id=engagement_id,
            boundary_id=boundary_node_id,
        )
        if prow and int(prow[0]["principals"]) != 1:
            raise TrustBoundaryInvariantError(
                f"capability boundary {boundary_node_id!r} endpoints span "
                f"{prow[0]['principals']} Principals; Step-5 requires exactly one"
            )


def _evidence_pair(
    side_a: tuple[str, ...], side_b: tuple[str, ...]
) -> tuple[str, ...]:
    """Pick up to `_EVIDENCE_PER_SIDE` evidencing observation(s) from each side.

    A boundary test recovers a concrete endpoint to replay from the boundary's
    evidence (ADR-0039); one observation per side is enough and keeps the lineage
    bounded on high-traffic boundaries. De-duplicates if a side somehow repeats and
    if the two sides share an observation (collapses to one rather than a degenerate
    self-pair) — the result is still ≥1, satisfying the inference-node invariant.
    """

    out: list[str] = []
    seen: set[str] = set()
    for side in (side_a, side_b):
        taken = 0
        for obs in side:
            if obs not in seen:
                seen.add(obs)
                out.append(obs)
                taken += 1
                if taken >= _EVIDENCE_PER_SIDE:
                    break
    return tuple(out)
