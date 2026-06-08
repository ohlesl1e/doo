"""The shared `reached` predicate (ADR-0033) — the authz-coverage success rule.

This is the one subtle semantic the C2 family turns on, isolated here so it can
be unit-tested directly and reused identically by C2 (and, later, C2b):

    reached(e, P) := ∃ r : (r)-[:HIT]->(e),
                          (r)-[:OBSERVED_UNDER]->(:AuthContext)-[:OF_PRINCIPAL]->(P),
                          r.response_status ∈ 200..299

"Reached as principal P" requires a **successful** observation (a 2xx), not
merely a sent request. This is deliberately **asymmetric from C1** (ADR-0033):
C1's "hit" counts *any* `HIT` edge — a 401 still proves the endpoint exists —
because C1 answers "is this endpoint dead?". C2's "reached" answers "did this
principal actually get in?", so a 401/403/404/5xx is *not* reached. On the B side
of C2 that folds "B never tried" together with "B was blocked", and both are
bypass/IDOR candidates we must not silently suppress.

This module is pure graph-read: Cypher does the 2xx traversal, Python does
nothing but shape the rows. No scope decision, no decay, no LLM (the L1-3 hard
rule) — and no body parsing, so soft-200s are surfaced as evidence, not
adjudicated here (the caller carries the per-principal evidence tuple).

The unit of work is *per-endpoint, per-principal*: `reached_map` returns, for one
engagement, every `(endpoint_id, principal_id)` pair that has at least one 2xx
observation, with the strongest evidence for that pair (used by C2 result rows).
A thin `reached` boolean wraps it for direct predicate testing.
"""

from __future__ import annotations

from dataclasses import dataclass

from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.queries import for_engagement

# The 2xx success window (ADR-0033). 3xx is treated as not-reached in slice 2
# (no passive login-redirect classifier); being conservative on the A side only
# reduces leads, which is safe.
_SUCCESS_MIN = 200
_SUCCESS_MAX = 299


@dataclass(frozen=True, slots=True)
class ReachedEvidence:
    """The strongest single 2xx observation backing `reached(e, P)`.

    Per ADR-0033 coverage *surfaces evidence, it does not adjudicate*: a human or
    the slice-3 interpreter decides the soft-200 case (200 + "access denied"
    body). So each reached pair carries the per-principal evidence tuple
    `(status, response_size_bytes, response_body_sha256)` rather than collapsing
    to a boolean. `response_body_sha256` is null until the body-metadata promotion
    has data (and for empty-body responses); callers tolerate null.
    """

    endpoint_id: str
    principal_id: str
    status: int
    response_size_bytes: int | None
    response_body_sha256: str | None


def reached_map(
    client: Neo4jClient,
    engagement_id: EngagementId,
) -> dict[tuple[str, str], ReachedEvidence]:
    """Return `{(endpoint_id, principal_id): evidence}` for every reached pair.

    A pair is present iff some active `RequestObservation` `HIT` the endpoint,
    was `OBSERVED_UNDER` an `AuthContext` `OF_PRINCIPAL` that principal, and
    returned a 2xx. The retained evidence is the *highest-status* 2xx (then the
    largest body) — an arbitrary but stable representative; coverage surfaces
    one concrete success per pair for the human to inspect.

    Engagement-scoped on the observation (ADR-0017), `status = 'active'` on the
    observation, the endpoint, and the principal (ADR-0033 / the settle-point
    discipline). Pure traversal; no Python judgement beyond per-pair max.
    """

    frag = for_engagement(engagement_id, var="r")
    cypher = f"""
        MATCH (r:RequestObservation)-[:HIT]->(e:Endpoint),
              (r)-[:OBSERVED_UNDER]->(:AuthContext)-[:OF_PRINCIPAL]->(p:Principal)
        {frag.and_("r.status = 'active'")}
          AND e.status = 'active'
          AND p.status = 'active'
          AND r.response_status >= {_SUCCESS_MIN}
          AND r.response_status <= {_SUCCESS_MAX}
        RETURN e.id AS endpoint_id,
               p.id AS principal_id,
               r.response_status AS status,
               r.response_size_bytes AS response_size_bytes,
               r.response_body_sha256 AS response_body_sha256
        ORDER BY status DESC, coalesce(response_size_bytes, 0) DESC
    """

    rows = client.execute_read(cypher, **frag.parameters)

    out: dict[tuple[str, str], ReachedEvidence] = {}
    for row in rows:
        key = (str(row["endpoint_id"]), str(row["principal_id"]))
        # ORDER BY makes the first row seen for a pair the representative
        # (highest 2xx status, then largest body); keep it and skip the rest.
        if key in out:
            continue
        size = row["response_size_bytes"]
        out[key] = ReachedEvidence(
            endpoint_id=key[0],
            principal_id=key[1],
            status=int(row["status"]),
            response_size_bytes=int(size) if size is not None else None,
            response_body_sha256=(
                str(row["response_body_sha256"])
                if row["response_body_sha256"] is not None
                else None
            ),
        )
    return out


def reached(
    client: Neo4jClient,
    engagement_id: EngagementId,
    *,
    endpoint_id: str,
    principal_id: str,
) -> bool:
    """`reached(e, P)` — true iff a 2xx observation links `P` to `e` (ADR-0033).

    A thin boolean over `reached_map`, kept so the predicate can be exercised
    directly. C2 itself consumes `reached_map` (one query for all pairs) rather
    than calling this per pair.
    """

    return (endpoint_id, principal_id) in reached_map(client, engagement_id)
