"""Evidence resolution: `TestCase` → the `RequestObservation` to replay.

A constructor (ADR-0043) is a pure function of `(TestCase, evidence observation,
auth material)`. The evidence is the highest-confidence `RequestObservation` that
demonstrated the target was reachable by the **victim** side — read via the
target's structural edges, not a TestCase→observation edge:

- `TARGETS_BOUNDARY` → `TrustBoundary -[DERIVED_FROM]-> RequestObservation`
  (the boundary's evidence chain, ADR-0039).
- `TARGETS_ENDPOINT` → `RequestObservation -[HIT]-> Endpoint` (any observed hit
  on this endpoint, preferring one under a non-anonymous, non-attacker
  `AuthContext`).
- `TARGETS_PARAMETER` → via the owning Endpoint's `HIT`s.

Kept separate from the constructor module so constructors stay pure / IO-free
(unit-testable against a synthetic `EvidenceObservation`).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from doo.canonical.value_objects import HostRef
from doo.ids import (
    AuthContextId,
    EngagementId,
    ObservationId,
    TestCaseKeyHash,
)
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.queries import for_engagement


@dataclass(frozen=True, slots=True)
class EvidenceObservation:
    """The constructor-facing projection of an evidencing `RequestObservation`.

    Carries only what request construction needs: the concrete request shape
    (method, host, path, query/header/cookie name→value pairs) plus the
    Endpoint's current `path_template` (for `OpaInput`, ADR-0046) and the victim
    `auth_context_id` (for `baseline_victim` in S5+). Bodies stay as blob refs
    (ADR-0015); raw secret-shaped values are already scrubbed at L2.
    """

    observation_id: ObservationId
    method: str
    host: HostRef
    concrete_path: str
    path_template: str
    query: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body_blob_key: str | None = None
    body_content_type: str | None = None
    victim_auth_context_id: AuthContextId | None = None
    confidence: float = 1.0


@dataclass(frozen=True, slots=True)
class DispatchTestCase:
    """A `TestCase` projection for the Executor (read from the graph).

    The constructor needs the full content-addressed identity plus the
    execution-fidelity annotations (`hold`, `replay_hazards`, ADR-0041) the
    planner persisted.
    """

    engagement_id: EngagementId
    key_hash: TestCaseKeyHash
    test_class: str
    payload_class: str
    auth_context_id: AuthContextId
    target_endpoint_id: str | None
    target_parameter_id: str | None
    target_trust_boundary_id: str | None
    hold: tuple[str, ...]
    replay_hazards: tuple[str, ...]
    expected_yield: float
    generator: str | None
    confidence: float


def load_evidence(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    testcase: DispatchTestCase,
) -> EvidenceObservation | None:
    """Resolve the highest-confidence evidencing `RequestObservation` for a TestCase.

    Ordered by `confidence` desc, `last_seen` desc so a fresher, cleaner
    observation wins. Returns `None` when no evidence resolves — the run records
    `hazard_unresolved` (ADR-0043 surfacing) rather than guessing.
    """

    frag = for_engagement(engagement_id, var="t")
    # Three target shapes, one OPTIONAL-MATCH each, coalesced. The boundary path
    # uses its `DERIVED_FROM` evidence (ADR-0039); the endpoint/parameter paths
    # use `HIT`. The observation must be under a non-anonymous AuthContext (the
    # victim side of the replay) — an anonymous hit gives nothing to swap.
    rows = client.execute_read(
        f"""
        MATCH (t:TestCase {{key_hash: $key_hash}})
        {frag.and_("t.status = 'active'")}
        OPTIONAL MATCH (t)-[:TARGETS_BOUNDARY]->(tb:TrustBoundary)
                       -[:DERIVED_FROM]->(rb:RequestObservation)
                       -[:HIT]->(eb:Endpoint)-[:ON_HOST]->(hb:Host)
        OPTIONAL MATCH (t)-[:TARGETS_ENDPOINT]->(ee:Endpoint)
                       <-[:HIT]-(re:RequestObservation),
                       (ee)-[:ON_HOST]->(he:Host)
        OPTIONAL MATCH (t)-[:TARGETS_PARAMETER]->(pp:Parameter)
                       <-[:HAS_PARAMETER]-(ep:Endpoint)
                       <-[:HIT]-(rp:RequestObservation),
                       (ep)-[:ON_HOST]->(hp:Host)
        WITH t,
             coalesce(rb, re, rp) AS r,
             coalesce(eb, ee, ep) AS e,
             coalesce(hb, he, hp) AS h
        WHERE r IS NOT NULL AND e IS NOT NULL
        OPTIONAL MATCH (r)-[:OBSERVED_UNDER]->(ac:AuthContext)
        WITH t, r, e, h, ac
        ORDER BY (ac IS NOT NULL AND coalesce(ac.is_anonymous, false) = false) DESC,
                 coalesce(r.confidence, 1.0) DESC,
                 r.last_seen DESC
        LIMIT 1
        RETURN r.id AS observation_id,
               r.method AS method,
               r.concrete_path AS concrete_path,
               r.query AS query,
               r.headers AS headers,
               r.cookies AS cookies,
               r.request_body_blob_key AS body_blob_key,
               r.request_body_content_type AS body_content_type,
               coalesce(r.confidence, 1.0) AS confidence,
               e.path_template AS path_template,
               h.scheme AS scheme,
               h.canonical_hostname AS host,
               h.port AS port,
               h.is_ip_literal AS is_ip,
               ac.id AS victim_ac_id
        """,
        key_hash=testcase.key_hash,
        **frag.parameters,
    )
    if not rows:
        return None
    row = rows[0]
    return EvidenceObservation(
        observation_id=ObservationId(str(row["observation_id"])),
        method=str(row["method"]),
        host=HostRef(
            scheme=str(row["scheme"]),  # type: ignore[arg-type]
            canonical_hostname=str(row["host"]),
            port=row["port"],
            is_ip_literal=bool(row["is_ip"]),
        ),
        concrete_path=str(row["concrete_path"]),
        path_template=str(row["path_template"]),
        query=_kv(row.get("query")),
        headers=_kv(row.get("headers")),
        cookies=_kv(row.get("cookies")),
        body_blob_key=row.get("body_blob_key"),
        body_content_type=row.get("body_content_type"),
        victim_auth_context_id=(
            AuthContextId(str(row["victim_ac_id"]))
            if row.get("victim_ac_id") is not None
            else None
        ),
        confidence=float(row["confidence"]),
    )


def _kv(raw: object) -> dict[str, str]:
    """Coerce a Neo4j list-of-`name=value` / map property into a `{name: value}` dict.

    `RequestObservation` persists params as a flat `["name=value", ...]` array
    (Neo4j has no nested-map property type — same JSON-string discipline as
    `graph_state.py`). Missing/null → `{}`.
    """

    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    out: dict[str, str] = {}
    if isinstance(raw, (list, tuple)):
        for item in raw:
            s = str(item)
            if "=" in s:
                name, _, value = s.partition("=")
                out[name] = value
    return out
