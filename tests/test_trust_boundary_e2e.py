"""End-to-end integration tests for `TrustBoundary` inference (slice-3 S4, ADR-0039).

Drives the real L1 -> L2 -> L3 pipeline (Neo4j + Redis + MinIO testcontainers,
mirroring `test_coverage_c2_e2e.py` / `test_observed_value_e2e.py`) and asserts on
the graph after flush:

- **capability** boundaries are drawn only between same-`Principal` `AuthContext`s
  with a claim delta in the decoded `identity_claims` (`scope`); a same-Principal
  pair with no distinguishing claim yields **no** boundary (evidence-gated);
- **tenant** boundaries are drawn only between `Tenant`s that share ≥1 `Endpoint`
  (one undirected node per unordered pair); two tenants that share no endpoint get
  no boundary;
- every boundary is a node with **exactly two** `BETWEEN` edges (kind-matched
  endpoint types), `DERIVED_FROM` edges to evidencing observations, and the
  cross-cutting + `inferred_at` / `code_version` fields, and carries **no**
  endpoint edge;
- the inference is **idempotent across re-flushes** (re-running adds nothing);
- the Step-5 invariants are enforced (a deliberately-malformed write is rejected).

Skips cleanly if docker / testcontainers is unavailable. Reuses the established
testcontainer fixtures and the identity pipeline (distinct JWT `sub` claims key
distinct discovered Principals; one `sub` with two tokens keys one Principal with
two AuthContexts, ADR-0025).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime

import jwt
import pytest

from doo.canonical.identity import trust_boundary_id
from doo.ids import EngagementId
from doo.infra.blobs import BlobClient
from doo.infra.neo4j_driver import Neo4jClient
from doo.infra.streams import StreamClient
from doo.ontology.commit import CommitOrchestrator, RedisSetNX
from doo.ontology.schema import apply_schema
from doo.ontology.tenant import infer_tenants
from doo.ontology.trust_boundary import (
    TrustBoundaryInvariantError,
    _merge_boundary,
    infer_trust_boundaries,
)
from doo.setup.loader import PlannedMutation
from tests.test_pipeline_e2e import _count, _run_pipeline

SIGNING_KEY = "irrelevant-signing-key-at-least-32-bytes-long!"

_SCOPE_RULES = {
    "host_patterns": ["api.example.com"],
    "allowed_methods": ["*"],
    "allowed_path_patterns": ["/**"],
    "payload_class_denylist": [],
    "rate_limit": None,
    "time_window": None,
    "required_headers": [],
}


@pytest.fixture
def neo4j_client(neo4j_container) -> Iterator[Neo4jClient]:
    client = Neo4jClient.connect(
        neo4j_container.get_connection_url(),
        neo4j_container.username,
        neo4j_container.password,
    )
    with client.driver.session() as session:
        apply_schema(session, edition=client.server_edition())
    try:
        yield client
    finally:
        client.close()


@pytest.fixture
def redis_client(redis_url):  # type: ignore[no-untyped-def]
    import redis

    client = redis.Redis.from_url(redis_url, decode_responses=True)
    try:
        yield client
    finally:
        client.flushall()
        client.close()


@pytest.fixture
def blob_client(minio_config) -> BlobClient:
    return BlobClient.from_config(
        endpoint_url=minio_config["endpoint_url"],
        access_key=minio_config["access_key"],
        secret_key=minio_config["secret_key"],
        bucket="doo-blobs",
    )


def _seed_engagement_in_scope(neo4j: Neo4jClient, engagement_id: str) -> None:
    now = datetime.now(UTC)
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
    from doo.ontology.graph_state import Neo4jGraphState

    Neo4jGraphState(neo4j).apply_mutations(
        (
            PlannedMutation(
                kind="scope_create",
                properties={
                    "content_hash": f"scope-{engagement_id}",
                    "rules": _SCOPE_RULES,
                    **cross,
                },
            ),
            PlannedMutation(
                kind="engagement_create",
                properties={
                    "id": engagement_id,
                    "name": engagement_id,
                    "description": None,
                    "time_window": None,
                    "kill_switch": {"backend": "redis"},
                    **cross,
                },
            ),
            PlannedMutation(
                kind="engagement_under_scope",
                properties={
                    "engagement_id": engagement_id,
                    "scope_content_hash": f"scope-{engagement_id}",
                },
            ),
        )
    )


def _entry(*, second: int, bearer: str, path: str, status: int = 200) -> dict:
    body = json.dumps({"ok": status < 400, "path": path})
    return {
        "startedDateTime": f"2026-06-08T09:00:{second:02d}.000Z",
        "request": {
            "method": "GET",
            "url": f"https://api.example.com{path}",
            "queryString": [],
            "headers": [{"name": "Authorization", "value": f"Bearer {bearer}"}],
            "cookies": [],
            "headersSize": -1,
            "bodySize": 0,
        },
        "response": {
            "status": status,
            "bodySize": len(body),
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"mimeType": "application/json", "text": body},
        },
    }


def _fixture_har() -> bytes:
    """A HAR exercising every S4 boundary case (ADR-0039).

    Capability:
    - sub=s4-cap presents TWO tokens differing only in `scope` -> ONE Principal,
      two AuthContexts, ONE `scope` capability boundary.
    - sub=s4-nodelta presents TWO tokens with the SAME `scope` (differing only in
      `exp`, so distinct auth_hashes / AuthContexts) -> ONE Principal, two
      AuthContexts, NO capability boundary (evidence-gated: no claim delta).

    Tenant:
    - orgs 42 and 43 are each hit on `/orgs/{org}/projects` (two distinct org
      values -> templates to `/orgs/{org_id}/projects`) -> Tenant(org_id,42) and
      Tenant(org_id,43) SHARE that endpoint -> ONE tenant boundary.
    - workspaces ws-a and ws-b are each hit on `/workspaces/{ws}/files` -> two
      Tenants sharing `/workspaces/{workspace_id}/files` -> ONE tenant boundary.
    - the org pair and the workspace pair SHARE NO endpoint -> NO cross boundary
      between an org Tenant and a workspace Tenant (the negative).
    """

    cap_a = jwt.encode({"sub": "s4-cap", "scope": "read", "exp": 4102444800}, SIGNING_KEY, algorithm="HS256")
    cap_b = jwt.encode(
        {"sub": "s4-cap", "scope": "read write admin", "exp": 4102444800},
        SIGNING_KEY,
        algorithm="HS256",
    )
    nd_a = jwt.encode({"sub": "s4-nodelta", "scope": "read", "exp": 4102444800}, SIGNING_KEY, algorithm="HS256")
    nd_b = jwt.encode({"sub": "s4-nodelta", "scope": "read", "exp": 4102444801}, SIGNING_KEY, algorithm="HS256")
    # Tenant-bearing principals (distinct subs -> distinct Principals).
    org42 = jwt.encode({"sub": "s4-org42"}, SIGNING_KEY, algorithm="HS256")
    org43 = jwt.encode({"sub": "s4-org43"}, SIGNING_KEY, algorithm="HS256")
    wsa = jwt.encode({"sub": "s4-wsa"}, SIGNING_KEY, algorithm="HS256")
    wsb = jwt.encode({"sub": "s4-wsb"}, SIGNING_KEY, algorithm="HS256")

    entries = [
        # Capability: same sub, scope delta -> ONE capability boundary.
        _entry(second=1, bearer=cap_a, path="/me"),
        _entry(second=2, bearer=cap_b, path="/me"),
        # Capability: same sub, NO scope delta -> NO capability boundary.
        _entry(second=3, bearer=nd_a, path="/me"),
        _entry(second=4, bearer=nd_b, path="/me"),
        # Tenant (orgs): two distinct org values share /orgs/{org_id}/projects.
        _entry(second=5, bearer=org42, path="/orgs/42/projects"),
        _entry(second=6, bearer=org43, path="/orgs/43/projects"),
        # Tenant (workspaces): two distinct ws values share /workspaces/{workspace_id}/files.
        _entry(second=7, bearer=wsa, path="/workspaces/ws-a/files"),
        _entry(second=8, bearer=wsb, path="/workspaces/ws-b/files"),
    ]
    return json.dumps({"log": {"version": "1.2", "entries": entries}}).encode()


def test_trust_boundary_inference_end_to_end(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-tb-e2e"
    _seed_engagement_in_scope(neo4j_client, eid)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=_fixture_har(),
        filename="trust_boundaries.har",
    )

    # --- Tenant inference (ADR-0008): 4 Tenants (orgs 42/43, ws-a/ws-b). ---
    assert _count(neo4j_client, "Tenant", eid) == 4
    tkinds = neo4j_client.execute_read(
        "MATCH (t:Tenant {engagement_id: $eid}) "
        "RETURN t.kind AS kind, t.normalized_value AS val ORDER BY kind, val",
        eid=eid,
    )
    assert {(r["kind"], r["val"]) for r in tkinds} == {
        ("org_id", "42"),
        ("org_id", "43"),
        ("workspace", "ws-a"),
        ("workspace", "ws-b"),
    }
    # Each Tenant carries DERIVED_FROM evidence + an OF_TENANT edge from a Principal.
    bad_tenant = neo4j_client.execute_read(
        "MATCH (t:Tenant {engagement_id: $eid}) "
        "WHERE NOT (t)-[:DERIVED_FROM]->(:RequestObservation) "
        "   OR NOT (:Principal)-[:OF_TENANT]->(t) "
        "   OR t.source <> 'deterministic-tenant' OR t.confidence IS NULL "
        "RETURN count(t) AS c",
        eid=eid,
    )
    assert bad_tenant[0]["c"] == 0

    # --- Capability boundaries: exactly ONE (the scope delta), kind=scope. ---
    cap = neo4j_client.execute_read(
        "MATCH (b:TrustBoundary {engagement_id: $eid}) "
        "WHERE b.kind IN ['scope','mfa','freshness'] "
        "RETURN b.kind AS kind, b.id AS id ORDER BY kind",
        eid=eid,
    )
    assert len(cap) == 1
    assert cap[0]["kind"] == "scope"
    cap_id = cap[0]["id"]

    # The capability boundary's two BETWEEN endpoints are AuthContexts of ONE Principal.
    cap_shape = neo4j_client.execute_read(
        "MATCH (b:TrustBoundary {engagement_id: $eid, id: $id}) "
        "OPTIONAL MATCH (b)-[:BETWEEN]->(x) "
        "WITH b, collect(x) AS ends "
        "OPTIONAL MATCH (b)-[:BETWEEN]->(:AuthContext)-[:OF_PRINCIPAL]->(p:Principal) "
        "RETURN size(ends) AS between_count, "
        "       [n IN ends | head(labels(n))] AS labels, "
        "       count(DISTINCT p) AS principals",
        eid=eid,
        id=cap_id,
    )
    assert cap_shape[0]["between_count"] == 2
    assert set(cap_shape[0]["labels"]) == {"AuthContext"}
    assert cap_shape[0]["principals"] == 1

    # The capability boundary has DERIVED_FROM evidence, the inference fields, and
    # NO endpoint edge (ADR-0039: endpoint is read from evidence).
    cap_meta = neo4j_client.execute_read(
        "MATCH (b:TrustBoundary {engagement_id: $eid, id: $id}) "
        "RETURN size([(b)-[:DERIVED_FROM]->(:RequestObservation) | 1]) AS evidence, "
        "       b.source AS source, b.confidence AS confidence, "
        "       b.inferred_at AS inferred_at, b.code_version AS code_version, "
        "       size([(b)-[:TARGETS_ENDPOINT]->() | 1]) AS endpoint_edges",
        eid=eid,
        id=cap_id,
    )
    assert cap_meta[0]["evidence"] >= 1
    assert cap_meta[0]["source"] == "deterministic-trustboundary"
    assert cap_meta[0]["confidence"] is not None
    assert cap_meta[0]["inferred_at"] is not None
    assert cap_meta[0]["code_version"]
    assert cap_meta[0]["endpoint_edges"] == 0

    # No capability boundary for the no-delta Principal (evidence-gated).
    # s4-nodelta has two AuthContexts but identical scope -> no boundary touches them.
    nodelta = neo4j_client.execute_read(
        "MATCH (b:TrustBoundary {engagement_id: $eid})-[:BETWEEN]->"
        "(:AuthContext)-[:OF_PRINCIPAL]->(p:Principal {identity_key: 'discovered:sub:s4-nodelta'}) "
        "RETURN count(DISTINCT b) AS c",
        eid=eid,
    )
    assert nodelta[0]["c"] == 0

    # --- Tenant boundaries: exactly TWO (org 42<->43, ws-a<->ws-b). ---
    tenant_bounds = neo4j_client.execute_read(
        "MATCH (b:TrustBoundary {engagement_id: $eid, kind: 'tenant'}) "
        "RETURN b.id AS id, b.between_a_id AS a, b.between_b_id AS b ORDER BY id",
        eid=eid,
    )
    assert len(tenant_bounds) == 2

    # Each tenant boundary's two BETWEEN endpoints are Tenants; same kind on both.
    tb_shape = neo4j_client.execute_read(
        "MATCH (b:TrustBoundary {engagement_id: $eid, kind: 'tenant'}) "
        "OPTIONAL MATCH (b)-[:BETWEEN]->(x) "
        "WITH b, collect(x) AS ends "
        "RETURN b.id AS id, size(ends) AS between_count, "
        "       [n IN ends | head(labels(n))] AS labels, "
        "       [n IN ends | n.kind] AS kinds",
        eid=eid,
    )
    for row in tb_shape:
        assert row["between_count"] == 2
        assert set(row["labels"]) == {"Tenant"}
        assert len(set(row["kinds"])) == 1  # both sides same tenant kind

    # The negative: NO boundary between an org Tenant and a workspace Tenant
    # (they share no endpoint).
    cross = neo4j_client.execute_read(
        "MATCH (b:TrustBoundary {engagement_id: $eid, kind: 'tenant'})-[:BETWEEN]->(ta:Tenant), "
        "      (b)-[:BETWEEN]->(tb:Tenant) "
        "WHERE ta.kind = 'org_id' AND tb.kind = 'workspace' "
        "RETURN count(b) AS c",
        eid=eid,
    )
    assert cross[0]["c"] == 0

    # Role/ownership boundaries are NOT inferred.
    role = neo4j_client.execute_read(
        "MATCH (b:TrustBoundary {engagement_id: $eid}) "
        "WHERE b.kind IN ['role','ownership'] RETURN count(b) AS c",
        eid=eid,
    )
    assert role[0]["c"] == 0

    # Total boundaries: 1 capability + 2 tenant.
    assert _count(neo4j_client, "TrustBoundary", eid) == 3

    # Global Step-5 invariant: every TrustBoundary has exactly two BETWEEN edges.
    bad_between = neo4j_client.execute_read(
        "MATCH (b:TrustBoundary {engagement_id: $eid}) "
        "WHERE size([(b)-[:BETWEEN]->() | 1]) <> 2 RETURN count(b) AS c",
        eid=eid,
    )
    assert bad_between[0]["c"] == 0
    # Every TrustBoundary has ≥1 DERIVED_FROM (inference-node invariant).
    bad_derived = neo4j_client.execute_read(
        "MATCH (b:TrustBoundary {engagement_id: $eid}) "
        "WHERE NOT (b)-[:DERIVED_FROM]->() RETURN count(b) AS c",
        eid=eid,
    )
    assert bad_derived[0]["c"] == 0


def test_trust_boundary_inference_is_idempotent_on_reflush(
    neo4j_client, redis_client, blob_client
) -> None:
    """Re-running the inference over an unchanged graph adds no new nodes/edges.

    Drives the pipeline once (the first flush infers everything), then calls the
    inference passes directly a second time and asserts the boundary / BETWEEN /
    DERIVED_FROM counts are unchanged — the MERGE idempotency (identity-keyed,
    canonical endpoint order) holds across re-flushes.
    """

    eid = "eng-tb-idem"
    _seed_engagement_in_scope(neo4j_client, eid)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=_fixture_har(),
        filename="trust_boundaries.har",
    )

    def _counts() -> tuple[int, int, int, int]:
        boundaries = _count(neo4j_client, "TrustBoundary", eid)
        between = neo4j_client.execute_read(
            "MATCH (:TrustBoundary {engagement_id: $eid})-[r:BETWEEN]->() RETURN count(r) AS c",
            eid=eid,
        )[0]["c"]
        derived = neo4j_client.execute_read(
            "MATCH (:TrustBoundary {engagement_id: $eid})-[r:DERIVED_FROM]->() "
            "RETURN count(r) AS c",
            eid=eid,
        )[0]["c"]
        tenants = _count(neo4j_client, "Tenant", eid)
        return boundaries, int(between), int(derived), tenants

    before = _counts()
    assert before[0] == 3  # 1 capability + 2 tenant

    # Re-run the inference directly (a re-flush over the settled graph).
    now = datetime.now(UTC)
    infer_tenants(neo4j_client, engagement_id=EngagementId(eid), observed_at=now, ingested_at=now)
    infer_trust_boundaries(
        neo4j_client, engagement_id=EngagementId(eid), observed_at=now, ingested_at=now
    )

    after = _counts()
    assert after == before  # no duplicates: nodes + BETWEEN + DERIVED_FROM all stable

    # And a full second flush via the orchestrator is likewise a no-op.
    orchestrator = CommitOrchestrator(
        neo4j=neo4j_client,
        idempotency=RedisSetNX(redis_client),
        streams=StreamClient(redis_client),
        expected_engagement_id=EngagementId(eid),
    )
    orchestrator.flush()
    assert _counts() == before


def test_capability_boundary_requires_two_distinct_endpoints(
    neo4j_client, redis_client, blob_client
) -> None:
    """A boundary between a node and itself is rejected (Step-5: two endpoints).

    Exercises the invariant guard directly: `_merge_boundary` refuses an a==b
    pair before writing, so a malformed boundary never reaches the graph.
    """

    eid = "eng-tb-invariant"
    _seed_engagement_in_scope(neo4j_client, eid)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=_fixture_har(),
        filename="trust_boundaries.har",
    )
    # Pick a real AuthContext id to feed as both endpoints.
    ac = neo4j_client.execute_read(
        "MATCH (ac:AuthContext {engagement_id: $eid}) WHERE ac.is_anonymous = false "
        "RETURN ac.id AS id LIMIT 1",
        eid=eid,
    )
    ac_id = ac[0]["id"]
    now = datetime.now(UTC)
    with pytest.raises(TrustBoundaryInvariantError):
        _merge_boundary(
            neo4j_client,
            engagement_id=EngagementId(eid),
            boundary_node_id=trust_boundary_id(EngagementId(eid), "scope", ac_id, ac_id),
            kind="scope",
            between_label="AuthContext",
            between_a_id=ac_id,
            between_b_id=ac_id,
            evidence_observation_ids=("obs-x",),
            observed_at=now,
            ingested_at=now,
        )
