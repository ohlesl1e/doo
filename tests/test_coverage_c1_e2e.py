"""Golden end-to-end test for C1 (dead-endpoint coverage) over the real pipeline.

Seeds the anon HAR through the real L1->L2->L3 pipeline (Neo4j + Redis + MinIO
testcontainers), which produces in-scope `Endpoint`s that are all *hit*. C1 must
return none of those. We then add two endpoints that the passive pipeline cannot
itself produce yet (a never-hit endpoint requires a non-passive discovery source
— sitemap/robots/LLM-proposed — which is deferred):

- an **in-scope, never-hit** active `Endpoint` (`GET /admin/dashboard` on the
  in-scope host) — the expected C1 result;
- an **out-of-scope, hit** `Endpoint` (`GET /login` on an SSO host outside the
  scope) — must NOT appear, proving the `is_in_scope` (ADR-0020) Python filter.

This asserts C1's external behaviour: the exact dead-endpoint rows for a known
graph, including that any-HIT endpoints and out-of-scope endpoints are excluded.

Skips cleanly if docker / testcontainers is unavailable.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from doo.coverage.queries import run_c1
from doo.ids import EngagementId
from doo.infra.blobs import BlobClient
from doo.infra.neo4j_driver import Neo4jClient
from doo.infra.streams import StreamClient
from doo.ingestion.intake import IntakeDeps, ingest_har
from doo.ingestion.l2_worker import L2WorkerDeps, run_l2_worker
from doo.ontology.commit import CommitOrchestrator, RedisSetNX
from doo.ontology.graph_state import Neo4jGraphState
from doo.ontology.l3_worker import L3WorkerDeps, run_l3_worker
from doo.ontology.schema import apply_schema
from doo.setup.loader import PlannedMutation
from tests.fixtures import ANON_HAR

# `is_in_scope` (ADR-0020) reads host_patterns as glob/exact, not regex — so the
# stored Scope.rules use the bare-hostname form the helper understands.
_SCOPE_RULES = {
    "host_patterns": ["shop.example.com"],
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


def _cross(now: datetime) -> dict[str, object]:
    return {
        "source": "manual",
        "source_id": None,
        "confidence": 1.0,
        "confidence_method": "manual",
        "first_seen": now,
        "last_seen": now,
        "ingested_at": now,
        "status": "active",
    }


def _seed_engagement(neo4j: Neo4jClient, engagement_id: str) -> None:
    now = datetime.now(UTC)
    state = Neo4jGraphState(neo4j)
    cross = _cross(now)
    state.apply_mutations(
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


def _run_pipeline(
    *,
    neo4j: Neo4jClient,
    redis_client,  # type: ignore[no-untyped-def]
    blob_client: BlobClient,
    engagement_id: str,
    har_bytes: bytes,
    filename: str,
) -> None:
    streams = StreamClient(redis_client)
    intake = IntakeDeps(
        engagements=Neo4jGraphState(neo4j), blobs=blob_client, streams=streams
    )
    ingest_har(
        intake,
        engagement_id=EngagementId(engagement_id),
        filename=filename,
        data=har_bytes,
    )
    run_l2_worker(L2WorkerDeps(blobs=blob_client, streams=streams), max_messages=10)
    orchestrator = CommitOrchestrator(
        neo4j=neo4j,
        idempotency=RedisSetNX(redis_client),
        streams=streams,
        expected_engagement_id=EngagementId(engagement_id),
    )
    run_l3_worker(
        L3WorkerDeps(orchestrator=orchestrator, streams=streams),
        max_messages=50,
        block_ms=500,
    )
    orchestrator.flush()


def _add_host(neo4j: Neo4jClient, *, engagement_id: str, host_id: str, hostname: str) -> None:
    now = datetime.now(UTC)
    neo4j.execute_write(
        """
        MERGE (h:Host {engagement_id: $eid, id: $hid})
        ON CREATE SET h.scheme = 'https', h.canonical_hostname = $hostname,
                      h.port = null, h.is_ip_literal = false, h += $props
        """,
        eid=engagement_id,
        hid=host_id,
        hostname=hostname,
        props=_cross(now),
    )


def _add_endpoint(
    neo4j: Neo4jClient,
    *,
    engagement_id: str,
    endpoint_id: str,
    host_id: str,
    method: str,
    path_template: str,
) -> None:
    """Add an active Endpoint + its ON_HOST edge with NO HIT edge (a discovered-
    but-untested endpoint — the shape C1 exists to find)."""

    now = datetime.now(UTC)
    neo4j.execute_write(
        """
        MERGE (e:Endpoint {engagement_id: $eid, method: $method,
                           host_id: $hid, path_template: $pt})
        ON CREATE SET e.id = $epid, e += $props
        WITH e
        MATCH (h:Host {engagement_id: $eid, id: $hid})
        MERGE (e)-[:ON_HOST]->(h)
        """,
        eid=engagement_id,
        epid=endpoint_id,
        method=method,
        hid=host_id,
        pt=path_template,
        props=_cross(now),
    )


def _add_hit_endpoint_oos(
    neo4j: Neo4jClient,
    *,
    engagement_id: str,
    endpoint_id: str,
    host_id: str,
    method: str,
    path_template: str,
) -> None:
    """An out-of-scope Endpoint that IS hit by a (synthetic) RequestObservation;
    must be excluded by the `is_in_scope` filter even though it is hit."""

    now = datetime.now(UTC)
    _add_endpoint(
        neo4j,
        engagement_id=engagement_id,
        endpoint_id=endpoint_id,
        host_id=host_id,
        method=method,
        path_template=path_template,
    )
    neo4j.execute_write(
        """
        MATCH (e:Endpoint {engagement_id: $eid, id: $epid})
        MERGE (r:RequestObservation {engagement_id: $eid, observation_id: $oid})
        ON CREATE SET r.id = $oid, r += $props
        MERGE (r)-[:HIT]->(e)
        """,
        eid=engagement_id,
        epid=endpoint_id,
        oid=f"obs-{endpoint_id}",
        props=_cross(now),
    )


def test_c1_returns_only_in_scope_never_hit_endpoints(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-c1-e2e"
    _seed_engagement(neo4j_client, eid)

    # Real pipeline: anon HAR -> 3 hit endpoints on the in-scope host. None dead.
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=ANON_HAR.read_bytes(),
        filename="anon_burp.har",
    )

    # Sanity: the pipeline made hit endpoints only — C1 is empty so far.
    assert run_c1(neo4j_client, EngagementId(eid)) == []

    # Find the in-scope host the pipeline created (shop.example.com).
    host_rows = neo4j_client.execute_read(
        "MATCH (h:Host {engagement_id: $eid, canonical_hostname: 'shop.example.com'}) "
        "RETURN h.id AS id",
        eid=eid,
    )
    assert host_rows, "pipeline should have created the in-scope shop.example.com host"
    in_scope_host_id = host_rows[0]["id"]

    # Add the expected C1 result: in-scope, never-hit, active endpoint.
    _add_endpoint(
        neo4j_client,
        engagement_id=eid,
        endpoint_id="ep-admin-dashboard",
        host_id=in_scope_host_id,
        method="GET",
        path_template="/admin/dashboard",
    )

    # Add an out-of-scope host with a HIT endpoint — must be excluded.
    _add_host(
        neo4j_client,
        engagement_id=eid,
        host_id="host-sso-oos",
        hostname="sso.partner.test",
    )
    _add_hit_endpoint_oos(
        neo4j_client,
        engagement_id=eid,
        endpoint_id="ep-sso-login",
        host_id="host-sso-oos",
        method="GET",
        path_template="/login",
    )

    results = run_c1(neo4j_client, EngagementId(eid))

    assert [r.endpoint_id for r in results] == ["ep-admin-dashboard"]
    row = results[0]
    assert row.method == "GET"
    assert row.host == "shop.example.com"
    assert row.path_template == "/admin/dashboard"
    assert row.query_id == "C1"
    assert 0.0 < row.effective_confidence <= 1.0


def test_c1_min_confidence_does_not_hide_by_default(
    neo4j_client, redis_client, blob_client
) -> None:
    """A dead endpoint with a stale (decayed) confidence is still surfaced at the
    default threshold (0), and only dropped when --min-confidence is raised."""

    eid = "eng-c1-minconf"
    _seed_engagement(neo4j_client, eid)
    _add_host(
        neo4j_client,
        engagement_id=eid,
        host_id="host-shop",
        hostname="shop.example.com",
    )
    # Set last_seen ~90 days ago so decay pulls effective confidence well below 1.
    stale = datetime.now(UTC).replace(year=datetime.now(UTC).year - 1)
    neo4j_client.execute_write(
        """
        MERGE (e:Endpoint {engagement_id: $eid, method: 'GET',
                           host_id: 'host-shop', path_template: '/stale'})
        ON CREATE SET e.id = 'ep-stale', e += $props
        WITH e
        MATCH (h:Host {engagement_id: $eid, id: 'host-shop'})
        MERGE (e)-[:ON_HOST]->(h)
        """,
        eid=eid,
        props={**_cross(datetime.now(UTC)), "confidence": 1.0, "last_seen": stale},
    )

    default = run_c1(neo4j_client, EngagementId(eid))
    assert [r.endpoint_id for r in default] == ["ep-stale"]
    # Year-old fact: effective confidence is far below 1.
    assert default[0].effective_confidence < 0.05

    # Raising the threshold above the decayed value drops it.
    assert run_c1(neo4j_client, EngagementId(eid), min_confidence=0.1) == []
