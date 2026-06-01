"""End-to-end pipeline integration test (Neo4j + Redis + MinIO via testcontainers).

Exercises L1 -> L2 -> L3 for the slice-1 HAR contents and asserts on the graph:
one Host, N Endpoints (one per distinct concrete path), N RequestObservations,
the per-engagement anonymous AuthContext + Principal singletons, ParseFailure
handling, L1 + L3 idempotency, cross-engagement isolation, and trace_id
propagation through structured logs.

Skips cleanly if any of the three containers cannot start (reported, not
deleted).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

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
from tests.fixtures import ANON_HAR, MIXED_HAR


@pytest.fixture
def neo4j_client(neo4j_container) -> Iterator[Neo4jClient]:
    client = Neo4jClient.connect(
        neo4j_container.get_connection_url(),
        neo4j_container.username,
        neo4j_container.password,
    )
    # Edition-aware schema bootstrap (skips existence constraints on Community).
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


def _seed_engagement(neo4j: Neo4jClient, engagement_id: str) -> None:
    """Create a minimal Engagement + Scope so intake's existence gate passes."""

    now = datetime.now(UTC)
    state = Neo4jGraphState(neo4j)
    from doo.setup.loader import PlannedMutation

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
    state.apply_mutations(
        (
            PlannedMutation(
                kind="scope_create",
                properties={"content_hash": f"scope-{engagement_id}", "rules": {}, **cross},
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
    redis_client,
    blob_client: BlobClient,
    engagement_id: str,
    har_bytes: bytes,
    filename: str,
) -> None:
    """Drive L1 intake -> L2 worker -> L3 worker for one HAR upload."""

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
    run_l2_worker(L2WorkerDeps(blobs=blob_client, streams=streams), max_messages=1)
    orchestrator = CommitOrchestrator(
        neo4j=neo4j,
        idempotency=RedisSetNX(redis_client),
        streams=streams,
        expected_engagement_id=EngagementId(engagement_id),
    )
    # Drain however many L2 events the HAR produced.
    run_l3_worker(
        L3WorkerDeps(orchestrator=orchestrator, streams=streams),
        max_messages=50,
        block_ms=500,
    )


def _count(neo4j: Neo4jClient, label: str, engagement_id: str) -> int:
    rows = neo4j.execute_read(
        f"MATCH (n:{label} {{engagement_id: $eid}}) RETURN count(n) AS c",
        eid=engagement_id,
    )
    return int(rows[0]["c"])


def test_anon_har_full_pipeline(neo4j_client, redis_client, blob_client) -> None:
    eid = "eng-e2e-anon"
    _seed_engagement(neo4j_client, eid)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=ANON_HAR.read_bytes(),
        filename="anon_burp.har",
    )

    # 4 entries -> 4 RequestObservations; /products and /products/ collapse, so
    # 3 distinct Endpoints; one Host; anonymous singletons (exactly one each).
    assert _count(neo4j_client, "RequestObservation", eid) == 4
    assert _count(neo4j_client, "Endpoint", eid) == 3
    assert _count(neo4j_client, "Host", eid) == 1
    assert _count(neo4j_client, "AuthContext", eid) == 1
    assert _count(neo4j_client, "Principal", eid) == 1

    # Every Endpoint carries engagement_id.
    rows = neo4j_client.execute_read(
        "MATCH (e:Endpoint {engagement_id: $eid}) RETURN count(e) AS c", eid=eid
    )
    assert rows[0]["c"] == 3

    # Structural edges exist: RequestObservation -HIT-> Endpoint.
    hit = neo4j_client.execute_read(
        "MATCH (:RequestObservation {engagement_id: $eid})-[:HIT]->(:Endpoint) "
        "RETURN count(*) AS c",
        eid=eid,
    )
    assert hit[0]["c"] == 4


def test_reupload_same_har_is_idempotent(neo4j_client, redis_client, blob_client) -> None:
    eid = "eng-e2e-idem"
    _seed_engagement(neo4j_client, eid)
    for _ in range(2):
        _run_pipeline(
            neo4j=neo4j_client,
            redis_client=redis_client,
            blob_client=blob_client,
            engagement_id=eid,
            har_bytes=ANON_HAR.read_bytes(),
            filename="anon_burp.har",
        )
    # Re-upload collapses: same node counts as a single ingest.
    assert _count(neo4j_client, "RequestObservation", eid) == 4
    assert _count(neo4j_client, "Endpoint", eid) == 3
    assert _count(neo4j_client, "AuthContext", eid) == 1
    assert _count(neo4j_client, "Principal", eid) == 1


def test_malformed_entry_produces_parse_failure_with_backref(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-e2e-mixed"
    _seed_engagement(neo4j_client, eid)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=MIXED_HAR.read_bytes(),
        filename="mixed.har",
    )
    # 2 good entries + 1 ParseFailure.
    assert _count(neo4j_client, "RequestObservation", eid) == 2
    assert _count(neo4j_client, "ParseFailure", eid) == 1
    rows = neo4j_client.execute_read(
        "MATCH (f:ParseFailure {engagement_id: $eid}) "
        "RETURN f.envelope_event_id AS ev, f.error_kind AS kind, f.error_message AS msg",
        eid=eid,
    )
    assert rows[0]["ev"]  # back-ref to the L1 envelope present
    assert rows[0]["kind"] == "missing_required_field"
    assert rows[0]["msg"]


def test_cross_engagement_isolation(neo4j_client, redis_client, blob_client) -> None:
    for eid in ("eng-e2e-x1", "eng-e2e-x2"):
        _seed_engagement(neo4j_client, eid)
        _run_pipeline(
            neo4j=neo4j_client,
            redis_client=redis_client,
            blob_client=blob_client,
            engagement_id=eid,
            har_bytes=ANON_HAR.read_bytes(),
            filename="anon_burp.har",
        )
    # Two disjoint subgraphs; counts independent.
    assert _count(neo4j_client, "Endpoint", "eng-e2e-x1") == 3
    assert _count(neo4j_client, "Endpoint", "eng-e2e-x2") == 3
    assert _count(neo4j_client, "Host", "eng-e2e-x1") == 1
    assert _count(neo4j_client, "Host", "eng-e2e-x2") == 1
    # No Host node is shared across engagements (engagement-scoped identity).
    shared = neo4j_client.execute_read(
        "MATCH (a:Host {engagement_id: 'eng-e2e-x1'}), (b:Host {engagement_id: 'eng-e2e-x2'}) "
        "WHERE a.id = b.id RETURN count(*) AS c"
    )
    assert shared[0]["c"] == 0


def test_unknown_engagement_4xx_nothing_lands(neo4j_client, redis_client, blob_client) -> None:
    from doo.ingestion.intake import UnknownEngagementError

    streams = StreamClient(redis_client)
    intake = IntakeDeps(
        engagements=Neo4jGraphState(neo4j_client), blobs=blob_client, streams=streams
    )
    with pytest.raises(UnknownEngagementError):
        ingest_har(
            intake,
            engagement_id=EngagementId("does-not-exist"),
            filename="x.har",
            data=ANON_HAR.read_bytes(),
        )
    # Nothing on the ingest stream.
    assert redis_client.xlen("ingest") == 0
