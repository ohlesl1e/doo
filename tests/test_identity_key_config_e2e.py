"""Integration test for ADR-0032: auth.identity_key config override.

Proves that a declared `identity_key` on the Engagement node changes the
resolved Principal key at L3 keying — specifically, that setting
`auth.identity_key = "_id"` causes an actor to be keyed on `_id` even
when a higher-priority heuristic claim (`sub`) is also present.

Drives the real L1 -> L2 -> L3 -> flush pipeline (testcontainers).
Mirrors the pattern from test_observed_identity_e2e.py.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime

import jwt
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
from doo.setup.loader import PlannedMutation

SIGNING_KEY = "irrelevant-signing-key-at-least-32-bytes-long!"


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


def _seed_engagement_with_identity_key(
    neo4j: Neo4jClient,
    engagement_id: str,
    identity_key: str | None,
) -> None:
    """Seed a minimal Engagement with an optional identity_key override."""
    now = datetime.now(UTC)
    state = Neo4jGraphState(neo4j)
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
                    "identity_key": identity_key,
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
    redis_client: object,
    blob_client: BlobClient,
    engagement_id: str,
    har_bytes: bytes,
    filename: str,
) -> None:
    """Drive L1 -> L2 -> L3 -> flush for one HAR upload."""
    streams = StreamClient(redis_client)  # type: ignore[arg-type]
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
        idempotency=RedisSetNX(redis_client),  # type: ignore[arg-type]
        streams=streams,
        expected_engagement_id=EngagementId(engagement_id),
    )
    run_l3_worker(
        L3WorkerDeps(orchestrator=orchestrator, streams=streams),
        max_messages=50,
        block_ms=500,
    )
    orchestrator.flush()


def _jwt_entry(*, second: int, bearer: str) -> dict:
    """A single request entry carrying a bearer token."""
    return {
        "startedDateTime": f"2026-06-05T09:00:{second:02d}.000Z",
        "request": {
            "method": "GET",
            "url": "https://api.example.com/api/data",
            "queryString": [],
            "headers": [{"name": "Authorization", "value": f"Bearer {bearer}"}],
            "cookies": [],
            "headersSize": -1,
            "bodySize": 0,
        },
        "response": {
            "status": 200,
            "bodySize": 2,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"mimeType": "application/json", "text": "{}"},
        },
    }


def test_identity_key_overrides_heuristic_at_resolve_time(
    neo4j_client, redis_client, blob_client
) -> None:
    """ADR-0032 M7: declaring identity_key='_id' forces keying on _id even when
    sub (higher heuristic priority) is also present in the JWT.

    Without the override, the heuristic would pick `sub` and key on
    `discovered:sub:{sub_value}`. With the override, the resolver keys on
    `discovered:_id:{_id_value}` instead.
    """
    eid = "eng-idv4-e2e"
    # Seed with identity_key = "_id"
    _seed_engagement_with_identity_key(neo4j_client, eid, identity_key="_id")

    # A JWT that carries both `sub` (higher heuristic priority) and `_id`.
    # Without the override the resolver would use `sub`; with it, `_id` wins.
    _id_value = "mongo-abc-123"
    sub_value = "jwt-sub-should-be-ignored"
    token = jwt.encode(
        {"sub": sub_value, "_id": _id_value, "exp": 9999999999},
        SIGNING_KEY,
        algorithm="HS256",
    )

    har = json.dumps(
        {"log": {"version": "1.2", "entries": [_jwt_entry(second=1, bearer=token)]}}
    ).encode()

    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=har,
        filename="identity_key_override.har",
    )

    # The Principal should be keyed on `_id`, NOT on `sub`.
    _id_principal = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, identity_key: $key}) "
        "RETURN p.identity_key AS key",
        eid=eid,
        key=f"discovered:_id:{_id_value}",
    )
    assert _id_principal, (
        f"Expected a Principal keyed 'discovered:_id:{_id_value}' but none found"
    )

    # No Principal keyed on `sub` should exist (override suppressed it).
    sub_principal = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, identity_key: $key}) "
        "RETURN p.identity_key AS key",
        eid=eid,
        key=f"discovered:sub:{sub_value}",
    )
    assert not sub_principal, (
        "Found a sub-keyed Principal despite identity_key='_id' override"
    )


def test_identity_key_get_identity_key_getter(neo4j_client, redis_client, blob_client) -> None:
    """Neo4jGraphState.get_identity_key returns the stored value and None when absent."""
    eid_set = "eng-idv4-getter-set"
    eid_none = "eng-idv4-getter-none"

    _seed_engagement_with_identity_key(neo4j_client, eid_set, identity_key="username")
    _seed_engagement_with_identity_key(neo4j_client, eid_none, identity_key=None)

    state = Neo4jGraphState(neo4j_client)
    assert state.get_identity_key(EngagementId(eid_set)) == "username"
    assert state.get_identity_key(EngagementId(eid_none)) is None
    assert state.get_identity_key(EngagementId("nonexistent")) is None


def test_identity_key_heuristic_fallback_when_claim_absent(
    neo4j_client, redis_client, blob_client
) -> None:
    """ADR-0032: when the declared claim is absent, heuristic priority is used (no penalty)."""
    eid = "eng-idv4-fallback"
    # Declare identity_key='nonexistent_claim'; the JWT only has `sub`.
    _seed_engagement_with_identity_key(
        neo4j_client, eid, identity_key="nonexistent_claim"
    )

    sub_value = "fallback-sub-user"
    token = jwt.encode(
        {"sub": sub_value, "exp": 9999999999},
        SIGNING_KEY,
        algorithm="HS256",
    )
    har = json.dumps(
        {"log": {"version": "1.2", "entries": [_jwt_entry(second=1, bearer=token)]}}
    ).encode()

    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=har,
        filename="identity_key_fallback.har",
    )

    # The heuristic picks `sub` since `nonexistent_claim` is absent.
    sub_principal = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, identity_key: $key}) "
        "RETURN p.identity_key AS key",
        eid=eid,
        key=f"discovered:sub:{sub_value}",
    )
    assert sub_principal, (
        f"Expected heuristic fallback to key on sub:{sub_value}"
    )
