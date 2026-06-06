"""End-to-end test for ADR-0029 observed-response identity reconciliation.

Drives the real L1 -> L2 -> L3 -> flush pipeline (testcontainers) and asserts that
synthetic (opaque-credential) discovered Principals are upgraded and collapsed
from an identity response header — and that the merge-safety invariant holds
(distinct identities never merge; a JWT-claim-keyed Principal is never touched).

Reuses the pipeline driver from `test_pipeline_e2e`.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import jwt
import pytest

from doo.infra.blobs import BlobClient
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.schema import apply_schema
from tests.test_pipeline_e2e import _run_pipeline, _seed_engagement

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


def _entry(*, second: int, bearer: str, x_user_id: str) -> dict:
    return {
        "startedDateTime": f"2026-06-04T09:00:{second:02d}.000Z",
        "request": {
            "method": "GET",
            "url": "https://api.example.com/dashboard",
            "queryString": [],
            "headers": [{"name": "Authorization", "value": f"Bearer {bearer}"}],
            "cookies": [],
            "headersSize": -1,
            "bodySize": 0,
        },
        "response": {
            "status": 200,
            "bodySize": 2,
            "headers": [
                {"name": "Content-Type", "value": "application/json"},
                {"name": "X-User-Id", "value": x_user_id},
            ],
            "content": {"mimeType": "application/json", "text": "{}"},
        },
    }


def test_observed_header_identity_collapses_synthetic_principals(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-oi-e2e"
    _seed_engagement(neo4j_client, eid)

    # alice: three rotated OPAQUE bearer tokens (3 synthetic AuthContexts), each
    # response asserting X-User-Id: alice-id. bob: one opaque token, X-User-Id:
    # bob-id. jwt-user: a decodable JWT (sub) whose response ALSO carries
    # X-User-Id: alice-id — it must NOT be upgraded (already claim-keyed).
    jwt_token = jwt.encode({"sub": "jwt-user"}, SIGNING_KEY, algorithm="HS256")
    entries = [
        _entry(second=1, bearer="opaque-alice-1", x_user_id="alice-id"),
        _entry(second=2, bearer="opaque-alice-2", x_user_id="alice-id"),
        _entry(second=3, bearer="opaque-alice-3", x_user_id="alice-id"),
        _entry(second=4, bearer="opaque-bob-1", x_user_id="bob-id"),
        _entry(second=5, bearer=jwt_token, x_user_id="alice-id"),
    ]
    har = json.dumps({"log": {"version": "1.2", "entries": entries}}).encode()
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=har,
        filename="observed_identity.har",
    )

    # alice's three opaque tokens collapse to ONE observed-identity Principal with
    # three AuthContexts beneath it.
    alice = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, "
        "identity_key: 'discovered:x-user-id:alice-id'}) "
        "RETURN count{ (:AuthContext)-[:OF_PRINCIPAL]->(p) } AS acs, p.confidence AS conf",
        eid=eid,
    )
    assert alice and alice[0]["acs"] == 3
    assert alice[0]["conf"] == 0.6  # above the synthetic 0.3 (ADR-0029)

    # bob stays distinct — no false merge with alice.
    bob = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, "
        "identity_key: 'discovered:x-user-id:bob-id'}) "
        "RETURN count{ (:AuthContext)-[:OF_PRINCIPAL]->(p) } AS acs",
        eid=eid,
    )
    assert bob and bob[0]["acs"] == 1

    # The JWT-claim-keyed Principal is NOT upgraded despite carrying X-User-Id.
    jwtp = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, identity_key: 'discovered:sub:jwt-user'}) "
        "RETURN count{ (:AuthContext)-[:OF_PRINCIPAL]->(p) } AS acs",
        eid=eid,
    )
    assert jwtp and jwtp[0]["acs"] == 1

    # The four synthetic (auth_hash-keyed) Principals are retracted, not deleted,
    # and carry no live AuthContext.
    synthetic = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, tier: 'discovered'}) "
        "WHERE p.identity_key =~ 'discovered:[0-9a-f]{64}' "
        "RETURN p.status AS status, count{ (:AuthContext)-[:OF_PRINCIPAL]->(p) } AS acs",
        eid=eid,
    )
    assert len(synthetic) == 4
    assert all(r["status"] == "retracted" and r["acs"] == 0 for r in synthetic)

    # No live non-anonymous Principal keyed on a raw auth_hash remains.
    live_synthetic = neo4j_client.execute_read(
        "MATCH (ac:AuthContext)-[:OF_PRINCIPAL]->(p:Principal {engagement_id: $eid}) "
        "WHERE p.identity_key =~ 'discovered:[0-9a-f]{64}' "
        "RETURN count(p) AS c",
        eid=eid,
    )
    assert live_synthetic[0]["c"] == 0


def test_bearer_sub_and_me_sub_converge_to_one_principal(
    neo4j_client, redis_client, blob_client
) -> None:
    """ADR-0030 M3: a bearer-JWT `sub` (resolve/cue path) and the same actor's `/me`
    response `sub` (observed path) produce the SAME unified `discovered:sub:{value}`
    key, so they MERGE into ONE Principal — the cross-signal unification.

    Two different opaque-bearer requests, each `/me` body asserting `sub: actor-9`,
    plus one bearer JWT carrying `sub: actor-9`: all three AuthContexts end up under
    the single `discovered:sub:actor-9` Principal.
    """

    eid = "eng-oi-converge-e2e"
    _seed_engagement(neo4j_client, eid)
    sub = "actor-9"
    jwt_token = jwt.encode({"sub": sub}, SIGNING_KEY, algorithm="HS256")
    entries = [
        # Opaque bearer, /me body reveals sub -> observed path keys discovered:sub.
        _me_sub_entry(second=1, bearer="opaque-x-1", sub=sub),
        _me_sub_entry(second=2, bearer="opaque-x-2", sub=sub),
        # Bearer JWT with the same sub -> resolve/cue path keys discovered:sub.
        {
            "startedDateTime": "2026-06-04T12:00:03.000Z",
            "request": {
                "method": "GET",
                "url": "https://api.example.com/dashboard",
                "queryString": [],
                "headers": [{"name": "Authorization", "value": f"Bearer {jwt_token}"}],
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
        },
    ]
    har = json.dumps({"log": {"version": "1.2", "entries": entries}}).encode()
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=har,
        filename="observed_converge.har",
    )

    # ONE Principal keyed on the unified discovered:sub:actor-9, with all THREE
    # AuthContexts (two opaque + one JWT) beneath it — the cue + observed paths
    # converged by identity-key MERGE.
    row = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, identity_key: 'discovered:sub:" + sub + "'}) "
        "RETURN count{ (:AuthContext)-[:OF_PRINCIPAL]->(p) } AS acs",
        eid=eid,
    )
    assert row and row[0]["acs"] == 3

    # No live synthetic Principal remains (the two opaque ones were re-pointed).
    live = neo4j_client.execute_read(
        "MATCH (ac:AuthContext)-[:OF_PRINCIPAL]->(p:Principal {engagement_id: $eid}) "
        "WHERE p.identity_key =~ 'discovered:[0-9a-f]{64}' RETURN count(p) AS c",
        eid=eid,
    )
    assert live[0]["c"] == 0


def _me_sub_entry(*, second: int, bearer: str, sub: str) -> dict:
    """A self-endpoint (`/me`) request whose JSON body carries the actor's `sub`."""
    return {
        "startedDateTime": f"2026-06-04T12:00:{second:02d}.000Z",
        "request": {
            "method": "GET",
            "url": "https://api.example.com/api/users/me",
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
            "content": {
                "mimeType": "application/json",
                "text": json.dumps({"sub": sub, "role": "user"}),
            },
        },
    }


def _me_entry(*, second: int, bearer: str, user_id: str) -> dict:
    """A self-endpoint (`/users/me`) request whose JSON body carries the actor's
    `_id` — and NO identity header, so the body signal (T-OI2) is what fires."""
    return {
        "startedDateTime": f"2026-06-04T10:00:{second:02d}.000Z",
        "request": {
            "method": "GET",
            "url": "https://api.example.com/api/wireless/users/me",
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
            "content": {
                "mimeType": "application/json",
                "text": json.dumps({"_id": user_id, "role": "admin"}),
            },
        },
    }


def test_self_endpoint_body_identity_collapses_synthetic_principals(
    neo4j_client, redis_client, blob_client
) -> None:
    """ADR-0029 T-OI2: opaque tokens whose `/me` response body reveals one `_id`
    (no identity header) collapse to one observed-body Principal."""

    eid = "eng-oi-body-e2e"
    _seed_engagement(neo4j_client, eid)
    user_id = "6614a9412c25a5000df5d4d6"
    entries = [
        _me_entry(second=1, bearer="opaque-tok-1", user_id=user_id),
        _me_entry(second=2, bearer="opaque-tok-2", user_id=user_id),
        _me_entry(second=3, bearer="opaque-tok-3", user_id=user_id),
    ]
    har = json.dumps({"log": {"version": "1.2", "entries": entries}}).encode()
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=har,
        filename="observed_body_identity.har",
    )

    # ADR-0030: the body `_id` claim keys the unified `discovered:_id:{value}`.
    row = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, "
        "identity_key: 'discovered:_id:" + user_id + "'}) "
        "RETURN count{ (:AuthContext)-[:OF_PRINCIPAL]->(p) } AS acs, p.confidence AS conf",
        eid=eid,
    )
    assert row and row[0]["acs"] == 3
    assert row[0]["conf"] == 0.5  # body claim ranks below a header (ADR-0030)

    # No live synthetic (auth_hash-keyed) Principal remains.
    live = neo4j_client.execute_read(
        "MATCH (ac:AuthContext)-[:OF_PRINCIPAL]->(p:Principal {engagement_id: $eid}) "
        "WHERE p.identity_key =~ 'discovered:[0-9a-f]{64}' "
        "RETURN count(p) AS c",
        eid=eid,
    )
    assert live[0]["c"] == 0


def test_jwt_keyed_principal_gains_me_email_alias(
    neo4j_client, redis_client, blob_client
) -> None:
    """ADR-0029 amendment: a JWT-claim-keyed Principal is NOT re-keyed by an
    observed `/me` identity (merge-safety) but DOES gain it as an alias —
    enrichment, so an actor known by an opaque id reads human-readably."""

    eid = "eng-oi-alias-e2e"
    _seed_engagement(neo4j_client, eid)
    token = jwt.encode({"sub": "jwt-user"}, SIGNING_KEY, algorithm="HS256")
    entries = [
        {
            "startedDateTime": "2026-06-04T11:00:01.000Z",
            "request": {
                "method": "GET",
                "url": "https://api.example.com/api/users/me",
                "queryString": [],
                "headers": [{"name": "Authorization", "value": f"Bearer {token}"}],
                "cookies": [],
                "headersSize": -1,
                "bodySize": 0,
            },
            "response": {
                "status": 200,
                "bodySize": 2,
                "headers": [{"name": "Content-Type", "value": "application/json"}],
                "content": {
                    "mimeType": "application/json",
                    "text": json.dumps({"_id": "507f1f77bcf86cd799439011", "email": "alice@corp.com"}),
                },
            },
        }
    ]
    har = json.dumps({"log": {"version": "1.2", "entries": entries}}).encode()
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=har,
        filename="observed_alias.har",
    )

    row = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, identity_key: 'discovered:sub:jwt-user'}) "
        "RETURN p.observed_aliases AS aliases",
        eid=eid,
    )
    # The Principal stays claim-keyed (not re-keyed) but records ALL /me claims as
    # aliases — both the `_id` and the human-readable `email` (ADR-0030).
    assert row and sorted(row[0]["aliases"]) == [
        "_id=507f1f77bcf86cd799439011",
        "email=alice@corp.com",
    ]

    # No NEW claim-keyed Principal was created (the existing one was aliased, not
    # merged): the only non-anonymous discovered Principal is the original sub one.
    obs_p = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid}) "
        "WHERE p.is_anonymous = false AND p.identity_key STARTS WITH 'discovered:' "
        "RETURN collect(p.identity_key) AS keys",
        eid=eid,
    )
    assert obs_p[0]["keys"] == ["discovered:sub:jwt-user"]
