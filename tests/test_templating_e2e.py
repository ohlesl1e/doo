"""End-to-end integration tests for T3 path templating + Parameter aggregation.

Drives the real L1 -> L2 -> L3 pipeline (Neo4j + Redis + MinIO testcontainers)
over the templating HAR corpus and asserts on the graph with explicit Cypher:
the multiplicity collapse, the version-segment guard, literal-sibling router
precedence, re-templating (with a `node_updated` L3 event), Parameter rollups,
cold-start confidence, and idempotency.

Skips cleanly if any container cannot start (reported, not deleted). Reuses the
plain pipeline-driving helpers from `test_pipeline_e2e`.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest

from doo.infra.blobs import BlobClient
from doo.infra.neo4j_driver import Neo4jClient
from doo.infra.streams import L3_EVENTS_STREAM
from doo.ontology.schema import apply_schema
from tests.fixtures import (
    LITERAL_SIBLING_HAR,
    USERS_TEMPLATING_HAR,
    VERSION_TEMPLATING_HAR,
)
from tests.test_pipeline_e2e import _count, _run_pipeline, _seed_engagement


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


def _templates(neo4j: Neo4jClient, eid: str) -> set[str]:
    rows = neo4j.execute_read(
        "MATCH (e:Endpoint {engagement_id: $eid}) WHERE e.status = 'active' "
        "RETURN e.path_template AS t",
        eid=eid,
    )
    return {str(r["t"]) for r in rows}


def _har(*urls: str, minute: int = 0) -> bytes:
    """Build a minimal anonymous-GET HAR over the given URLs.

    `minute` distinguishes batches: the per-entry `source_id` (and thus the L3
    idempotency semantic key) is derived from `startedDateTime`, so successive
    batches that must NOT collapse as idempotent no-ops need distinct times.
    """

    entries = []
    for i, url in enumerate(urls):
        entries.append(
            {
                "startedDateTime": f"2026-05-03T09:{minute:02d}:0{i}.000Z",
                "request": {
                    "method": "GET",
                    "url": url,
                    "queryString": [],
                    "headersSize": -1,
                    "bodySize": 0,
                },
                "response": {"status": 200, "bodySize": 64},
            }
        )
    return json.dumps({"log": {"version": "1.2", "entries": entries}}).encode()


# --- Acceptance: multiplicity collapse + path Parameter. ---


def test_users_collapse_to_one_endpoint_with_path_parameter(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-t3-users"
    _seed_engagement(neo4j_client, eid)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=USERS_TEMPLATING_HAR.read_bytes(),
        filename="users.har",
    )

    # One Endpoint /users/{user_id}; three observations all HIT it.
    assert _count(neo4j_client, "Endpoint", eid) == 1
    assert _templates(neo4j_client, eid) == {"/users/{user_id}"}
    assert _count(neo4j_client, "RequestObservation", eid) == 3

    hits = neo4j_client.execute_read(
        "MATCH (:RequestObservation {engagement_id: $eid})-[:HIT]->"
        "(e:Endpoint {path_template: '/users/{user_id}'}) RETURN count(*) AS c",
        eid=eid,
    )
    assert hits[0]["c"] == 3

    # One path Parameter (name=user_id, location=path) with HAS_PARAMETER edge.
    params = neo4j_client.execute_read(
        "MATCH (e:Endpoint {engagement_id: $eid})-[:HAS_PARAMETER]->"
        "(p:Parameter {location: 'path'}) RETURN p.name AS name",
        eid=eid,
    )
    assert [r["name"] for r in params] == ["user_id"]


# --- Acceptance: version segment stays literal under multiplicity. ---


def test_version_segments_stay_literal(neo4j_client, redis_client, blob_client) -> None:
    eid = "eng-t3-version"
    _seed_engagement(neo4j_client, eid)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=VERSION_TEMPLATING_HAR.read_bytes(),
        filename="version.har",
    )
    assert _templates(neo4j_client, eid) == {
        "/v1/orgs/{org_id}/projects",
        "/v2/orgs/{org_id}/projects",
    }
    assert _count(neo4j_client, "Endpoint", eid) == 2


# --- Acceptance: literal sibling wins over parameter (router precedence). ---


def test_literal_sibling_route_coexists(neo4j_client, redis_client, blob_client) -> None:
    eid = "eng-t3-literal"
    _seed_engagement(neo4j_client, eid)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=LITERAL_SIBLING_HAR.read_bytes(),
        filename="literal.har",
    )
    assert _templates(neo4j_client, eid) == {"/users/{user_id}", "/users/settings"}
    assert _count(neo4j_client, "Endpoint", eid) == 2

    # /users/settings routes to the literal endpoint, not the parameter one.
    routed = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid, concrete_path: '/users/settings'})"
        "-[:HIT]->(e:Endpoint) RETURN e.path_template AS t",
        eid=eid,
    )
    assert routed[0]["t"] == "/users/settings"


# --- Acceptance: re-templating revises an existing Endpoint + emits node_updated. ---


def test_retemplating_revises_endpoint_and_emits_node_updated(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-t3-retemplate"
    _seed_engagement(neo4j_client, eid)

    # Batch 1: a single interior word -> stays literal at cold start.
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=_har("https://api.example.com/orgs/acme/projects", minute=0),
        filename="orgs1.har",
    )
    assert _templates(neo4j_client, eid) == {"/orgs/acme/projects"}

    # Clear the l3-events stream so we can isolate the re-templating event below.
    redis_client.delete(L3_EVENTS_STREAM)

    # Batch 2: a second distinct word at the same interior slot overturns the
    # guess -> /orgs/{org_id}/projects; the old literal Endpoint is retracted.
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=_har("https://api.example.com/orgs/globex/projects", minute=5),
        filename="orgs2.har",
    )

    assert _templates(neo4j_client, eid) == {"/orgs/{org_id}/projects"}
    # Exactly one active templated Endpoint; the old literal is retracted, not gone.
    active = neo4j_client.execute_read(
        "MATCH (e:Endpoint {engagement_id: $eid}) WHERE e.status = 'active' "
        "RETURN count(e) AS c",
        eid=eid,
    )
    assert active[0]["c"] == 1
    retracted = neo4j_client.execute_read(
        "MATCH (e:Endpoint {engagement_id: $eid}) WHERE e.status = 'retracted' "
        "RETURN e.path_template AS t",
        eid=eid,
    )
    assert {r["t"] for r in retracted} == {"/orgs/acme/projects"}

    # Both observations now HIT the templated Endpoint (HIT re-grouped, obs not moved).
    hits = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid})-[:HIT]->"
        "(e:Endpoint {path_template: '/orgs/{org_id}/projects'}) RETURN count(*) AS c",
        eid=eid,
    )
    assert hits[0]["c"] == 2
    # The concrete paths are preserved unchanged on the observations.
    paths = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid}) "
        "RETURN r.concrete_path AS p ORDER BY p",
        eid=eid,
    )
    assert [r["p"] for r in paths] == ["/orgs/acme/projects", "/orgs/globex/projects"]

    # A node_updated L3 event was emitted with path_template {old, new}.
    msgs = redis_client.xrange(L3_EVENTS_STREAM)
    updates = [
        json.loads(fields["data"]) if "data" in fields else fields
        for _mid, fields in msgs
    ]
    node_updated = [m for m in updates if m.get("kind") == "node_updated"]
    assert node_updated, "expected a node_updated event from re-templating"
    change = node_updated[0]["changed_properties"]["path_template"]
    assert change["old"] == "/orgs/acme/projects"
    assert change["new"] == "/orgs/{org_id}/projects"


# --- Acceptance: cold-start single observation, UUID shape, confidence < 1.0. ---


def test_cold_start_uuid_confidence_below_one(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-t3-coldstart"
    _seed_engagement(neo4j_client, eid)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=_har(
            "https://api.example.com/files/550e8400-e29b-41d4-a716-446655440000"
        ),
        filename="cold.har",
    )
    rows = neo4j_client.execute_read(
        "MATCH (e:Endpoint {engagement_id: $eid}) "
        "RETURN e.path_template AS t, e.path_template_confidence AS c",
        eid=eid,
    )
    assert rows[0]["t"] == "/files/{file_id}"
    assert rows[0]["c"] < 1.0
    # And the path Parameter records the uuid shape prior.
    shape = neo4j_client.execute_read(
        "MATCH (:Endpoint {engagement_id: $eid})-[:HAS_PARAMETER]->"
        "(p:Parameter {location: 'path'}) RETURN p.value_shape AS s",
        eid=eid,
    )
    assert shape[0]["s"] == "uuid"


def test_cold_start_word_stays_literal(neo4j_client, redis_client, blob_client) -> None:
    eid = "eng-t3-word"
    _seed_engagement(neo4j_client, eid)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=_har("https://api.example.com/about"),
        filename="about.har",
    )
    assert _templates(neo4j_client, eid) == {"/about"}
    assert _count(neo4j_client, "Parameter", eid) == 0


# --- Acceptance: query Parameter aggregation + idempotency (no duplicates). ---


def test_query_parameter_aggregated_and_idempotent(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-t3-query"
    _seed_engagement(neo4j_client, eid)
    har = _har(
        "https://api.example.com/search?q=shoes&page=1",
        "https://api.example.com/search?q=hats&page=2",
    )
    # Ingest twice: Parameters must not duplicate (constraint per ADR-0017).
    for _ in range(2):
        _run_pipeline(
            neo4j=neo4j_client,
            redis_client=redis_client,
            blob_client=blob_client,
            engagement_id=eid,
            har_bytes=har,
            filename="search.har",
        )
    # One Endpoint /search; two query Parameters q + page, deduped.
    assert _templates(neo4j_client, eid) == {"/search"}
    qparams = neo4j_client.execute_read(
        "MATCH (:Endpoint {engagement_id: $eid})-[:HAS_PARAMETER]->"
        "(p:Parameter {location: 'query'}) RETURN p.name AS name ORDER BY name",
        eid=eid,
    )
    assert [r["name"] for r in qparams] == ["page", "q"]
    assert _count(neo4j_client, "Parameter", eid) == 2
