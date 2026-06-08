"""Golden end-to-end test for C3 (leak-to-input pivot coverage, issue #53).

Seeds a HAR through the real L1->L2->L3 pipeline (Neo4j + Redis + MinIO
testcontainers) and asserts C3's external behaviour: a value that surfaces in one
endpoint's *response* (output) and is sent as a request *parameter* to a
*different* in-scope endpoint (input) is surfaced as a pivot, naming the value,
its source endpoint(s), and the target endpoint + parameter name.

Cases (each a distinct UUID so promotion fires on leak-to-input, #16):

- **Cross-endpoint, in-scope target** (`/widgets` response -> `/detail/item/page`
  input on `api.example.com`): SHOULD surface by default.
- **Same-endpoint reuse** (a value both yielded and sent on the SAME `/echo`
  endpoint): EXCLUDED by default, appears only with `--include-same-endpoint`.
- **Cross-endpoint, out-of-scope target** (`/widgets` response -> input on
  `other.test`, not in `host_patterns`): EXCLUDED (the target must be in scope,
  ADR-0020 — though the source need not be).

Paths deliberately have distinct segment counts so the multiplicity templater
keeps them as separate `Endpoint`s; the test asserts on *behaviour* (pivot
present / absent), not on literal templated path strings.

Skips cleanly if docker / testcontainers is unavailable.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from doo.coverage.queries import run_c3
from doo.ids import EngagementId
from doo.infra.blobs import BlobClient
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.schema import apply_schema
from doo.setup.loader import PlannedMutation
from tests.test_pipeline_e2e import _run_pipeline

# Distinct UUIDs per case (each promotes via leak-to-input, #16).
CROSS_UUID = "aaaaaaaa-1111-2222-3333-444444444444"
SAME_UUID = "bbbbbbbb-1111-2222-3333-444444444444"
OOS_UUID = "cccccccc-1111-2222-3333-444444444444"

_SCOPE_RULES = {
    "host_patterns": ["api.example.com"],  # other.test is deliberately NOT in scope
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
    """Engagement + a real Scope so `is_in_scope` admits api.example.com only."""

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


def _output_entry(*, second: int, url: str, body: str) -> dict:
    """A 200 GET whose response body surfaces a value (the output side)."""

    return {
        "startedDateTime": f"2026-06-06T09:00:{second:02d}.000Z",
        "request": {
            "method": "GET",
            "url": url,
            "queryString": [],
            "headersSize": -1,
            "bodySize": 0,
        },
        "response": {
            "status": 200,
            "bodySize": len(body),
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"mimeType": "application/json", "text": body},
        },
    }


def _input_entry(*, second: int, url: str, query: list[dict[str, str]], body: str = "{}") -> dict:
    """A 200 GET carrying query parameters (the input side)."""

    return {
        "startedDateTime": f"2026-06-06T09:00:{second:02d}.000Z",
        "request": {
            "method": "GET",
            "url": url,
            "queryString": query,
            "headersSize": -1,
            "bodySize": 0,
        },
        "response": {
            "status": 200,
            "bodySize": len(body),
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"mimeType": "application/json", "text": body},
        },
    }


def _fixture_har() -> bytes:
    widgets = json.dumps(
        {"items": [{"id": CROSS_UUID}, {"id": OOS_UUID}]}
    )
    # Same-endpoint reuse: /sync/cursor (2 segments) yields a token in its response
    # AND the request carries it as a param -> same value, same endpoint, both roles.
    cursor_body = json.dumps({"page_token": SAME_UUID})
    # Distinct segment counts per endpoint so the multiplicity templater keeps them
    # as separate Endpoints rather than collapsing same-length siblings:
    #   /widgets (1) | /sync/cursor (2) | /detail/item/page (3) | other.test/.. (4)
    entries = [
        # Output side (in-scope source): /widgets (1 segment) leaks two UUIDs.
        _output_entry(second=1, url="https://api.example.com/widgets", body=widgets),
        # Cross-endpoint, in-scope target: /detail/item/page (3 segments).
        _input_entry(
            second=2,
            url=f"https://api.example.com/detail/item/page?widget_id={CROSS_UUID}",
            query=[{"name": "widget_id", "value": CROSS_UUID}],
        ),
        # Same-endpoint reuse on /sync/cursor (2 segments): output AND input.
        _output_entry(
            second=3,
            url=f"https://api.example.com/sync/cursor?page_token={SAME_UUID}",
            body=cursor_body,
        ),
        _input_entry(
            second=4,
            url=f"https://api.example.com/sync/cursor?page_token={SAME_UUID}",
            query=[{"name": "page_token", "value": SAME_UUID}],
        ),
        # Cross-endpoint, OUT-OF-SCOPE target: input goes to other.test (not in
        # host_patterns) -> the OOS_UUID pivot must be excluded.
        _input_entry(
            second=5,
            url=f"https://other.test/lookup/by/the/uuid?ref={OOS_UUID}",
            query=[{"name": "ref", "value": OOS_UUID}],
        ),
    ]
    return json.dumps({"log": {"version": "1.2", "entries": entries}}).encode()


def test_c3_surfaces_cross_endpoint_pivot(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-c3-e2e"
    _seed_engagement_in_scope(neo4j_client, eid)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=_fixture_har(),
        filename="c3.har",
    )

    # Sanity: each UUID promoted to an ObservedValue (leak-to-input, #16) with at
    # least one SENT_VALUE edge.
    sent = neo4j_client.execute_read(
        "MATCH (:RequestObservation {engagement_id: $eid})-[s:SENT_VALUE]->"
        "(v:ObservedValue {engagement_id: $eid}) "
        "RETURN collect(DISTINCT v.value) AS vals",
        eid=eid,
    )
    vals = set(sent[0]["vals"])
    assert {CROSS_UUID, SAME_UUID, OOS_UUID} <= vals, vals

    # --- Default: cross-endpoint, in-scope target only. ---
    # Non-secret UUIDs surface their (safe) raw value as the preview.
    rows = run_c3(neo4j_client, EngagementId(eid))

    # The cross-endpoint in-scope pivot SURFACES.
    cross = [r for r in rows if r.value_preview == CROSS_UUID]
    assert len(cross) == 1, [r.value_preview for r in rows]
    crow = cross[0]
    assert crow.parameter_name == "widget_id"
    assert crow.same_endpoint is False
    # The source endpoint (/widgets) is named; the target is the detail endpoint.
    assert any("widgets" in s for s in crow.source_endpoints), crow.source_endpoints
    assert "widgets" not in crow.target_path_template
    assert crow.shape_rank == 0  # UUID -> most-specific bucket
    assert 0.0 < crow.effective_confidence <= 1.0

    # The same-endpoint reuse is EXCLUDED by default.
    assert not any(r.value_preview == SAME_UUID for r in rows), (
        "same-endpoint reuse must be excluded by default"
    )

    # The out-of-scope-target pivot is EXCLUDED (target host not in scope).
    assert not any(r.value_preview == OOS_UUID for r in rows), (
        "out-of-scope-target pivot must be excluded"
    )

    # --- With --include-same-endpoint: the /echo reuse now appears. ---
    rows_same = run_c3(neo4j_client, EngagementId(eid), include_same_endpoint=True)
    same = [r for r in rows_same if r.value_preview == SAME_UUID]
    assert len(same) == 1, [r.value_preview for r in rows_same]
    assert same[0].same_endpoint is True
    assert same[0].parameter_name == "page_token"

    # The OOS target is STILL excluded even with the same-endpoint flag.
    assert not any(r.value_preview == OOS_UUID for r in rows_same)
