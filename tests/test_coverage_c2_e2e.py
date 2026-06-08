"""Golden end-to-end test for C2 (presence-differential authz coverage).

Seeds a HAR through the real L1->L2->L3 pipeline (Neo4j + Redis + MinIO
testcontainers) with two principals over an *overlapping* endpoint that returns
differently per principal:

- `admin` (JWT bearer, sub=c2-admin) gets **200** on `GET /admin/panel`,
- `user`  (JWT bearer, sub=c2-user)  gets **401** on `GET /admin/panel`,
- both get **200** on a shared `GET /dashboard` (a non-differential control).

This is the canonical authz boundary. The test asserts C2's external behaviour
per ADR-0033:

- `C2(admin, user)` surfaces `/admin/panel` — admin reached (2xx), user did not
  (401 is *not* reached, the bypass candidate), with A=200 evidence and B=null;
- `C2(user, admin)` does NOT surface it — user never reached it;
- the shared `/dashboard` (both 200) is never a gap (both reached);
- the promoted `response_size_bytes` lands on the node as queryable evidence.

Skips cleanly if docker / testcontainers is unavailable. Reuses the established
testcontainer fixtures and the identity pipeline (two distinct JWT `sub` claims
key two distinct discovered Principals, ADR-0030).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime

import jwt
import pytest

from doo.coverage.queries import run_c2
from doo.ids import EngagementId
from doo.infra.blobs import BlobClient
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.schema import apply_schema
from doo.setup.loader import PlannedMutation
from tests.test_pipeline_e2e import _run_pipeline

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
    """Engagement + a real (non-empty) Scope so `is_in_scope` admits api.example.com."""

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


def _entry(*, second: int, bearer: str, path: str, status: int) -> dict:
    body = json.dumps({"ok": status < 400, "path": path})
    return {
        "startedDateTime": f"2026-06-06T09:00:{second:02d}.000Z",
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


def _label_of(rows, principal_a, principal_b):  # type: ignore[no-untyped-def]
    return {(r.principal_a_label, r.principal_b_label, r.path_template) for r in rows}


def test_c2_surfaces_admin_only_endpoint_and_respects_direction(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-c2-e2e"
    _seed_engagement_in_scope(neo4j_client, eid)

    admin = jwt.encode({"sub": "c2-admin"}, SIGNING_KEY, algorithm="HS256")
    user = jwt.encode({"sub": "c2-user"}, SIGNING_KEY, algorithm="HS256")
    entries = [
        # Overlapping shared endpoint: both reach it (200) -> NOT a gap.
        _entry(second=1, bearer=admin, path="/dashboard", status=200),
        _entry(second=2, bearer=user, path="/dashboard", status=200),
        # The authz boundary: admin 200, user 401 -> the C2(admin,user) gap.
        _entry(second=3, bearer=admin, path="/admin/panel", status=200),
        _entry(second=4, bearer=user, path="/admin/panel", status=401),
    ]
    har = json.dumps({"log": {"version": "1.2", "entries": entries}}).encode()
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=har,
        filename="c2.har",
    )

    # Sanity: both principals exist as distinct discovered Principals.
    plabels = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid}) WHERE p.is_anonymous = false "
        "RETURN collect(p.identity_key) AS keys",
        eid=eid,
    )
    keys = set(plabels[0]["keys"])
    assert "discovered:sub:c2-admin" in keys
    assert "discovered:sub:c2-user" in keys

    # The promoted body-metadata evidence lands on the node (ADR-0033 prereq).
    sized = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid}) "
        "WHERE r.response_size_bytes IS NOT NULL RETURN count(r) AS c",
        eid=eid,
    )
    assert sized[0]["c"] == 4

    # The discovered principals carry no `label`; C2 falls back to identity_key.
    admin_lbl = "discovered:sub:c2-admin"
    user_lbl = "discovered:sub:c2-user"

    # Direction A=admin, B=user: /admin/panel is the gap; /dashboard is not.
    a_to_b = run_c2(neo4j_client, EngagementId(eid), as_label=admin_lbl, not_as_label=user_lbl)
    gaps = _label_of(a_to_b, admin_lbl, user_lbl)
    assert (admin_lbl, user_lbl, "/admin/panel") in gaps
    assert (admin_lbl, user_lbl, "/dashboard") not in gaps  # both reached -> no gap
    assert all(r.path_template == "/admin/panel" for r in a_to_b)

    # Evidence: A is a real 200 with a size; B is null (user's 401 is not reached).
    row = next(r for r in a_to_b if r.path_template == "/admin/panel")
    assert row.evidence_a.status == 200
    assert row.evidence_a.response_size_bytes is not None
    assert row.evidence_b is None
    assert 0.0 < row.effective_confidence <= 1.0

    # Reverse direction A=user, B=admin: user never reached /admin/panel -> empty.
    b_to_a = run_c2(neo4j_client, EngagementId(eid), as_label=user_lbl, not_as_label=admin_lbl)
    assert b_to_a == []

    # No-pin run computes all ordered pairs and still contains the admin->user gap.
    all_pairs = run_c2(neo4j_client, EngagementId(eid))
    assert (admin_lbl, user_lbl, "/admin/panel") in _label_of(all_pairs, admin_lbl, user_lbl)
