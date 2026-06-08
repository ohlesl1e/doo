"""Golden end-to-end test for C2b (content-differential authz coverage).

Seeds a HAR through the real L1->L2->L3 pipeline (Neo4j + Redis + MinIO
testcontainers) and asserts C2b's external behaviour per ADR-0033 — the
*role-differentiated-200* case C2's presence query is blind to:

- `GET /orders/mine/detail` returns **200 to BOTH** `admin` and `user`, but with
  **different bodies** (different sha256 and size) — the BOLA/IDOR signal C2b must
  surface;
- `GET /dashboard` returns **200 to BOTH** with the **identical body** — both
  reached, no divergence, must NOT appear;
- `GET /admin/panel` returns 200 to **only** `admin` — a single-principal reach,
  no ≥2-principal group, must NOT appear.

Paths deliberately have distinct segment counts (3 / 1 / 2) so the multiplicity
templater keeps them as three separate `Endpoint`s rather than collapsing
distinct first-segments into a shared `{id}` template.

Coverage surfaces the divergence as evidence (per-principal `(status, size,
sha256)`); it does not adjudicate whether it is a vulnerability (ADR-0033).

Skips cleanly if docker / testcontainers is unavailable. Reuses the established
testcontainer fixtures and the identity pipeline (distinct JWT `sub` claims key
distinct discovered Principals, ADR-0030).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime

import jwt
import pytest

from doo.coverage.queries import run_c2b
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


def _entry(*, second: int, bearer: str, path: str, status: int, body: str) -> dict:
    """A GET observation carrying an explicit response body (drives sha256/size)."""

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


def test_c2b_surfaces_role_differentiated_200(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-c2b-e2e"
    _seed_engagement_in_scope(neo4j_client, eid)

    admin = jwt.encode({"sub": "c2b-admin"}, SIGNING_KEY, algorithm="HS256")
    user = jwt.encode({"sub": "c2b-user"}, SIGNING_KEY, algorithm="HS256")

    divergent_path = "/orders/mine/detail"  # 3 segments, distinct from the others
    # both 200, DIFFERENT bodies (different sha256 AND size) -> C2b row.
    admin_orders = json.dumps({"id": 1, "owner": "admin", "total": 999, "items": [1, 2, 3]})
    user_orders = json.dumps({"id": 1, "owner": "user"})
    # /dashboard: both 200 with IDENTICAL body -> NOT a divergence.
    shared = json.dumps({"widgets": ["a", "b"]})

    entries = [
        # Role-differentiated 200: the BOLA/IDOR signal C2b must surface.
        _entry(second=1, bearer=admin, path=divergent_path, status=200, body=admin_orders),
        _entry(second=2, bearer=user, path=divergent_path, status=200, body=user_orders),
        # Both reached with the SAME body -> excluded (not a divergence).
        _entry(second=3, bearer=admin, path="/dashboard", status=200, body=shared),
        _entry(second=4, bearer=user, path="/dashboard", status=200, body=shared),
        # Single-principal 200 -> no ≥2-principal group -> excluded.
        _entry(second=5, bearer=admin, path="/admin/panel", status=200, body=admin_orders),
    ]
    har = json.dumps({"log": {"version": "1.2", "entries": entries}}).encode()
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=har,
        filename="c2b.har",
    )

    # Sanity: both principals exist as distinct discovered Principals.
    plabels = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid}) WHERE p.is_anonymous = false "
        "RETURN collect(p.identity_key) AS keys",
        eid=eid,
    )
    keys = set(plabels[0]["keys"])
    assert "discovered:sub:c2b-admin" in keys
    assert "discovered:sub:c2b-user" in keys

    # The promoted body-metadata evidence lands on the node (ADR-0033 prereq):
    # every observation carries a sha256 + a size.
    promoted = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid}) "
        "WHERE r.response_body_sha256 IS NOT NULL AND r.response_size_bytes IS NOT NULL "
        "RETURN count(r) AS c",
        eid=eid,
    )
    assert promoted[0]["c"] == 5

    rows = run_c2b(neo4j_client, EngagementId(eid))

    # Exactly ONE divergence: the role-differentiated-200 endpoint. The identical-
    # body `/dashboard` (both reached, same body) and the single-reach
    # `/admin/panel` are correctly excluded, so they never appear in `rows`.
    assert len(rows) == 1, [r.path_template for r in rows]
    orders_row = rows[0]
    assert "/dashboard" not in orders_row.path_template
    assert "/admin/panel" not in orders_row.path_template

    # Both principals reached it with a 2xx.
    labels = {ev.label for ev in orders_row.evidence}
    assert labels == {"discovered:sub:c2b-admin", "discovered:sub:c2b-user"}
    # The divergence is real in the stored metadata: distinct sha256s, distinct
    # sizes — surfaced from promoted node properties, no body parsed.
    shas = {ev.response_body_sha256 for ev in orders_row.evidence}
    sizes = {ev.response_size_bytes for ev in orders_row.evidence}
    assert len(shas) == 2 and None not in shas
    assert len(sizes) == 2
    for ev in orders_row.evidence:
        assert ev.status == 200
        assert ev.response_size_bytes is not None
    assert 0.0 < orders_row.effective_confidence <= 1.0
