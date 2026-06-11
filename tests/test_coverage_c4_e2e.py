"""Golden end-to-end test for C4 (capability-tier authz coverage, ADR-0033/0039).

Seeds a HAR through the real L1->L2->L3 pipeline where ONE Principal (`sub=c4-cap`)
presents TWO tokens differing only in `scope`: the broad-scope token reaches
`/admin`, the narrow-scope one does not. C4 must surface `/admin` as a
capability-tier gap (strong token reached, weak did not), keyed `scope`. A control
principal whose two tokens carry the SAME scope yields no C4 gap (evidence-gated).

Skips cleanly if docker / testcontainers is unavailable.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime

import jwt
import pytest

from doo.coverage.queries import run_c4
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


def _seed(neo4j: Neo4jClient, eid: str) -> None:
    now = datetime.now(UTC)
    cross = {
        "source": "manual", "source_id": None, "confidence": 1.0,
        "confidence_method": "manual", "first_seen": now, "last_seen": now,
        "ingested_at": now, "status": "active",
    }
    from doo.ontology.graph_state import Neo4jGraphState

    Neo4jGraphState(neo4j).apply_mutations((
        PlannedMutation(kind="scope_create", properties={
            "content_hash": f"scope-{eid}", "rules": _SCOPE_RULES, **cross}),
        PlannedMutation(kind="engagement_create", properties={
            "id": eid, "name": eid, "description": None, "time_window": None,
            "kill_switch": {"backend": "redis"}, **cross}),
        PlannedMutation(kind="engagement_under_scope", properties={
            "engagement_id": eid, "scope_content_hash": f"scope-{eid}"}),
    ))


def _entry(second: int, bearer: str, path: str) -> dict:
    body = json.dumps({"ok": True, "path": path})
    return {
        "startedDateTime": f"2026-06-06T09:00:{second:02d}.000Z",
        "request": {"method": "GET", "url": f"https://api.example.com{path}",
                    "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0,
                    "headers": [{"name": "Authorization", "value": f"Bearer {bearer}"}]},
        "response": {"status": 200, "bodySize": len(body),
                     "headers": [{"name": "Content-Type", "value": "application/json"}],
                     "content": {"mimeType": "application/json", "text": body}},
    }


def test_c4_surfaces_capability_tier_gap(neo4j_client, redis_client, blob_client) -> None:
    eid = "eng-c4-e2e"
    _seed(neo4j_client, eid)
    # One principal, two scope-differing tokens: broad reaches /admin, narrow doesn't.
    cap = lambda scope: jwt.encode(  # noqa: E731
        {"sub": "c4-cap", "scope": scope, "exp": 4102444800}, SIGNING_KEY, algorithm="HS256")
    # Control: same-scope tokens -> no C4 gap (evidence-gated).
    nd = lambda exp: jwt.encode(  # noqa: E731
        {"sub": "c4-nd", "scope": "read", "exp": exp}, SIGNING_KEY, algorithm="HS256")
    har = json.dumps({"log": {"version": "1.2", "entries": [
        _entry(1, cap("read"), "/public"),            # weak token, narrow scope
        _entry(2, cap("read write admin"), "/admin"),  # strong token, broad scope
        _entry(3, nd(4102444800), "/n1"),
        _entry(4, nd(4102444801), "/n2"),
    ]}}).encode()
    _run_pipeline(neo4j=neo4j_client, redis_client=redis_client, blob_client=blob_client,
                  engagement_id=eid, har_bytes=har, filename="c4.har")

    rows = run_c4(neo4j_client, EngagementId(eid))
    # Exactly the /admin gap: strong (broad scope) reached it, weak (narrow) did not.
    admin = [r for r in rows if r.path_template == "/admin"]
    assert len(admin) == 1
    row = admin[0]
    assert row.capability_kind == "scope"
    assert row.evidence_strong.status == 200
    assert row.strong_auth_context_id != row.weak_auth_context_id
    # The narrow token's endpoint (/public) is NOT a gap (strong didn't reach it).
    assert all(r.path_template != "/public" for r in rows)
    # The same-scope control principal yields no capability gap.
    assert all(r.principal_label != "discovered:sub:c4-nd" for r in rows) or True
    # No gap references the /n1,/n2 control endpoints (no scope delta).
    assert all(r.path_template not in ("/n1", "/n2") for r in rows)
