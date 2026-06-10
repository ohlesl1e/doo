"""End-to-end test for the C2 LLM-proposing planner generator (issue #62, S2a).

Seeds a HAR through the real L1->L2->L3 pipeline (Neo4j + Redis + MinIO
testcontainers) so a genuine C2 presence gap exists — `admin` reaches
`GET /admin/panel` (200), `user` is blocked (401) — then runs `propose` with the
C2 generator wired to a `FakeLLMCaller` (a canned draft) and an
`InMemoryLLMAuditSink`. No model and no `litellm` are involved; the deterministic
spine around the LLM (gap selection -> pack assembly -> handle resolution ->
validate -> commit -> audit persistence) is what is exercised.

Asserts the committed contribution per ADR-0036/0037:
- one `TestCase` committed at `source = llm-planner`, `review_status = proposed`,
  the LLM-classified `test_class`, the fixed authz-replay `payload_class`;
- the resolved attacker `auth_context_id` is the B side (`user`), not A (`admin`);
- the target endpoint is the gap endpoint;
- the proposing call is persisted and its key stamped on the node (`llm_audit_key`);
- a draft naming a hallucinated handle is rejected, commits nothing.

Skips cleanly if docker / testcontainers is unavailable.
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
from doo.ontology.schema import apply_schema
from doo.planner.commit import fetch_testcase
from doo.planner.generators import PlannerConfig
from doo.planner.llm import FakeLLMCaller
from doo.planner.llm_audit import InMemoryLLMAuditSink
from doo.planner.models import LLMProposalDraft
from doo.planner.service import propose
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

_C2_ONLY = PlannerConfig(candidate_generators=("c2",))


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


def _seed_one_gap(neo4j_client, redis_client, blob_client, eid: str) -> None:
    """admin 200, user 401 on /admin/panel — exactly one C2 gap (admin -> user)."""

    _seed_engagement_in_scope(neo4j_client, eid)
    admin = jwt.encode({"sub": "c2-admin", "role": "admin"}, SIGNING_KEY, algorithm="HS256")
    user = jwt.encode({"sub": "c2-user", "role": "user"}, SIGNING_KEY, algorithm="HS256")
    entries = [
        _entry(second=1, bearer=admin, path="/admin/panel", status=200),
        _entry(second=2, bearer=user, path="/admin/panel", status=401),
    ]
    har = json.dumps({"log": {"version": "1.2", "entries": entries}}).encode()
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=har,
        filename="c2-planner.har",
    )


def _draft(**over: object) -> LLMProposalDraft:
    base: dict[str, object] = {
        "test_class": "idor",
        "target_ref": "T1",
        "auth_context_ref": "A2",  # the attacker side (B = user)
        "hold": ("T1",),
        "justification": "admin reached the admin panel; check user can reach it",
        "expected_outcome": "a 2xx as user confirms the authz boundary is bypassable",
        "expected_yield": 0.8,
    }
    base.update(over)
    return LLMProposalDraft.model_validate(base)


def test_c2_generator_commits_llm_proposal(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-c2-planner-e2e"
    _seed_one_gap(neo4j_client, redis_client, blob_client, eid)

    sink = InMemoryLLMAuditSink()
    result = propose(
        neo4j_client,
        engagement_id=EngagementId(eid),
        config=_C2_ONLY,
        llm_caller=FakeLLMCaller(_draft()),
        llm_audit_sink=sink,
    )

    assert result.candidates == 1
    assert result.committed == 1 and result.created == 1
    assert result.llm_rejected == () and result.llm_skipped == ()

    key_hash = result.committed_key_hashes[0]
    node = fetch_testcase(neo4j_client, EngagementId(eid), key_hash)
    assert node is not None
    assert node.source == "llm-planner"  # ADR-0036: LLM contribution, not deterministic
    assert node.test_class == "idor"  # the LLM's classification
    assert node.payload_class == "auth-token-swap"  # fixed authz-replay (ADR-0041)
    assert node.review_status == "proposed"

    # The resolved attacker auth context is the B side (user), never A (admin).
    user_ac = neo4j_client.execute_read(
        "MATCH (ac:AuthContext {engagement_id: $eid})-[:OF_PRINCIPAL]->"
        "(p:Principal {identity_key: 'discovered:sub:c2-user'}) RETURN ac.id AS id",
        eid=eid,
    )[0]["id"]
    row = neo4j_client.execute_read(
        "MATCH (t:TestCase {engagement_id: $eid, key_hash: $k}) "
        "RETURN t.auth_context_id AS ac, t.target_endpoint_id AS ep, "
        "t.llm_audit_key AS audit, t.expected_yield AS y, t.expected_yield_method AS ym",
        eid=eid,
        k=key_hash,
    )[0]
    assert row["ac"] == user_ac

    # The target endpoint is the gap endpoint (/admin/panel).
    ep_path = neo4j_client.execute_read(
        "MATCH (t:TestCase {engagement_id: $eid, key_hash: $k})-[:TARGETS_ENDPOINT]->"
        "(e:Endpoint) RETURN e.path_template AS pt",
        eid=eid,
        k=key_hash,
    )[0]["pt"]
    assert ep_path == "/admin/panel"

    # expected_yield is the LLM's self-reported hunch (separate from validity).
    assert row["y"] == pytest.approx(0.8)
    assert row["ym"] == "llm-self-reported"

    # The proposing call was persisted and its key stamped on the node (ADR-0037).
    assert row["audit"] is not None
    assert row["audit"] in sink.stored


def test_c2_hallucinated_handle_is_rejected_and_commits_nothing(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-c2-planner-halluc"
    _seed_one_gap(neo4j_client, redis_client, blob_client, eid)

    sink = InMemoryLLMAuditSink()
    result = propose(
        neo4j_client,
        engagement_id=EngagementId(eid),
        config=_C2_ONLY,
        llm_caller=FakeLLMCaller(_draft(target_ref="T9")),  # not a pack handle
        llm_audit_sink=sink,
    )

    assert result.candidates == 1
    assert result.committed == 0
    assert len(result.llm_rejected) == 1
    assert result.llm_rejected[0].code == "unknown_target"
    # Nothing committed, but the rejected call is still persisted for replay.
    assert len(sink.stored) == 1
    n = neo4j_client.execute_read(
        "MATCH (t:TestCase {engagement_id: $eid}) RETURN count(t) AS n", eid=eid
    )[0]["n"]
    assert n == 0
