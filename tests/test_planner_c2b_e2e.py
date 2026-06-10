"""End-to-end test for the C2b LLM-proposing planner generator (issue #63, S2b).

Seeds a HAR through the real L1->L2->L3 pipeline (Neo4j + Redis + MinIO
testcontainers) so a genuine C2b content-differential gap exists — `admin` and
`user` BOTH 200 on `/profile` but with DIFFERING response bodies (the role-
differentiated-200 BOLA/IDOR hotspot, ADR-0033) — and the request carries an
`X-CSRF-Token` header (a replay-breaker, ADR-0041). Then runs `propose` with the
C2b generator wired to a `FakeLLMCaller` (a canned IDOR draft) and an
`InMemoryLLMAuditSink`. No model and no `litellm` are involved; the deterministic
spine (gap selection -> pack assembly -> handle resolution -> replay-hazard
detection -> validate -> commit) is what is exercised.

Asserts:
- one `TestCase` committed at `source = llm-planner`, `test_class = idor`,
  `review_status = proposed`, the fixed authz-replay `payload_class`;
- the committed node carries `replay_hazards` containing `csrf_token` — the
  deterministic detector flagged the `X-CSRF-Token` header (set by CODE, ADR-0041);
- the resolved attacker `auth_context_id` is one of the reaching principals.

Two distinct JWT `sub` claims key two discovered Principals (ADR-0030), as in
`test_coverage_c2b_e2e.py`. Skips cleanly if docker / testcontainers is unavailable.
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

_C2B_ONLY = PlannerConfig(candidate_generators=("c2b",))


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


def _entry(*, second: int, bearer: str, path: str, status: int, body: str, csrf: str) -> dict:
    """A GET observation carrying an explicit body + an `X-CSRF-Token` header."""

    return {
        "startedDateTime": f"2026-06-06T09:00:{second:02d}.000Z",
        "request": {
            "method": "GET",
            "url": f"https://api.example.com{path}",
            "queryString": [],
            "headers": [
                {"name": "Authorization", "value": f"Bearer {bearer}"},
                {"name": "X-CSRF-Token", "value": csrf},
            ],
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


def _seed_content_differential(neo4j_client, redis_client, blob_client, eid: str) -> None:
    """admin + user BOTH 200 on /profile with DIFFERING bodies; both carry a CSRF token."""

    _seed_engagement_in_scope(neo4j_client, eid)
    admin = jwt.encode({"sub": "c2b-admin"}, SIGNING_KEY, algorithm="HS256")
    user = jwt.encode({"sub": "c2b-user"}, SIGNING_KEY, algorithm="HS256")
    admin_body = json.dumps({"id": 1, "owner": "admin", "secret": "boardroom"})
    user_body = json.dumps({"id": 1, "owner": "user"})
    # High-entropy, session-bound CSRF tokens (per principal) -> the replay-breaker.
    entries = [
        _entry(
            second=1,
            bearer=admin,
            path="/profile",
            status=200,
            body=admin_body,
            csrf="Qk3mZ8tVr2Lp9xWf6Hd1Nc4Bs7Yg0Aj",
        ),
        _entry(
            second=2,
            bearer=user,
            path="/profile",
            status=200,
            body=user_body,
            csrf="Td5nP1qXw8Kc3Vb6Rh2Mf9Lz0Js4Ye7",
        ),
    ]
    har = json.dumps({"log": {"version": "1.2", "entries": entries}}).encode()
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=har,
        filename="c2b-planner.har",
    )


def _draft(**over: object) -> LLMProposalDraft:
    base: dict[str, object] = {
        "test_class": "idor",
        "target_ref": "T1",
        "auth_context_ref": "A2",  # one of the reaching principals (attacker candidate)
        "hold": ("T1",),
        "justification": "both 200 with differing bodies; check one reads the other's",
        "expected_outcome": "a 2xx returning the other principal's body confirms IDOR",
        "expected_yield": 0.85,
    }
    base.update(over)
    return LLMProposalDraft.model_validate(base)


def test_c2b_generator_commits_idor_with_csrf_hazard(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-c2b-planner-e2e"
    _seed_content_differential(neo4j_client, redis_client, blob_client, eid)

    # Sanity: the X-CSRF-Token landed as a header-borne input value candidate.
    csrf_seen = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid}) "
        "WHERE any(vc IN r.value_candidates WHERE vc CONTAINS 'X-CSRF-Token') "
        "RETURN count(r) AS c",
        eid=eid,
    )[0]["c"]
    assert csrf_seen >= 1, "X-CSRF-Token must be extracted as a value candidate"

    sink = InMemoryLLMAuditSink()
    result = propose(
        neo4j_client,
        engagement_id=EngagementId(eid),
        config=_C2B_ONLY,
        llm_caller=FakeLLMCaller(_draft()),
        llm_audit_sink=sink,
    )

    assert result.candidates == 1
    assert result.committed == 1 and result.created == 1
    assert result.llm_rejected == () and result.llm_skipped == ()

    key_hash = result.committed_key_hashes[0]
    node = fetch_testcase(neo4j_client, EngagementId(eid), key_hash)
    assert node is not None
    assert node.source == "llm-planner"  # ADR-0036: LLM contribution
    assert node.test_class == "idor"
    assert node.payload_class == "auth-token-swap"
    assert node.review_status == "proposed"

    # ADR-0041: the committed node carries the code-set replay-hazard annotation,
    # detected deterministically from the X-CSRF-Token request header.
    row = neo4j_client.execute_read(
        "MATCH (t:TestCase {engagement_id: $eid, key_hash: $k}) "
        "RETURN t.replay_hazards AS hazards, t.target_endpoint_id AS ep",
        eid=eid,
        k=key_hash,
    )[0]
    assert row["hazards"] is not None
    assert "csrf_token" in list(row["hazards"])

    # The target is the differential endpoint (/profile).
    ep_path = neo4j_client.execute_read(
        "MATCH (t:TestCase {engagement_id: $eid, key_hash: $k})-[:TARGETS_ENDPOINT]->"
        "(e:Endpoint) RETURN e.path_template AS pt",
        eid=eid,
        k=key_hash,
    )[0]["pt"]
    assert ep_path == "/profile"

    # The resolved attacker auth context is one of the two reaching principals.
    acs = {
        r["id"]
        for r in neo4j_client.execute_read(
            "MATCH (ac:AuthContext {engagement_id: $eid})-[:OF_PRINCIPAL]->"
            "(p:Principal) WHERE p.is_anonymous = false RETURN ac.id AS id",
            eid=eid,
        )
    }
    chosen = neo4j_client.execute_read(
        "MATCH (t:TestCase {engagement_id: $eid, key_hash: $k}) "
        "RETURN t.auth_context_id AS ac",
        eid=eid,
        k=key_hash,
    )[0]["ac"]
    assert chosen in acs
