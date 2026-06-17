"""End-to-end test for the S5 boundary-targeting generators (#66, ADR-0039).

Seeds a HAR (via the real pipeline) that S4 inference turns into a **capability**
`TrustBoundary` (one Principal, two scope-differing tokens on `/me`) and two
**tenant** `TrustBoundary`s (org-42/43 share `/orgs/{org_id}/projects`; ws-a/b share
`/workspaces/{workspace_id}/files`). Then runs `propose` with the `c4` (capability)
and `tenant` generators + a `FakeLLMCaller`, asserting committed `TARGETS_BOUNDARY`
TestCases whose concrete endpoint was resolved from the boundary's `DERIVED_FROM`
evidence (the boundary carries no endpoint edge — XOR preserved).

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
    body = json.dumps({"ok": True})
    return {
        "startedDateTime": f"2026-06-06T09:00:{second:02d}.000Z",
        "request": {"method": "GET", "url": f"https://api.example.com{path}",
                    "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0,
                    "headers": [{"name": "Authorization", "value": f"Bearer {bearer}"}]},
        "response": {"status": 200, "bodySize": len(body),
                     "headers": [{"name": "Content-Type", "value": "application/json"}],
                     "content": {"mimeType": "application/json", "text": body}},
    }


def _boundary_har() -> bytes:
    cap_a = jwt.encode({"sub": "b5-cap", "scope": "read", "exp": 4102444800}, SIGNING_KEY, algorithm="HS256")
    cap_b = jwt.encode({"sub": "b5-cap", "scope": "read write admin", "exp": 4102444800}, SIGNING_KEY, algorithm="HS256")
    org42 = jwt.encode({"sub": "b5-org42"}, SIGNING_KEY, algorithm="HS256")
    org43 = jwt.encode({"sub": "b5-org43"}, SIGNING_KEY, algorithm="HS256")
    return json.dumps({"log": {"version": "1.2", "entries": [
        _entry(1, cap_a, "/me"),
        _entry(2, cap_b, "/me"),
        _entry(3, org42, "/orgs/42/projects"),
        _entry(4, org43, "/orgs/43/projects"),
    ]}}).encode()


def _run(neo4j, redis_client, blob_client, eid: str) -> None:
    _seed(neo4j, eid)
    _run_pipeline(neo4j=neo4j, redis_client=redis_client, blob_client=blob_client,
                  engagement_id=eid, har_bytes=_boundary_har(), filename="boundary.har")
    # #110: an authz replay only swaps in a credential the tester controls. The
    # fixture takes the loader shortcut of ingesting the controlled tokens via HAR,
    # so promote them to the declared tier the loader would have set.
    neo4j.execute_write(
        "MATCH (ac:AuthContext {engagement_id: $eid}) "
        "WHERE coalesce(ac.is_anonymous, false) = false SET ac.tier = 'declared'",
        eid=eid,
    )


def test_capability_boundary_proposal_targets_boundary(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-b5-cap"
    _run(neo4j_client, redis_client, blob_client, eid)
    # Sanity: S4 inferred a capability boundary.
    caps = neo4j_client.execute_read(
        "MATCH (tb:TrustBoundary {engagement_id:$e}) WHERE tb.kind IN ['scope','mfa','freshness'] "
        "RETURN count(tb) AS n", e=eid)[0]["n"]
    assert caps >= 1

    draft = LLMProposalDraft(
        test_class="privilege-escalation", target_ref="T1", auth_context_ref="A2",
        hold=("T1",), justification="replay the admin-scope request under the read token",
        expected_outcome="a 2xx under the weaker token confirms missing scope enforcement",
        expected_yield=0.7)
    result = propose(
        neo4j_client, engagement_id=EngagementId(eid),
        config=PlannerConfig(candidate_generators=("c4",)),
        llm_caller=FakeLLMCaller(draft), llm_audit_sink=InMemoryLLMAuditSink())

    assert result.committed >= 1
    key = result.committed_key_hashes[0]
    node = fetch_testcase(neo4j_client, EngagementId(eid), key)
    assert node is not None
    assert node.source == "llm-planner"
    assert node.test_class == "privilege-escalation"
    assert node.target_trust_boundary_id is not None
    assert node.target_endpoint_id is None and node.target_parameter_id is None
    # TARGETS_BOUNDARY edge to a TrustBoundary; the boundary has NO endpoint edge.
    edge = neo4j_client.execute_read(
        "MATCH (t:TestCase {engagement_id:$e, key_hash:$k})-[:TARGETS_BOUNDARY]->(tb:TrustBoundary) "
        "RETURN tb.kind AS kind", e=eid, k=key)
    assert edge and edge[0]["kind"] in ("scope", "mfa", "freshness")


def test_tenant_boundary_proposal_targets_boundary(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-b5-tenant"
    _run(neo4j_client, redis_client, blob_client, eid)
    tcount = neo4j_client.execute_read(
        "MATCH (tb:TrustBoundary {engagement_id:$e, kind:'tenant'}) RETURN count(tb) AS n",
        e=eid)[0]["n"]
    assert tcount >= 1

    draft = LLMProposalDraft(
        test_class="idor", target_ref="T1", auth_context_ref="A2", hold=("T1",),
        justification="hold tenant-42's project ref, swap tenant-43's auth",
        expected_outcome="a 2xx returning tenant-42's data under tenant-43 confirms cross-tenant access",
        expected_yield=0.8)
    result = propose(
        neo4j_client, engagement_id=EngagementId(eid),
        config=PlannerConfig(candidate_generators=("tenant",)),
        llm_caller=FakeLLMCaller(draft), llm_audit_sink=InMemoryLLMAuditSink())

    assert result.committed >= 1
    key = result.committed_key_hashes[0]
    node = fetch_testcase(neo4j_client, EngagementId(eid), key)
    assert node is not None
    assert node.test_class == "idor"
    assert node.target_trust_boundary_id is not None
    edge = neo4j_client.execute_read(
        "MATCH (t:TestCase {engagement_id:$e, key_hash:$k})-[:TARGETS_BOUNDARY]->(tb:TrustBoundary {kind:'tenant'}) "
        "RETURN count(tb) AS n", e=eid, k=key)
    assert edge[0]["n"] == 1
