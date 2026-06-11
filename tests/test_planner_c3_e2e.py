"""End-to-end test for the S3 C3 leak-replay generator (#64).

Seeds a HAR through the real L1->L2->L3 pipeline so a genuine C3 leak-to-input pivot
exists — a UUID surfaces in `/widgets`' response (output) and is sent as the
`widget_id` query parameter to in-scope `/detail/item/page` (input) — then runs
`propose` with the C3 generator wired to a `FakeLLMCaller`. Asserts the committed
contribution per #64:
- one `TestCase` at `source=llm-planner`, `test_class=leak_replay`, `proposed`;
- it targets the input **Parameter** (`TARGETS_PARAMETER` -> the `widget_id` node),
  not an endpoint;
- the `observed_value` payload is resolved to a real `payload_hash` == the leaked
  `ObservedValue`'s `value_hash` (not the empty-payload sentinel).

Skips cleanly if docker / testcontainers is unavailable.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime

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

LEAK_UUID = "aaaaaaaa-1111-2222-3333-444444444444"
_C3_ONLY = PlannerConfig(candidate_generators=("c3",))

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


def _seed_engagement(neo4j: Neo4jClient, eid: str) -> None:
    now = datetime.now(UTC)
    cross = {
        "source": "manual", "source_id": None, "confidence": 1.0,
        "confidence_method": "manual", "first_seen": now, "last_seen": now,
        "ingested_at": now, "status": "active",
    }
    from doo.ontology.graph_state import Neo4jGraphState

    Neo4jGraphState(neo4j).apply_mutations(
        (
            PlannedMutation(kind="scope_create", properties={
                "content_hash": f"scope-{eid}", "rules": _SCOPE_RULES, **cross}),
            PlannedMutation(kind="engagement_create", properties={
                "id": eid, "name": eid, "description": None, "time_window": None,
                "kill_switch": {"backend": "redis"}, **cross}),
            PlannedMutation(kind="engagement_under_scope", properties={
                "engagement_id": eid, "scope_content_hash": f"scope-{eid}"}),
        )
    )


def _output_entry(second: int, url: str, body: str) -> dict:
    return {
        "startedDateTime": f"2026-06-06T09:00:{second:02d}.000Z",
        "request": {"method": "GET", "url": url, "queryString": [], "headersSize": -1, "bodySize": 0},
        "response": {"status": 200, "bodySize": len(body),
                     "headers": [{"name": "Content-Type", "value": "application/json"}],
                     "content": {"mimeType": "application/json", "text": body}},
    }


def _input_entry(second: int, url: str, query: list[dict[str, str]]) -> dict:
    return {
        "startedDateTime": f"2026-06-06T09:00:{second:02d}.000Z",
        "request": {"method": "GET", "url": url, "queryString": query, "headersSize": -1, "bodySize": 0},
        "response": {"status": 200, "bodySize": 2,
                     "headers": [{"name": "Content-Type", "value": "application/json"}],
                     "content": {"mimeType": "application/json", "text": "{}"}},
    }


def test_c3_generator_commits_leak_replay_targeting_parameter(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-c3-planner-e2e"
    _seed_engagement(neo4j_client, eid)
    # /widgets (1 seg) leaks the UUID; /detail/item/page (3 seg) consumes it as
    # widget_id — distinct segment counts so templating keeps them separate.
    har = json.dumps({"log": {"version": "1.2", "entries": [
        _output_entry(1, "https://api.example.com/widgets",
                      json.dumps({"items": [{"id": LEAK_UUID}]})),
        _input_entry(2, f"https://api.example.com/detail/item/page?widget_id={LEAK_UUID}",
                     [{"name": "widget_id", "value": LEAK_UUID}]),
    ]}}).encode()
    _run_pipeline(neo4j=neo4j_client, redis_client=redis_client, blob_client=blob_client,
                  engagement_id=eid, har_bytes=har, filename="c3.har")

    draft = LLMProposalDraft(
        test_class="leak_replay", target_ref="T1", auth_context_ref="A1",
        justification="the app handed out this id and /detail consumes it; replay it",
        expected_outcome="a 2xx returning another widget's detail confirms the pivot",
        expected_yield=0.6)
    result = propose(
        neo4j_client, engagement_id=EngagementId(eid), config=_C3_ONLY,
        llm_caller=FakeLLMCaller(draft), llm_audit_sink=InMemoryLLMAuditSink())

    assert result.candidates == 1
    assert result.committed == 1 and result.created == 1
    assert result.llm_rejected == () and result.llm_skipped == ()

    key = result.committed_key_hashes[0]
    node = fetch_testcase(neo4j_client, EngagementId(eid), key)
    assert node is not None
    assert node.source == "llm-planner"
    assert node.test_class == "leak_replay"
    assert node.review_status == "proposed"
    assert node.target_parameter_id is not None and node.target_endpoint_id is None

    # Targets the input PARAMETER via TARGETS_PARAMETER -> the widget_id node.
    pname = neo4j_client.execute_read(
        "MATCH (t:TestCase {engagement_id:$e, key_hash:$k})-[:TARGETS_PARAMETER]->(p:Parameter) "
        "RETURN p.name AS name", e=eid, k=key)[0]["name"]
    assert pname == "widget_id"

    # observed_value payload resolved to the leaked ObservedValue's hash (real, not
    # the empty-payload sentinel).
    row = neo4j_client.execute_read(
        "MATCH (t:TestCase {engagement_id:$e, key_hash:$k}) "
        "RETURN t.payload_class AS pc, t.payload_hash AS ph", e=eid, k=key)[0]
    assert row["pc"] == "benign-probe"
    assert row["ph"] != hashlib.sha256(b"").hexdigest()
    ov = neo4j_client.execute_read(
        "MATCH (v:ObservedValue {engagement_id:$e}) WHERE v.value = $val "
        "RETURN v.value_hash AS vh", e=eid, val=LEAK_UUID)
    assert ov and row["ph"] == ov[0]["vh"]
