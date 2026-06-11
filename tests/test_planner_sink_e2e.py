"""End-to-end test for the S6 sink_params generator (#65).

Seeds a HAR with an endpoint taking a `redirect` query parameter; the deterministic
detector flags it `redirect_target`, the `sink` generator proposes an open-redirect
test against that Parameter, and the Validator resolves the **configured** payload to
a real `payload_hash`. No dispatch.

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

_SCOPE_RULES = {
    "host_patterns": ["api.example.com"],
    "allowed_methods": ["*"],
    "allowed_path_patterns": ["/**"],
    "payload_class_denylist": [],
    "rate_limit": None,
    "time_window": None,
    "required_headers": [],
}
# The configured-probe content address the validator resolves (matches
# validator._resolve_payload_hash for kind=configured, key="sink_callback").
_EXPECTED_PH = hashlib.sha256(b"configured-probe:sink_callback").hexdigest()


@pytest.fixture
def neo4j_client(neo4j_container) -> Iterator[Neo4jClient]:
    client = Neo4jClient.connect(
        neo4j_container.get_connection_url(), neo4j_container.username, neo4j_container.password)
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
        endpoint_url=minio_config["endpoint_url"], access_key=minio_config["access_key"],
        secret_key=minio_config["secret_key"], bucket="doo-blobs")


def _seed(neo4j: Neo4jClient, eid: str) -> None:
    now = datetime.now(UTC)
    cross = {"source": "manual", "source_id": None, "confidence": 1.0, "confidence_method": "manual",
             "first_seen": now, "last_seen": now, "ingested_at": now, "status": "active"}
    from doo.ontology.graph_state import Neo4jGraphState
    Neo4jGraphState(neo4j).apply_mutations((
        PlannedMutation(kind="scope_create", properties={"content_hash": f"s-{eid}", "rules": _SCOPE_RULES, **cross}),
        PlannedMutation(kind="engagement_create", properties={"id": eid, "name": eid, "description": None,
            "time_window": None, "kill_switch": {"backend": "redis"}, **cross}),
        PlannedMutation(kind="engagement_under_scope", properties={"engagement_id": eid, "scope_content_hash": f"s-{eid}"}),
    ))


def _entry(second: int, url: str, query: list[dict]) -> dict:
    return {
        "startedDateTime": f"2026-06-06T09:00:{second:02d}.000Z",
        "request": {"method": "GET", "url": url, "queryString": query, "headersSize": -1, "bodySize": 0},
        "response": {"status": 302, "bodySize": 2,
                     "headers": [{"name": "Location", "value": "https://example.com/dest"}],
                     "content": {"mimeType": "text/html", "text": "{}"}},
    }


def test_sink_generator_commits_open_redirect_with_configured_payload(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-sink-e2e"
    _seed(neo4j_client, eid)
    har = json.dumps({"log": {"version": "1.2", "entries": [
        _entry(1, "https://api.example.com/go?redirect=https://example.com/dest",
               [{"name": "redirect", "value": "https://example.com/dest"}]),
    ]}}).encode()
    _run_pipeline(neo4j=neo4j_client, redis_client=redis_client, blob_client=blob_client,
                  engagement_id=eid, har_bytes=har, filename="sink.har")

    draft = LLMProposalDraft(
        test_class="open-redirect", target_ref="T1", auth_context_ref="A1",
        justification="the redirect param is reflected into Location; test open-redirect",
        expected_outcome="a 3xx to the configured probe confirms open redirect",
        expected_yield=0.7)
    result = propose(
        neo4j_client, engagement_id=EngagementId(eid),
        config=PlannerConfig(candidate_generators=("sink",)),
        llm_caller=FakeLLMCaller(draft), llm_audit_sink=InMemoryLLMAuditSink())

    assert result.committed >= 1
    key = result.committed_key_hashes[0]
    node = fetch_testcase(neo4j_client, EngagementId(eid), key)
    assert node is not None
    assert node.source == "llm-planner"
    assert node.test_class == "open-redirect"
    assert node.payload_class == "ssrf-callback"
    assert node.target_parameter_id is not None and node.target_endpoint_id is None

    # Targets the sink Parameter (redirect) and the configured payload resolved.
    row = neo4j_client.execute_read(
        "MATCH (t:TestCase {engagement_id:$e, key_hash:$k})-[:TARGETS_PARAMETER]->(p:Parameter) "
        "RETURN p.name AS name, t.payload_hash AS ph", e=eid, k=key)[0]
    assert row["name"] == "redirect"
    assert row["ph"] == _EXPECTED_PH
