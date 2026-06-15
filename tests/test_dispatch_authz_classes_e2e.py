"""Authz-class dispatch e2e (S7/#92): boundary-violation end-to-end + C5 shrink.

The most novel new authz path: a `boundary-violation` TestCase resolves its
evidence via the `TrustBoundary -DERIVED_FROM-> RequestObservation` chain
(ADR-0039), dispatches the `primary`, and the Interpreter reaches a verdict — so
the boundary, a C5 gap beforehand, is covered (executed-to-verdict) afterward.

Skips cleanly when docker / testcontainers is unavailable.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
import redis

from doo.canonical.identity import auth_context_id, compute_auth_hash
from doo.coverage.queries import run_c5
from doo.dispatch.executor.dispatcher import RedisLeaseReader, StubOpaClient
from doo.dispatch.executor.send import HttpResponse, StubSender
from doo.dispatch.interpreter.loop import AssistantTurn
from doo.dispatch.ledger import InMemoryDispatchLedger
from doo.dispatch.models import DispatchSelection
from doo.dispatch.ontology import NoopBodyStore
from doo.dispatch.run import RunDependencies, arm_run, execute_run
from doo.dispatch.secrets import EnvSecretStore
from doo.events.slice4 import compute_testcase_key_hash
from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.infra.redis_lease import RedisLease
from doo.ontology.schema import apply_schema
from doo.setup.config import EngagementConfig

ENG = "eng-authz-classes-e2e"
HOSTNAME = "shop.example.com"
VICTIM = "bv-victim-token"  # noqa: S105
ATTACKER = "bv-attacker-token"  # noqa: S105
TB = "tb-bv-1"


class _AlwaysNotVulnerable:
    """Multi-turn caller that emits `not_vulnerable` on turn 1 for any TestCase."""

    def turn(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> AssistantTurn:
        args = {
            "verdict": "not_vulnerable",
            "justification": "boundary held (attacker side got 403-equivalent)",
            "observed_vs_expected": "no cross-boundary access",
            "evidence_refs": [],
            "affected_refs": [],
        }
        tc = {
            "id": "call_0",
            "type": "function",
            "function": {"name": "emit_verdict", "arguments": json.dumps(args)},
        }
        return AssistantTurn(tool_calls=(tc,), content=None, raw={"tool_calls": [tc]})


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


def _config() -> EngagementConfig:
    return EngagementConfig.model_validate(
        {
            "engagement": {"id": ENG, "name": "authz classes e2e"},
            "environment": "staging",
            "scope": {
                "host_patterns": [HOSTNAME],
                "allowed_methods": ["GET"],
                "allowed_path_patterns": ["/**"],
            },
            "dispatch": {"arming": "auto", "interpreter": "confirm"},
            "principals": [
                {"label": "victim-a", "auth_contexts": [{"kind": "bearer", "token": "${BV_VICTIM}"}]},
                {"label": "attacker-b", "auth_contexts": [{"kind": "bearer", "token": "${BV_ATTACKER}"}]},
            ],
        }
    )


def _seed(neo4j: Neo4jClient, *, attacker_ac: str, victim_ac: str) -> str:
    now = datetime.now(UTC)
    cross = {
        "source": "manual", "confidence": 1.0, "confidence_method": "manual",
        "first_seen": now, "last_seen": now, "ingested_at": now, "status": "active",
    }
    # Host + endpoint + a victim observation HITting it, and a TrustBoundary whose
    # DERIVED_FROM evidence is that observation (the ADR-0039 boundary-test path).
    neo4j.execute_write(
        """
        MERGE (h:Host {engagement_id:$eid, id:'h-bv'})
        ON CREATE SET h.scheme='https', h.canonical_hostname=$host, h.port=null,
                      h.is_ip_literal=false, h += $cross
        MERGE (e:Endpoint {engagement_id:$eid, id:'ep-bv'})
        ON CREATE SET e.method='GET', e.path_template='/orgs/{org_id}/projects', e += $cross
        MERGE (e)-[:ON_HOST]->(h)
        MERGE (acA:AuthContext {engagement_id:$eid, id:$victim_ac})
        ON CREATE SET acA.is_anonymous=false, acA.tier='declared', acA += $cross
        MERGE (acB:AuthContext {engagement_id:$eid, id:$attacker_ac})
        ON CREATE SET acB.is_anonymous=false, acB.tier='declared', acB += $cross
        MERGE (r:RequestObservation {engagement_id:$eid, observation_id:'obs-bv'})
        ON CREATE SET r.id='obs-bv', r.method='GET', r.concrete_path='/orgs/42/projects',
                      r.response_status=200, r.headers=['Accept=application/json'],
                      r.query=[], r.cookies=[], r += $cross
        MERGE (r)-[:HIT]->(e)
        MERGE (r)-[:ON_HOST]->(h)
        MERGE (r)-[:OBSERVED_UNDER]->(acA)
        MERGE (tb:TrustBoundary {engagement_id:$eid, id:$tb})
        ON CREATE SET tb.kind='tenant', tb.between_a_id=$attacker_ac,
                      tb.between_b_id=$victim_ac, tb += $cross
        MERGE (tb)-[:BETWEEN]->(acA)
        MERGE (tb)-[:BETWEEN]->(acB)
        MERGE (tb)-[:DERIVED_FROM]->(r)
        """,
        eid=ENG, host=HOSTNAME, attacker_ac=attacker_ac, victim_ac=victim_ac, tb=TB, cross=cross,
    )
    payload_hash = hashlib.sha256(b"").hexdigest()
    key_hash = compute_testcase_key_hash(
        engagement_id=EngagementId(ENG), test_class="boundary-violation",
        target_endpoint_id=None, target_parameter_id=None,
        target_trust_boundary_id=TB,  # type: ignore[arg-type]
        payload_class="boundary-probe", payload_hash=payload_hash,  # type: ignore[arg-type]
        auth_context_id=attacker_ac,  # type: ignore[arg-type]
    )
    neo4j.execute_write(
        """
        MATCH (tb:TrustBoundary {engagement_id:$eid, id:$tb})
        MERGE (t:TestCase {engagement_id:$eid, key_hash:$kh})
        ON CREATE SET t.test_class='boundary-violation', t.payload_class='boundary-probe',
                      t.payload_hash=$ph, t.auth_context_id=$attacker_ac,
                      t.target_trust_boundary_id=$tb, t.review_status='approved',
                      t.expected_yield=0.9, t.generator='capability', t.hold=[],
                      t.replay_hazards=[], t.source='llm-planner', t.confidence=0.99, t += $cross
        MERGE (t)-[:TARGETS_BOUNDARY]->(tb)
        """,
        eid=ENG, tb=TB, kh=key_hash, ph=payload_hash, attacker_ac=attacker_ac,
        cross={
            "source": "manual", "confidence": 1.0, "confidence_method": "manual",
            "first_seen": now, "last_seen": now, "ingested_at": now, "status": "active",
        },
    )
    return key_hash


def test_boundary_violation_dispatch_then_c5_shrinks(
    neo4j_client: Neo4jClient, redis_url: str
) -> None:
    config = _config()
    env = {"BV_VICTIM": VICTIM, "BV_ATTACKER": ATTACKER}
    secrets = EnvSecretStore.from_config(config, env=env)
    attacker_ac = auth_context_id(EngagementId(ENG), compute_auth_hash("bearer", ATTACKER))
    victim_ac = auth_context_id(EngagementId(ENG), compute_auth_hash("bearer", VICTIM))
    key_hash = _seed(neo4j_client, attacker_ac=attacker_ac, victim_ac=victim_ac)

    # Before the run: the boundary is a C5 gap (no TestCase executed-to-verdict).
    assert TB in {r.boundary_id for r in run_c5(neo4j_client, EngagementId(ENG))}

    rclient = redis.Redis.from_url(redis_url)
    lease = RedisLease(rclient, EngagementId(ENG))
    lease.set_active(ttl_seconds=60)

    run = arm_run(
        config=config,
        selection=DispatchSelection(test_classes=("boundary-violation",), limit=1),
        actor="e2e",
    )
    deps = RunDependencies(
        neo4j=neo4j_client, lease=RedisLeaseReader(lease=lease),
        opa=StubOpaClient(allow=True),
        sender=StubSender(response=HttpResponse(status=200, body=b'{"projects":[]}')),
        secrets=secrets, bodies=NoopBodyStore(), ledger=InMemoryDispatchLedger(),
        interpreter=_AlwaysNotVulnerable(),  # type: ignore[arg-type]
    )
    result = execute_run(run, deps)
    assert result.outcomes[0].outcome == "executed"

    # EXECUTED_AS(ok, primary) + the 4th-axis verdict on the TestCase.
    rows = neo4j_client.execute_read(
        """
        MATCH (t:TestCase {engagement_id:$eid, key_hash:$kh})
        OPTIONAL MATCH (t)-[x:EXECUTED_AS {request_role:'primary'}]->()
        RETURN t.interpreter_verdict AS v, x.dispatch_status AS s
        """,
        eid=ENG, kh=key_hash,
    )
    assert rows[0]["v"] == "not_vulnerable"
    assert rows[0]["s"] == "ok"

    # After the run: the boundary is no longer a C5 gap (tested-to-verdict).
    assert TB not in {r.boundary_id for r in run_c5(neo4j_client, EngagementId(ENG))}
