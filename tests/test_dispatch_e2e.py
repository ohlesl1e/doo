"""Slice-4 S1 dispatch-spine e2e over Neo4j + Redis testcontainers (issue #86).

Mirrors `test_planner_e2e.py`: seed an engagement (`environment = staging`) with
two declared Principals (victim + attacker), one Endpoint, one victim-side
`RequestObservation` HITting it, and one **`approved`** IDOR `TestCase` (attacker
auth_context). Arm a run with a `StubSender` (no real wire) and a live Redis
lease. Assert:

- `EXECUTED_AS(dispatch_status='ok', request_role='primary', run_id=…)` in the graph
- the agent `RequestObservation` carries `source = 'agent'` and is `OBSERVED_UNDER`
  the attacker's `AuthContext`
- the dispatch ledger has one `armed` row + one `executed` `RunOutcome`
- killing the lease → next send is `dispatcher_blocked('kill_switch')`

Skips cleanly when docker / testcontainers is unavailable.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
import redis

from doo.canonical.identity import auth_context_id, compute_auth_hash
from doo.dispatch.executor.dispatcher import RedisLeaseReader, StubOpaClient
from doo.dispatch.executor.send import HttpResponse, StubSender
from doo.dispatch.ledger import InMemoryDispatchLedger
from doo.dispatch.models import DispatchSelection
from doo.dispatch.ontology import NoopBodyStore
from doo.dispatch.run import RunDependencies, arm_run, execute_run
from doo.dispatch.secrets import EnvSecretStore
from doo.events.slice4 import compute_testcase_key_hash
from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.infra.redis_lease import RedisLease
from doo.ontology.graph_state import Neo4jGraphState
from doo.ontology.schema import apply_schema
from doo.setup.config import EngagementConfig
from doo.setup.loader import PlannedMutation

ENG = "eng-dispatch-e2e"
HOST_ID = "host-shop"
HOSTNAME = "shop.example.com"
EP_ID = "ep-orders"
VICTIM_TOKEN = "victim-jwt-aaa"  # noqa: S105 - test fixture
ATTACKER_TOKEN = "attacker-jwt-bbb"  # noqa: S105 - test fixture


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
def engagement_config() -> EngagementConfig:
    """A minimal staging engagement with two declared Principals (victim + attacker)."""
    return EngagementConfig.model_validate(
        {
            "engagement": {"id": ENG, "name": "dispatch e2e"},
            "environment": "staging",
            "scope": {
                "host_patterns": [HOSTNAME],
                "allowed_methods": ["GET"],
                "allowed_path_patterns": ["/**"],
            },
            "dispatch": {"arming": "auto", "interpreter": "confirm"},
            "principals": [
                {
                    "label": "victim-a",
                    "auth_contexts": [{"kind": "bearer", "token": "${E2E_VICTIM}"}],
                },
                {
                    "label": "attacker-b",
                    "auth_contexts": [{"kind": "bearer", "token": "${E2E_ATTACKER}"}],
                },
            ],
        }
    )


def _cross(now: datetime) -> dict[str, object]:
    return {
        "source": "manual",
        "source_id": None,
        "confidence": 1.0,
        "confidence_method": "manual",
        "first_seen": now,
        "last_seen": now,
        "ingested_at": now,
        "status": "active",
    }


def _seed_graph(neo4j: Neo4jClient, *, attacker_ac_id: str) -> str:
    """Seed engagement + host + endpoint + victim observation + approved IDOR TestCase.

    Returns the TestCase `key_hash`.
    """
    now = datetime.now(UTC)
    cross = _cross(now)
    state = Neo4jGraphState(neo4j)
    state.apply_mutations(
        (
            PlannedMutation(
                kind="scope_create",
                properties={
                    "content_hash": f"scope-{ENG}",
                    "rules": {
                        "host_patterns": [HOSTNAME],
                        "allowed_methods": ["*"],
                        "allowed_path_patterns": ["/**"],
                        "payload_class_denylist": [],
                        "rate_limit": None,
                        "time_window": None,
                        "required_headers": [],
                    },
                    **cross,
                },
            ),
            PlannedMutation(
                kind="engagement_create",
                properties={
                    "id": ENG,
                    "name": ENG,
                    "description": None,
                    "time_window": None,
                    "kill_switch": {"backend": "redis"},
                    "session_cookie_names": [],
                    "identity_key": None,
                    "environment": "staging",
                    **cross,
                },
            ),
            PlannedMutation(
                kind="engagement_under_scope",
                properties={
                    "engagement_id": ENG,
                    "scope_content_hash": f"scope-{ENG}",
                },
            ),
        )
    )

    # Host + Endpoint + a victim-side RequestObservation HITting it.
    neo4j.execute_write(
        """
        MERGE (h:Host {engagement_id: $eid, id: $hid})
        ON CREATE SET h.scheme = 'https', h.canonical_hostname = $hostname,
                      h.port = null, h.is_ip_literal = false, h += $cross
        MERGE (e:Endpoint {engagement_id: $eid, id: $epid})
        ON CREATE SET e.method = 'GET', e.path_template = '/orders/{order_id}',
                      e += $cross
        MERGE (e)-[:ON_HOST]->(h)
        MERGE (acA:AuthContext {engagement_id: $eid, id: $ac_victim})
        ON CREATE SET acA.auth_hash = $ah_victim, acA.tier = 'declared',
                      acA.is_anonymous = false, acA.token_kind = 'bearer',
                      acA += $cross
        MERGE (acB:AuthContext {engagement_id: $eid, id: $ac_attacker})
        ON CREATE SET acB.auth_hash = $ah_attacker, acB.tier = 'declared',
                      acB.is_anonymous = false, acB.token_kind = 'bearer',
                      acB += $cross
        MERGE (r:RequestObservation {engagement_id: $eid, observation_id: 'obs-victim-1'})
        ON CREATE SET r.id = 'obs-victim-1', r.method = 'GET',
                      r.concrete_path = '/orders/123', r.response_status = 200,
                      r.headers = ['Authorization=Bearer victim-...',
                                   'Accept=application/json'],
                      r.query = [], r.cookies = [], r += $cross
        MERGE (r)-[:HIT]->(e)
        MERGE (r)-[:ON_HOST]->(h)
        MERGE (r)-[:OBSERVED_UNDER]->(acA)
        """,
        eid=ENG,
        hid=HOST_ID,
        hostname=HOSTNAME,
        epid=EP_ID,
        ac_victim=auth_context_id(EngagementId(ENG), compute_auth_hash("bearer", VICTIM_TOKEN)),
        ah_victim=compute_auth_hash("bearer", VICTIM_TOKEN),
        ac_attacker=attacker_ac_id,
        ah_attacker=compute_auth_hash("bearer", ATTACKER_TOKEN),
        cross=cross,
    )

    # An **approved** IDOR TestCase under the attacker's AuthContext.
    payload_hash = hashlib.sha256(b"").hexdigest()
    key_hash = compute_testcase_key_hash(
        engagement_id=EngagementId(ENG),
        test_class="idor",
        target_endpoint_id=EP_ID,
        target_parameter_id=None,
        target_trust_boundary_id=None,
        payload_class="auth-token-swap",
        payload_hash=payload_hash,  # type: ignore[arg-type]
        auth_context_id=attacker_ac_id,  # type: ignore[arg-type]
    )
    neo4j.execute_write(
        """
        MATCH (e:Endpoint {engagement_id: $eid, id: $epid})
        MERGE (t:TestCase {engagement_id: $eid, key_hash: $kh})
        ON CREATE SET t.test_class = 'idor', t.payload_class = 'auth-token-swap',
                      t.payload_hash = $ph, t.auth_context_id = $ac_attacker,
                      t.target_endpoint_id = $epid,
                      t.review_status = 'approved', t.expected_yield = 0.9,
                      t.generator = 'c2', t.hold = ['order_id'],
                      t.replay_hazards = [], t.source = 'llm-planner',
                      t.confidence = 0.99, t += $cross
        MERGE (t)-[:TARGETS_ENDPOINT]->(e)
        """,
        eid=ENG,
        epid=EP_ID,
        kh=key_hash,
        ph=payload_hash,
        ac_attacker=attacker_ac_id,
        cross=cross,
    )
    return key_hash


def test_dispatch_spine_e2e(
    neo4j_client: Neo4jClient, redis_url: str, engagement_config: EngagementConfig
) -> None:
    """Arm one run → one IDOR `primary` through the full gate → `EXECUTED_AS` + ledger.

    Then kill the lease → next dispatch is `dispatcher_blocked('kill_switch')`.
    """
    env = {"E2E_VICTIM": VICTIM_TOKEN, "E2E_ATTACKER": ATTACKER_TOKEN}
    secrets = EnvSecretStore.from_config(engagement_config, env=env)
    attacker_ac_id = auth_context_id(
        EngagementId(ENG), compute_auth_hash("bearer", ATTACKER_TOKEN)
    )
    assert secrets.material_for(attacker_ac_id) is not None

    key_hash = _seed_graph(neo4j_client, attacker_ac_id=attacker_ac_id)

    # Live kill-switch lease (the keepalive's job; here, set directly).
    rclient = redis.Redis.from_url(redis_url)
    lease = RedisLease(rclient, EngagementId(ENG))
    lease.set_active(ttl_seconds=60)

    sender = StubSender(
        response=HttpResponse(status=200, body=b'{"order_id":123,"owner":"victim"}')
    )
    ledger = InMemoryDispatchLedger()

    run = arm_run(
        config=engagement_config,
        selection=DispatchSelection(test_classes=("idor",), limit=1),
        actor="e2e-tester",
    )
    deps = RunDependencies(
        neo4j=neo4j_client,
        lease=RedisLeaseReader(lease=lease),
        opa=StubOpaClient(allow=True),
        sender=sender,
        secrets=secrets,
        bodies=NoopBodyStore(),
        ledger=ledger,
    )
    result = execute_run(run, deps)

    # --- one TestCase drained, one wire send. ---
    assert len(result.outcomes) == 1
    outcome = result.outcomes[0]
    assert outcome.outcome == "executed"
    assert outcome.key_hash == key_hash
    assert result.requests_sent == 1
    assert len(sender.sent) == 1
    sent = sender.sent[0]
    assert sent.path == "/orders/123"
    assert dict(sent.headers).get("Authorization") == f"Bearer {ATTACKER_TOKEN}"

    # --- ledger: one `armed` + one `outcome` row, with the ADR-0042 audit shape. ---
    events = ledger.events_for(EngagementId(ENG), run.run_id)
    assert [e.kind for e in events] == ["armed", "outcome"]
    armed = events[0]
    assert armed.actor == "e2e-tester"
    assert armed.environment == "staging"
    assert armed.selection is not None and armed.selection.limit == 1

    # --- graph: `EXECUTED_AS(dispatch_status='ok', request_role='primary', run_id)`. ---
    rows = neo4j_client.execute_read(
        """
        MATCH (t:TestCase {engagement_id: $eid, key_hash: $kh})
              -[x:EXECUTED_AS]->(r:RequestObservation)
        OPTIONAL MATCH (r)-[:OBSERVED_UNDER]->(ac:AuthContext)
        RETURN x.dispatch_status AS status, x.request_role AS role, x.run_id AS run_id,
               r.source AS source, r.concrete_path AS path, r.response_status AS http,
               ac.id AS ac_id
        """,
        eid=ENG,
        kh=key_hash,
    )
    assert len(rows) == 1
    row = rows[0]
    assert row["status"] == "ok"
    assert row["role"] == "primary"
    assert row["run_id"] == run.run_id
    assert row["source"] == "agent"
    assert row["path"] == "/orders/123"
    assert row["http"] == 200
    # The agent send is OBSERVED_UNDER the attacker's AuthContext (not the victim's).
    assert row["ac_id"] == attacker_ac_id

    # Auth header was redacted on the persisted observation (ADR-0015):
    obs_rows = neo4j_client.execute_read(
        """
        MATCH (t:TestCase {engagement_id: $eid, key_hash: $kh})
              -[:EXECUTED_AS]->(r:RequestObservation)
        RETURN r.headers AS headers
        """,
        eid=ENG,
        kh=key_hash,
    )
    persisted_headers = obs_rows[0]["headers"]
    assert any(h.startswith("Authorization=") for h in persisted_headers)
    assert ATTACKER_TOKEN not in " ".join(persisted_headers)

    # --- kill the lease → next send is `dispatcher_blocked('kill_switch')`. ---
    lease.release()
    run2 = arm_run(
        config=engagement_config,
        selection=DispatchSelection(test_classes=("idor",), limit=1),
        actor="e2e-tester",
    )
    result2 = execute_run(run2, deps)
    assert len(result2.outcomes) == 1
    assert result2.outcomes[0].outcome == "dispatcher_blocked"
    assert result2.outcomes[0].reason == "kill_switch"
    # No additional wire send.
    assert len(sender.sent) == 1
