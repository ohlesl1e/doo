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
from doo.dispatch.finding import (
    InMemoryFindingLedger,
    list_proposed_findings,
    review_finding,
)
from doo.dispatch.interpreter.loop import FakeMultiTurnCaller
from doo.dispatch.ledger import InMemoryDispatchLedger
from doo.dispatch.models import DispatchSelection
from doo.dispatch.ontology import NoopBodyStore
from doo.dispatch.run import RunDependencies, arm_run, execute_run
from doo.dispatch.secrets import EnvSecretStore
from doo.events.execution import compute_testcase_key_hash
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
        attacker_principal="attacker",
        attacker_slot="bearer",
    )
    neo4j.execute_write(
        """
        MATCH (e:Endpoint {engagement_id: $eid, id: $epid})
        MERGE (t:TestCase {engagement_id: $eid, key_hash: $kh})
        ON CREATE SET t.test_class = 'idor', t.payload_class = 'auth-token-swap',
                      t.payload_hash = $ph, t.auth_context_id = $ac_attacker,
                      t.attacker_principal = 'attacker', t.attacker_slot = 'bearer',
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


ENG_LIVE = "eng-dispatch-liveness-e2e"


def _seed_authz_graph(
    neo4j: Neo4jClient, *, eng: str, attacker_ac_id: str, victim_ac_id: str
) -> str:
    """Lean seed for the liveness e2e: host + endpoint + victim obs + approved IDOR TC.

    No Engagement/Scope node (the liveness test uses StubOpaClient(allow=True), so
    no bundle is built); only what `select_testcases` + `load_evidence` read.
    Returns the TestCase `key_hash`.
    """
    now = datetime.now(UTC)
    cross = _cross(now)
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
        ON CREATE SET acA.auth_hash = 'ah-v', acA.tier = 'declared',
                      acA.is_anonymous = false, acA.token_kind = 'bearer', acA += $cross
        MERGE (acB:AuthContext {engagement_id: $eid, id: $ac_attacker})
        ON CREATE SET acB.auth_hash = 'ah-a', acB.tier = 'declared',
                      acB.is_anonymous = false, acB.token_kind = 'bearer', acB += $cross
        MERGE (r:RequestObservation {engagement_id: $eid, observation_id: 'obs-v-live'})
        ON CREATE SET r.id = 'obs-v-live', r.method = 'GET',
                      r.concrete_path = '/orders/123', r.response_status = 200,
                      r.headers = ['Accept=application/json'], r.query = [],
                      r.cookies = [], r += $cross
        MERGE (r)-[:HIT]->(e)
        MERGE (r)-[:ON_HOST]->(h)
        MERGE (r)-[:OBSERVED_UNDER]->(acA)
        """,
        eid=eng,
        hid=HOST_ID,
        hostname=HOSTNAME,
        epid=EP_ID,
        ac_victim=victim_ac_id,
        ac_attacker=attacker_ac_id,
        cross=cross,
    )
    payload_hash = hashlib.sha256(b"").hexdigest()
    key_hash = compute_testcase_key_hash(
        engagement_id=EngagementId(eng),
        test_class="idor",
        target_endpoint_id=EP_ID,
        target_parameter_id=None,
        target_trust_boundary_id=None,
        payload_class="auth-token-swap",
        payload_hash=payload_hash,  # type: ignore[arg-type]
        attacker_principal="attacker",
        attacker_slot="bearer",
    )
    neo4j.execute_write(
        """
        MATCH (e:Endpoint {engagement_id: $eid, id: $epid})
        MERGE (t:TestCase {engagement_id: $eid, key_hash: $kh})
        ON CREATE SET t.test_class = 'idor', t.payload_class = 'auth-token-swap',
                      t.payload_hash = $ph, t.auth_context_id = $ac_attacker,
                      t.attacker_principal = 'attacker', t.attacker_slot = 'bearer',
                      t.target_endpoint_id = $epid, t.review_status = 'approved',
                      t.expected_yield = 0.9, t.generator = 'c2', t.hold = ['order_id'],
                      t.replay_hazards = [], t.source = 'llm-planner',
                      t.confidence = 0.99, t += $cross
        MERGE (t)-[:TARGETS_ENDPOINT]->(e)
        """,
        eid=eng,
        epid=EP_ID,
        kh=key_hash,
        ph=payload_hash,
        ac_attacker=attacker_ac_id,
        cross=cross,
    )
    return key_hash


class _PathScriptedSender:
    """`Sender` that returns a canned response keyed by request path; records sends."""

    def __init__(self, by_path: dict[str, HttpResponse]) -> None:
        self._by_path = by_path
        self.sent: list[object] = []

    def send(self, request: object) -> HttpResponse:
        self.sent.append(request)
        path = request.path  # type: ignore[attr-defined]
        return self._by_path.get(path, HttpResponse(status=500, body=b"unscripted"))


def _liveness_config(eng: str) -> EngagementConfig:
    """Attacker principal declares a `liveness_endpoint` (ADR-0044)."""
    return EngagementConfig.model_validate(
        {
            "engagement": {"id": eng, "name": "liveness e2e"},
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
                    "liveness_endpoint": {"method": "GET", "path": "/me"},
                },
            ],
        }
    )


@pytest.mark.parametrize(
    "probe_status,expected_status,expect_reactive",
    [
        (200, "ok", False),  # token live → boundary genuinely held
        (403, "auth_invalid", True),  # token dead → auth_invalid + reactive refresh
    ],
)
def test_authz_liveness_e2e(
    neo4j_client: Neo4jClient,
    redis_url: str,
    probe_status: int,
    expected_status: str,
    expect_reactive: bool,
) -> None:
    """ADR-0044: an authz `primary` 403 + a liveness probe disambiguates the status.

    primary(/orders/123)=403; probe(/me)=200 → `ok`; probe(/me)=403 → `auth_invalid`
    + one reactive `auth_invalid` event.
    """
    from doo.dispatch.executor.liveness import LivenessPolicy
    from doo.dispatch.reactive import FakeReactiveEmitter

    env = {"E2E_VICTIM": VICTIM_TOKEN, "E2E_ATTACKER": ATTACKER_TOKEN}
    config = _liveness_config(ENG_LIVE)
    secrets = EnvSecretStore.from_config(config, env=env)
    attacker_ac_id = auth_context_id(
        EngagementId(ENG_LIVE), compute_auth_hash("bearer", ATTACKER_TOKEN)
    )
    victim_ac_id = auth_context_id(
        EngagementId(ENG_LIVE), compute_auth_hash("bearer", VICTIM_TOKEN)
    )
    key_hash = _seed_authz_graph(
        neo4j_client,
        eng=ENG_LIVE,
        attacker_ac_id=attacker_ac_id,
        victim_ac_id=victim_ac_id,
    )

    rclient = redis.Redis.from_url(redis_url)
    lease = RedisLease(rclient, EngagementId(ENG_LIVE))
    lease.set_active(ttl_seconds=60)

    sender = _PathScriptedSender(
        {
            "/orders/123": HttpResponse(status=403, body=b'{"error":"forbidden"}'),
            "/me": HttpResponse(status=probe_status, body=b'{"id":"attacker"}'),
        }
    )
    reactive = FakeReactiveEmitter()
    run = arm_run(
        config=config,
        selection=DispatchSelection(test_classes=("idor",), limit=1),
        actor="e2e-tester",
    )
    deps = RunDependencies(
        neo4j=neo4j_client,
        lease=RedisLeaseReader(lease=lease),
        opa=StubOpaClient(allow=True),
        sender=sender,  # type: ignore[arg-type]
        secrets=secrets,
        bodies=NoopBodyStore(),
        ledger=InMemoryDispatchLedger(),
        liveness=LivenessPolicy.from_config(
            config, graph_map={attacker_ac_id: ("attacker-b", "bearer")}
        ),
        reactive=reactive,
    )
    result = execute_run(run, deps)

    assert result.outcomes[0].outcome == "executed"
    # primary + liveness probe both went on the wire.
    paths = [r.path for r in sender.sent]  # type: ignore[attr-defined]
    assert paths == ["/orders/123", "/me"]
    assert result.requests_sent == 2

    # The `primary` EXECUTED_AS edge carries the DISAMBIGUATED status.
    rows = neo4j_client.execute_read(
        """
        MATCH (t:TestCase {engagement_id: $eid, key_hash: $kh})
              -[x:EXECUTED_AS {run_id: $rid}]->(:RequestObservation)
        RETURN x.request_role AS role, x.dispatch_status AS status
        ORDER BY role
        """,
        eid=ENG_LIVE,
        kh=key_hash,
        rid=run.run_id,
    )
    by_role = {r["role"]: r["status"] for r in rows}
    assert by_role["primary"] == expected_status
    # The probe is recorded as its own `liveness` agent observation (ADR-0044).
    assert by_role.get("liveness") == "ok"

    # The reactive refresh fires exactly when the token is judged dead.
    assert len(reactive.events) == (1 if expect_reactive else 0)
    if expect_reactive:
        ev = reactive.events[0]
        assert ev["kind"] == "auth_invalid"
        assert ev["auth_context_id"] == attacker_ac_id
        assert ev["principal_label"] == "attacker-b"


ENG_HZ = "eng-dispatch-csrf-e2e"


def _seed_csrf_graph(
    neo4j: Neo4jClient,
    *,
    eng: str,
    attacker_ac_id: str,
    victim_ac_id: str,
    with_referer: bool,
) -> str:
    """Seed an approved IDOR TestCase whose evidence carries a `_csrf` query param.

    When `with_referer`, the victim observation also carries a `Referer` header so
    the run derives a CSRF `source_hint` and resolves it; otherwise the hazard is
    unresolvable. Returns the TestCase `key_hash`.
    """
    now = datetime.now(UTC)
    cross = _cross(now)
    headers = ["Accept=application/json"]
    if with_referer:
        headers.append("Referer=https://shop.example.com/orders/new")
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
        ON CREATE SET acA.auth_hash='ah-v', acA.tier='declared',
                      acA.is_anonymous=false, acA.token_kind='bearer', acA += $cross
        MERGE (acB:AuthContext {engagement_id: $eid, id: $ac_attacker})
        ON CREATE SET acB.auth_hash='ah-a', acB.tier='declared',
                      acB.is_anonymous=false, acB.token_kind='bearer', acB += $cross
        MERGE (r:RequestObservation {engagement_id: $eid, observation_id: 'obs-csrf'})
        ON CREATE SET r.id='obs-csrf', r.method='GET', r.concrete_path='/orders/123',
                      r.response_status=200, r.headers=$headers,
                      r.query=['_csrf=stale-token'], r.cookies=[], r += $cross
        MERGE (r)-[:HIT]->(e)
        MERGE (r)-[:ON_HOST]->(h)
        MERGE (r)-[:OBSERVED_UNDER]->(acA)
        """,
        eid=eng, hid=HOST_ID, hostname=HOSTNAME, epid=EP_ID,
        ac_victim=victim_ac_id, ac_attacker=attacker_ac_id, headers=headers, cross=cross,
    )
    payload_hash = hashlib.sha256(b"").hexdigest()
    key_hash = compute_testcase_key_hash(
        engagement_id=EngagementId(eng), test_class="idor",
        target_endpoint_id=EP_ID, target_parameter_id=None, target_trust_boundary_id=None,
        payload_class="auth-token-swap", payload_hash=payload_hash,  # type: ignore[arg-type]
        attacker_principal="attacker", attacker_slot="bearer",
    )
    neo4j.execute_write(
        """
        MATCH (e:Endpoint {engagement_id: $eid, id: $epid})
        MERGE (t:TestCase {engagement_id: $eid, key_hash: $kh})
        ON CREATE SET t.test_class='idor', t.payload_class='auth-token-swap',
                      t.payload_hash=$ph, t.auth_context_id=$ac_attacker,
                      t.attacker_principal='attacker', t.attacker_slot='bearer',
                      t.target_endpoint_id=$epid, t.review_status='approved',
                      t.expected_yield=0.9, t.generator='c2', t.hold=['order_id'],
                      t.replay_hazards=['csrf_token'], t.source='llm-planner',
                      t.confidence=0.99, t += $cross
        MERGE (t)-[:TARGETS_ENDPOINT]->(e)
        """,
        eid=eng, epid=EP_ID, kh=key_hash, ph=payload_hash, ac_attacker=attacker_ac_id, cross=cross,
    )
    return key_hash


def test_csrf_hazard_resolution_e2e(
    neo4j_client: Neo4jClient, redis_url: str
) -> None:
    """S5: a `_csrf` replay hazard is fetched + spliced so the IDOR `primary` sends.

    With a `Referer`, the run warm-fetches the form page, extracts a fresh token,
    splices it, and the `primary` carries it. Without one, the hazard is
    unresolvable → `hazard_unresolved`, visible in `doo dispatch review`.
    """
    from doo.dispatch.executor.liveness import LivenessPolicy

    config = _liveness_config(ENG_HZ)  # reuse the two-principal staging config shape
    config = config.model_copy(update={"engagement": config.engagement.model_copy(update={"id": ENG_HZ})})
    env = {"E2E_VICTIM": VICTIM_TOKEN, "E2E_ATTACKER": ATTACKER_TOKEN}
    secrets = EnvSecretStore.from_config(config, env=env)
    attacker_ac_id = auth_context_id(EngagementId(ENG_HZ), compute_auth_hash("bearer", ATTACKER_TOKEN))
    victim_ac_id = auth_context_id(EngagementId(ENG_HZ), compute_auth_hash("bearer", VICTIM_TOKEN))

    rclient = redis.Redis.from_url(redis_url)
    lease = RedisLease(rclient, EngagementId(ENG_HZ))
    lease.set_active(ttl_seconds=60)

    # --- phase A: Referer present → warmup fetch resolves the token. ---
    _seed_csrf_graph(
        neo4j_client, eng=ENG_HZ, attacker_ac_id=attacker_ac_id,
        victim_ac_id=victim_ac_id, with_referer=True,
    )
    sender = _PathScriptedSender(
        {
            "/orders/new": HttpResponse(
                status=200, body=b'<form><input name="_csrf" value="FRESH-TOKEN"></form>'
            ),
            "/orders/123": HttpResponse(status=200, body=b'{"order_id":123}'),
        }
    )
    ledger = InMemoryDispatchLedger()
    run = arm_run(
        config=config,
        selection=DispatchSelection(test_classes=("idor",), limit=1),
        actor="e2e",
    )
    deps = RunDependencies(
        neo4j=neo4j_client, lease=RedisLeaseReader(lease=lease),
        opa=StubOpaClient(allow=True), sender=sender,  # type: ignore[arg-type]
        secrets=secrets, bodies=NoopBodyStore(), ledger=ledger,
        liveness=LivenessPolicy.from_config(config),
    )
    result = execute_run(run, deps)

    assert result.outcomes[0].outcome == "executed"
    # warmup (/orders/new) then primary (/orders/123).
    paths = [r.path for r in sender.sent]  # type: ignore[attr-defined]
    assert paths == ["/orders/new", "/orders/123"]
    primary = sender.sent[1]
    assert dict(primary.query).get("_csrf") == "FRESH-TOKEN"  # type: ignore[attr-defined]

    # --- phase B: no Referer, no hint → hazard_unresolved + dispatch review. ---
    eng_b = ENG_HZ + "-b"
    cfg_b = config.model_copy(update={"engagement": config.engagement.model_copy(update={"id": eng_b})})
    secrets_b = EnvSecretStore.from_config(cfg_b, env=env)
    attacker_b = auth_context_id(EngagementId(eng_b), compute_auth_hash("bearer", ATTACKER_TOKEN))
    victim_b = auth_context_id(EngagementId(eng_b), compute_auth_hash("bearer", VICTIM_TOKEN))
    lease_b = RedisLease(rclient, EngagementId(eng_b))
    lease_b.set_active(ttl_seconds=60)
    kh_b = _seed_csrf_graph(
        neo4j_client, eng=eng_b, attacker_ac_id=attacker_b,
        victim_ac_id=victim_b, with_referer=False,
    )
    ledger_b = InMemoryDispatchLedger()
    run_b = arm_run(
        config=cfg_b, selection=DispatchSelection(test_classes=("idor",), limit=1), actor="e2e"
    )
    deps_b = RunDependencies(
        neo4j=neo4j_client, lease=RedisLeaseReader(lease=lease_b),
        opa=StubOpaClient(allow=True), sender=_PathScriptedSender({}),  # type: ignore[arg-type]
        secrets=secrets_b, bodies=NoopBodyStore(), ledger=ledger_b,
        liveness=LivenessPolicy.from_config(cfg_b),
    )
    result_b = execute_run(run_b, deps_b)
    outcome_b = result_b.outcomes[0]
    assert outcome_b.outcome == "hazard_unresolved"
    assert outcome_b.hazard is not None
    assert outcome_b.hazard.kind == "csrf_token" and outcome_b.hazard.param == "_csrf"
    assert kh_b == outcome_b.key_hash

    # `doo dispatch review` would list it: the latest non-executed outcome.
    events = ledger_b.all_for_engagement(EngagementId(eng_b))
    refused = [e.outcome for e in events if e.kind == "outcome" and e.outcome is not None
               and e.outcome.outcome == "hazard_unresolved"]
    assert len(refused) == 1 and refused[0].hazard is not None


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

    # === S3: arm a SECOND run with a fake Interpreter (ADR-0045). ===
    # Scripted: read primary body → emit_verdict(vulnerable). Assert the verdict
    # lands on the TestCase (4th axis) and a `Finding@proposed` is committed with
    # `REFERENCES → TestCase` + `AFFECTS → Endpoint`.
    fake_interpreter = FakeMultiTurnCaller(
        script=[
            [("read_response_body", {"body_ref": "role:primary"})],
            [
                (
                    "emit_verdict",
                    {
                        "verdict": "vulnerable",
                        "justification": "primary 200 returned victim's order under attacker auth",
                        "observed_vs_expected": "200 with owner=victim; expected boundary to deny",
                        "evidence_refs": [],
                        "proposed_severity": "high",
                        "vuln_category": "idor",
                        "affected_refs": ["TARGET"],
                    },
                )
            ],
        ]
    )
    run3 = arm_run(
        config=engagement_config,
        selection=DispatchSelection(test_classes=("idor",), limit=1),
        actor="e2e-tester",
    )
    deps3 = RunDependencies(
        neo4j=neo4j_client,
        lease=RedisLeaseReader(lease=lease),
        opa=StubOpaClient(allow=True),
        sender=StubSender(
            response=HttpResponse(status=200, body=b'{"order_id":123,"owner":"victim"}')
        ),
        secrets=secrets,
        bodies=NoopBodyStore(),
        ledger=ledger,
        interpreter=fake_interpreter,
    )
    result3 = execute_run(run3, deps3)
    assert result3.outcomes[0].outcome == "executed"

    # 4th-axis verdict on the TestCase node.
    vrows = neo4j_client.execute_read(
        """
        MATCH (t:TestCase {engagement_id: $eid, key_hash: $kh})
        RETURN t.interpreter_verdict AS v, t.interpreter_run_id AS rid
        """,
        eid=ENG,
        kh=key_hash,
    )
    assert vrows[0]["v"] == "vulnerable"
    assert vrows[0]["rid"] == run3.run_id

    # `Finding@proposed` with `REFERENCES → TestCase` + `AFFECTS → Endpoint`.
    frows = neo4j_client.execute_read(
        """
        MATCH (f:Finding {engagement_id: $eid})-[:REFERENCES]->
              (t:TestCase {key_hash: $kh})
        OPTIONAL MATCH (f)-[:AFFECTS]->(a)
        RETURN f.finding_key AS fk, f.finding_status AS status,
               f.disclosure_status AS disc, f.category AS cat, f.source AS src,
               labels(a) AS affects_labels
        """,
        eid=ENG,
        kh=key_hash,
    )
    assert len(frows) == 1
    assert frows[0]["status"] == "proposed"
    assert frows[0]["disc"] == "unreported"
    assert frows[0]["cat"] == "idor"
    assert frows[0]["src"] == "llm-interpreter"
    assert "Endpoint" in (frows[0]["affects_labels"] or [])
    finding_key = frows[0]["fk"]

    # `doo finding review` flow: list → confirm → ledger row + denormalised status.
    proposed = list_proposed_findings(neo4j_client, EngagementId(ENG))
    assert len(proposed) == 1 and proposed[0].finding_key == finding_key
    fledger = InMemoryFindingLedger()
    ev = review_finding(
        neo4j_client,
        fledger,
        engagement_id=EngagementId(ENG),
        finding_key=finding_key,
        decision="confirm",
        actor="e2e-tester",
    )
    assert ev.prior_status == "proposed" and ev.new_status == "confirmed"
    assert len(fledger.events) == 1

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
