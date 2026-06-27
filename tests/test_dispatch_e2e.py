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
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import redis

from doo.canonical.identity import (
    auth_context_id,
    compute_anonymous_auth_hash,
    compute_auth_hash,
)
from doo.dispatch.auth_alarm import (
    AUTH_STALL_THRESHOLD,
    StalledSlot,
    detect_stalled_auth_slots,
)
from doo.dispatch.candidates import list_redispatch_candidates
from doo.dispatch.executor.dispatcher import RedisLeaseReader, StubOpaClient
from doo.dispatch.executor.evidence import DispatchTestCase
from doo.dispatch.executor.send import HttpResponse, StubSender, TransportError
from doo.dispatch.finding import (
    InMemoryFindingLedger,
    list_proposed_findings,
    list_reasserted_findings,
    resolve_finding_key,
    review_finding,
)
from doo.dispatch.interpreter.loop import FakeMultiTurnCaller
from doo.dispatch.ledger import InMemoryDispatchLedger
from doo.dispatch.models import DispatchSelection, RunOutcome
from doo.dispatch.ontology import NoopBodyStore
from doo.dispatch.run import RunDependencies, arm_run, execute_run
from doo.dispatch.secrets import (
    EnvSecretStore,
    SlotResolvingSecretStore,
    write_rotation_entry,
)
from doo.dispatch.selection import count_already_completed, select_testcases
from doo.events.execution import compute_testcase_key_hash
from doo.ids import AuthContextId, DispatchRunId, EngagementId, TestCaseKeyHash
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


def _seed_second_idor_testcase(
    neo4j: Neo4jClient, *, attacker_ac_id: str, seed: bytes = b"second"
) -> str:
    """A second approved IDOR TestCase on the same endpoint (distinct key_hash).

    Used by the resume / interrupt / progress tests that need >1 TestCase in a run
    against the `_seed_graph` engagement. Returns the new TestCase `key_hash`.
    """
    cross = _cross(datetime.now(UTC))
    payload_hash = hashlib.sha256(seed).hexdigest()
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
                      t.review_status = 'approved', t.expected_yield = 0.8,
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


class _RaisingSender:
    """`Sender` that fails at the wire with a `TransportError` (e.g. conn refused)."""

    def __init__(self, message: str) -> None:
        self._message = message
        self.sent: list[object] = []

    def send(self, request: object) -> HttpResponse:
        self.sent.append(request)
        raise TransportError(self._message)


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


@pytest.mark.parametrize(
    "probe_status,expect_refused",
    [
        (403, True),  # rotated credential dead → refuse the primary + reactive
        (200, False),  # rotated credential live → proceed to the primary
    ],
)
def test_verify_on_first_use_e2e(
    neo4j_client: Neo4jClient,
    redis_url: str,
    tmp_path: Path,
    probe_status: int,
    expect_refused: bool,
) -> None:
    """ADR-0053 (#168): material resolved from the rotation overlay is probed
    BEFORE the primary. Dead probe → `auth_unverified` refusal (no primary send,
    no primary `EXECUTED_AS`) + one reactive event. Live probe → the primary
    proceeds, and the authz-4xx disambiguation reuses the cached verdict, so the
    `/me` probe is sent exactly once.
    """
    from doo.dispatch.executor.liveness import LivenessPolicy
    from doo.dispatch.reactive import FakeReactiveEmitter

    env = {"E2E_VICTIM": VICTIM_TOKEN, "E2E_ATTACKER": ATTACKER_TOKEN}
    config = _liveness_config(ENG_LIVE)
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

    # The attacker's bearer slot is served from the rotation overlay → the
    # resolved material is `from_rotation`, triggering verify-on-first-use.
    rot = tmp_path / "rotation.json"
    write_rotation_entry(
        rot,
        principal_label="attacker-b",
        slot="bearer",
        raw=ATTACKER_TOKEN,
        kind="bearer",
    )
    slot_map = {attacker_ac_id: ("attacker-b", "bearer")}
    secrets = SlotResolvingSecretStore(
        graph_map=slot_map,
        env=EnvSecretStore.from_config(config, env=env),
        anon_id=auth_context_id(
            EngagementId(ENG_LIVE), compute_anonymous_auth_hash()
        ),
        rotation_path=rot,
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
        liveness=LivenessPolicy.from_config(config, graph_map=slot_map),
        reactive=reactive,
    )
    result = execute_run(run, deps)

    paths = [r.path for r in sender.sent]  # type: ignore[attr-defined]
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

    if expect_refused:
        # Pre-flight probe (/me) only — the primary is NEVER sent.
        assert paths == ["/me"]
        assert result.requests_sent == 1
        assert result.outcomes[0].outcome == "auth_unverified"
        # The probe is recorded; there is NO `primary` EXECUTED_AS edge.
        assert by_role.get("liveness") == "ok"
        assert "primary" not in by_role
        # The dead rotated credential fires exactly one reactive refresh.
        assert len(reactive.events) == 1
        ev = reactive.events[0]
        assert ev["kind"] == "auth_invalid"
        assert ev["auth_context_id"] == attacker_ac_id
        assert ev["principal_label"] == "attacker-b"
    else:
        # Pre-flight probe FIRST, then the primary; the authz-4xx disambiguation
        # reuses the cached `live` verdict → exactly one `/me` probe.
        assert paths == ["/me", "/orders/123"]
        assert paths.count("/me") == 1
        assert result.requests_sent == 2
        assert result.outcomes[0].outcome == "executed"
        # 403 primary + live token + no hazards → boundary genuinely held → ok.
        assert by_role["primary"] == "ok"
        assert by_role.get("liveness") == "ok"
        assert len(reactive.events) == 0


def _seed_watermark_history(
    neo4j: Neo4jClient,
    *,
    eng: str,
    key_hash: str,
    generations: list[tuple[datetime, str]],
    fail_at: datetime,
) -> None:
    """Add a Principal `attacker` + AuthContext generations on slot `bearer`
    (`(first_seen, status)` each) and a prior `auth_invalid` `primary`
    `EXECUTED_AS{at: fail_at}` on the TestCase — the inputs the #170 watermark reads.
    """
    now = datetime.now(UTC)
    cross = _cross(now)
    neo4j.execute_write(
        """
        MERGE (p:Principal {engagement_id: $eid, label: 'attacker'})
        ON CREATE SET p.identity_key = 'attacker', p.tier = 'declared', p += $cross
        """,
        eid=eng,
        cross=cross,
    )
    for i, (first_seen, status) in enumerate(generations):
        gen_cross = {
            **cross,
            "first_seen": first_seen,
            "last_seen": first_seen,
            "ingested_at": first_seen,
            "status": status,
        }
        neo4j.execute_write(
            """
            MATCH (p:Principal {engagement_id: $eid, label: 'attacker'})
            MERGE (ac:AuthContext {engagement_id: $eid, id: $acid})
            ON CREATE SET ac.auth_hash = $acid, ac.tier = 'declared',
                          ac.token_kind = 'bearer', ac.slot = 'bearer',
                          ac.is_anonymous = false, ac += $gen_cross
            MERGE (ac)-[:OF_PRINCIPAL]->(p)
            """,
            eid=eng,
            acid=f"ac-gen-{i}",
            gen_cross=gen_cross,
        )
    ro_cross = {
        **cross,
        "first_seen": fail_at,
        "last_seen": fail_at,
        "ingested_at": fail_at,
        "id": "obs-prior-fail",
        "observation_id": "obs-prior-fail",
        "method": "GET",
        "concrete_path": "/orders/123",
        "response_status": 403,
    }
    edge_cross = {
        **cross,
        "first_seen": fail_at,
        "last_seen": fail_at,
        "ingested_at": fail_at,
        "engagement_id": eng,
        "source_id": "run-prior",
    }
    neo4j.execute_write(
        """
        MATCH (t:TestCase {engagement_id: $eid, key_hash: $kh})
        MERGE (r:RequestObservation {engagement_id: $eid, observation_id: 'obs-prior-fail'})
        ON CREATE SET r += $ro_cross
        MERGE (t)-[x:EXECUTED_AS {run_id: 'run-prior', request_role: 'primary'}]->(r)
        ON CREATE SET x.dispatch_status = 'auth_invalid', x.at = $fail_at, x += $edge_cross
        """,
        eid=eng,
        kh=key_hash,
        fail_at=fail_at,
        ro_cross=ro_cross,
        edge_cross=edge_cross,
    )


@pytest.mark.parametrize(
    "generations_spec,expect_waiting",
    [
        ("below", True),  # only an active gen OLDER than the failure → waiting
        ("above", False),  # a newer active gen exists (rotation cleared it) → proceed
    ],
)
def test_watermark_redispatch_guard_e2e(
    neo4j_client: Neo4jClient,
    redis_url: str,
    generations_spec: str,
    expect_waiting: bool,
) -> None:
    """ADR-0053 (#170): a TestCase that already failed `auth_invalid` is refused
    (`waiting_on_rotation`, no send) until its slot rotates past the failure. Below
    the watermark → refused; a newer `active` generation (ignoring `expired` ones)
    → the re-dispatch proceeds.
    """
    from doo.dispatch.executor.liveness import LivenessPolicy
    from doo.dispatch.reactive import FakeReactiveEmitter

    env = {"E2E_VICTIM": VICTIM_TOKEN, "E2E_ATTACKER": ATTACKER_TOKEN}
    config = _liveness_config(ENG_LIVE)
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

    fail_at = datetime(2026, 6, 24, 12, 0, 0, tzinfo=UTC)
    if generations_spec == "below":
        gens = [(fail_at - timedelta(hours=1), "active")]
    else:
        gens = [
            (fail_at - timedelta(hours=1), "expired"),
            (fail_at + timedelta(hours=1), "active"),
        ]
    _seed_watermark_history(
        neo4j_client, eng=ENG_LIVE, key_hash=key_hash, generations=gens, fail_at=fail_at
    )

    rclient = redis.Redis.from_url(redis_url)
    lease = RedisLease(rclient, EngagementId(ENG_LIVE))
    lease.set_active(ttl_seconds=60)

    sender = _PathScriptedSender(
        {"/orders/123": HttpResponse(status=200, body=b'{"ok":true}')}
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
        secrets=EnvSecretStore.from_config(config, env=env),
        bodies=NoopBodyStore(),
        ledger=InMemoryDispatchLedger(),
        liveness=LivenessPolicy.from_config(
            config, graph_map={attacker_ac_id: ("attacker-b", "bearer")}
        ),
        reactive=reactive,
    )
    result = execute_run(run, deps)

    new_edges = neo4j_client.execute_read(
        """
        MATCH (t:TestCase {engagement_id: $eid, key_hash: $kh})
              -[x:EXECUTED_AS {run_id: $rid}]->()
        RETURN x.request_role AS role, x.dispatch_status AS status
        """,
        eid=ENG_LIVE,
        kh=key_hash,
        rid=run.run_id,
    )

    if expect_waiting:
        # Below the watermark: refused upfront — nothing sent, no new edge.
        assert result.outcomes[0].outcome == "waiting_on_rotation"
        assert sender.sent == []
        assert new_edges == []
        assert reactive.events == []
    else:
        # Above the watermark: the re-dispatch proceeds through the normal gate.
        assert result.outcomes[0].outcome == "executed"
        paths = [r.path for r in sender.sent]  # type: ignore[attr-defined]
        assert paths == ["/orders/123"]
        by_role = {r["role"]: r["status"] for r in new_edges}
        assert by_role["primary"] == "ok"


def _seed_principal_gen(
    neo4j: Neo4jClient, *, eng: str, gens: list[tuple[str, datetime, str]]
) -> None:
    """Principal `attacker` + AuthContext generations `(gen_id, first_seen, status)` on slot `bearer`."""
    base = _cross(datetime.now(UTC))
    neo4j.execute_write(
        "MERGE (p:Principal {engagement_id:$eid, label:'attacker'}) "
        "ON CREATE SET p.identity_key='attacker', p.tier='declared', p += $cross",
        eid=eng,
        cross=base,
    )
    for gen_id, first_seen, status in gens:
        gc = {
            **base,
            "first_seen": first_seen,
            "last_seen": first_seen,
            "ingested_at": first_seen,
            "status": status,
        }
        neo4j.execute_write(
            """
            MATCH (p:Principal {engagement_id:$eid, label:'attacker'})
            MERGE (ac:AuthContext {engagement_id:$eid, id:$gid})
            ON CREATE SET ac.auth_hash=$gid, ac.tier='declared', ac.token_kind='bearer',
                          ac.slot='bearer', ac.is_anonymous=false, ac += $gc
            MERGE (ac)-[:OF_PRINCIPAL]->(p)
            """,
            eid=eng,
            gid=gen_id,
            gc=gc,
        )


def _seed_tc(
    neo4j: Neo4jClient, *, eng: str, key_hash: str, test_class: str
) -> None:
    """Minimal approved TestCase node (attacker `attacker`:`bearer`) for candidate reads."""
    cross = _cross(datetime.now(UTC))
    neo4j.execute_write(
        """
        MERGE (t:TestCase {engagement_id:$eid, key_hash:$kh})
        ON CREATE SET t.test_class=$tc, t.payload_class='auth-token-swap',
                      t.auth_context_id='ac-x', t.attacker_principal='attacker',
                      t.attacker_slot='bearer', t.review_status='approved',
                      t.expected_yield=0.9, t.generator='c2',
                      t.target_endpoint_id=null, t.target_parameter_id=null,
                      t.target_trust_boundary_id=null, t.hold=[], t.replay_hazards=[],
                      t.hazard_source_hints=[], t.confidence=0.99, t += $cross
        """,
        eid=eng,
        kh=key_hash,
        tc=test_class,
        cross=cross,
    )


def _exec_edge(
    neo4j: Neo4jClient,
    *,
    eng: str,
    key_hash: str,
    role: str,
    status: str,
    at: datetime,
    obs_id: str,
) -> None:
    """One `EXECUTED_AS{role, dispatch_status, at}` edge + its RequestObservation."""
    base = _cross(datetime.now(UTC))
    ro = {
        **base,
        "first_seen": at,
        "last_seen": at,
        "ingested_at": at,
        "id": obs_id,
        "observation_id": obs_id,
        "method": "GET",
        "concrete_path": "/x",
        "response_status": 200,
    }
    edge = {
        **base,
        "first_seen": at,
        "last_seen": at,
        "ingested_at": at,
        "engagement_id": eng,
        "source_id": obs_id,
    }
    neo4j.execute_write(
        """
        MATCH (t:TestCase {engagement_id:$eid, key_hash:$kh})
        MERGE (r:RequestObservation {engagement_id:$eid, observation_id:$obs})
        ON CREATE SET r += $ro
        MERGE (t)-[x:EXECUTED_AS {run_id:$obs, request_role:$role}]->(r)
        ON CREATE SET x.dispatch_status=$status, x.at=$at, x += $edge
        """,
        eid=eng,
        kh=key_hash,
        obs=obs_id,
        role=role,
        status=status,
        at=at,
        ro=ro,
        edge=edge,
    )


def test_list_redispatch_candidates_e2e(neo4j_client: Neo4jClient) -> None:
    """ADR-0053 (#171): both failure shapes surface as candidates, classified by
    the rotation watermark; a clean (`ok`) TestCase is excluded.

    One `active` generation at T; candidates whose last failure predates T are
    eligible, those after T wait. `auth_invalid` = primary edge; `auth_unverified`
    = liveness edge with no primary edge.
    """
    eng = "eng-redispatch-cands"
    t_gen = datetime(2026, 6, 24, 12, 0, 0, tzinfo=UTC)
    _seed_principal_gen(neo4j_client, eng=eng, gens=[("ac-active", t_gen, "active")])
    kh_a, kh_b, kh_c, kh_d = ("a" * 64, "b" * 64, "c" * 64, "d" * 64)
    for kh, tc in [(kh_a, "idor"), (kh_b, "bola"), (kh_c, "auth-bypass"), (kh_d, "idor")]:
        _seed_tc(neo4j_client, eng=eng, key_hash=kh, test_class=tc)
    # A: auth_invalid AFTER the active gen → waiting on rotation.
    _exec_edge(
        neo4j_client, eng=eng, key_hash=kh_a, role="primary",
        status="auth_invalid", at=t_gen + timedelta(hours=1), obs_id="o-a",
    )
    # B: auth_invalid BEFORE the active gen → eligible.
    _exec_edge(
        neo4j_client, eng=eng, key_hash=kh_b, role="primary",
        status="auth_invalid", at=t_gen - timedelta(hours=1), obs_id="o-b",
    )
    # C: liveness-only BEFORE the gen (auth_unverified, #168) → eligible.
    _exec_edge(
        neo4j_client, eng=eng, key_hash=kh_c, role="liveness",
        status="ok", at=t_gen - timedelta(hours=1), obs_id="o-c",
    )
    # D: clean ok primary → NOT a candidate.
    _exec_edge(
        neo4j_client, eng=eng, key_hash=kh_d, role="primary",
        status="ok", at=t_gen - timedelta(hours=2), obs_id="o-d",
    )

    cands = list_redispatch_candidates(
        neo4j_client, engagement_id=EngagementId(eng)
    )
    by_kh = {c.key_hash: c for c in cands}
    assert set(by_kh) == {kh_a, kh_b, kh_c}
    assert by_kh[kh_a].eligible is False and by_kh[kh_a].failure_kind == "auth_invalid"
    assert by_kh[kh_b].eligible is True and by_kh[kh_b].failure_kind == "auth_invalid"
    assert by_kh[kh_c].eligible is True and by_kh[kh_c].failure_kind == "auth_unverified"
    assert by_kh[kh_c].principal == "attacker" and by_kh[kh_c].slot == "bearer"

    # The rerun selector targets exactly the chosen key_hash(es).
    sel = select_testcases(
        neo4j_client,
        engagement_id=EngagementId(eng),
        selection=DispatchSelection(key_hashes=(TestCaseKeyHash(kh_b),)),
    )
    assert [t.key_hash for t in sel] == [kh_b]


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


def test_transport_error_reason_on_edge_e2e(
    neo4j_client: Neo4jClient, redis_url: str, engagement_config: EngagementConfig
) -> None:
    """#136: a `transport_error` send (bytes went out, the wire failed) commits an
    `EXECUTED_AS` edge whose `dispatch_reason` is the stringified transport exception.
    """
    env = {"E2E_VICTIM": VICTIM_TOKEN, "E2E_ATTACKER": ATTACKER_TOKEN}
    secrets = EnvSecretStore.from_config(engagement_config, env=env)
    attacker_ac_id = auth_context_id(
        EngagementId(ENG), compute_auth_hash("bearer", ATTACKER_TOKEN)
    )
    key_hash = _seed_graph(neo4j_client, attacker_ac_id=attacker_ac_id)

    lease = RedisLease(redis.Redis.from_url(redis_url), EngagementId(ENG))
    lease.set_active(ttl_seconds=60)

    sender = _RaisingSender("connection refused")
    run = arm_run(
        config=engagement_config,
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
    )
    execute_run(run, deps)

    # Bytes left the process (sent=True), so the edge is committed — with the cause.
    assert len(sender.sent) == 1
    rows = neo4j_client.execute_read(
        """
        MATCH (t:TestCase {engagement_id: $eid, key_hash: $kh})
              -[x:EXECUTED_AS {request_role: 'primary'}]->(:RequestObservation)
        RETURN x.dispatch_status AS status, x.dispatch_reason AS reason
        """,
        eid=ENG,
        kh=key_hash,
    )
    assert len(rows) == 1
    assert rows[0]["status"] == "transport_error"
    assert rows[0]["reason"] == "connection refused"


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
               x.dispatch_reason AS reason,
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
    # An `ok` send carries no `dispatch_reason` (#136).
    assert row["reason"] is None
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
    # Scripted: send baseline_victim → read primary body → emit_verdict(vulnerable).
    # The baseline send is required by the #124 deterministic guard: a
    # differential `vulnerable` with no `ok` baseline is downgraded to
    # `inconclusive`. Assert the verdict lands on the TestCase (4th axis) and a
    # `Finding@proposed` is committed with `REFERENCES → TestCase` + `AFFECTS →
    # Endpoint`.
    fake_interpreter = FakeMultiTurnCaller(
        script=[
            [("send_http_request_within_scope", {"role": "baseline_victim"})],
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
        # #180: run1 already left an `ok` primary on this TestCase, so a
        # re-dispatch must opt out of the resume-skip default to send again.
        selection=DispatchSelection(
            test_classes=("idor",), limit=1, skip_completed=False
        ),
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

    # `resolve_finding_key` reaches a non-`proposed` Finding (the CLI's
    # --confirm/--reject must work after a prior decision; the ledger holds
    # both events). 12-char prefix and full key both resolve; ambiguity raises.
    assert resolve_finding_key(neo4j_client, EngagementId(ENG), finding_key) == finding_key
    assert resolve_finding_key(neo4j_client, EngagementId(ENG), finding_key[:12]) == finding_key
    assert resolve_finding_key(neo4j_client, EngagementId(ENG), "ffffffffffff") is None
    # And `review_finding` itself transitions confirmed → rejected → confirmed
    # with each step ledger-recorded (a tester changing their mind).
    ev2 = review_finding(
        neo4j_client, fledger, engagement_id=EngagementId(ENG),
        finding_key=finding_key, decision="reject", actor="e2e-tester",
        reason="re-eval",
    )
    assert ev2.prior_status == "confirmed" and ev2.new_status == "rejected"

    # === #125: re-assert against a `rejected` Finding is surfaced. ===
    # No re-commit yet → not re-asserted.
    assert list_reasserted_findings(neo4j_client, EngagementId(ENG), fledger) == []
    # Re-arm with a fresh scripted Interpreter (same `vulnerable` script as run3).
    run4 = arm_run(
        config=engagement_config,
        # #180: re-assert path re-sends the already-completed TestCase.
        selection=DispatchSelection(
            test_classes=("idor",), limit=1, skip_completed=False
        ),
        actor="e2e-tester",
    )
    fake4 = FakeMultiTurnCaller(
        script=[
            [("send_http_request_within_scope", {"role": "baseline_victim"})],
            [
                (
                    "emit_verdict",
                    {
                        "verdict": "vulnerable",
                        "justification": "re-test: still victim data",
                        "observed_vs_expected": "200 with owner=victim",
                        "evidence_refs": [],
                        "proposed_severity": "high",
                        "vuln_category": "idor",
                        "affected_refs": ["TARGET"],
                    },
                )
            ],
        ]
    )
    deps4 = RunDependencies(
        neo4j=neo4j_client,
        lease=RedisLeaseReader(lease=lease),
        opa=StubOpaClient(allow=True),
        sender=StubSender(
            response=HttpResponse(status=200, body=b'{"order_id":123,"owner":"victim"}')
        ),
        secrets=secrets,
        bodies=NoopBodyStore(),
        ledger=ledger,
        interpreter=fake4,
    )
    result4 = execute_run(run4, deps4)
    # The re-commit landed on the `rejected` Finding → surfaced on the outcome.
    assert result4.outcomes[0].finding_reasserted == (finding_key, "rejected")
    # And `list_reasserted_findings` now returns it (last_seen > ev2.timestamp).
    ra = list_reasserted_findings(neo4j_client, EngagementId(ENG), fledger)
    assert len(ra) == 1
    assert ra[0].finding_key == finding_key and ra[0].finding_status == "rejected"

    ev3 = review_finding(
        neo4j_client, fledger, engagement_id=EngagementId(ENG),
        finding_key=finding_key, decision="confirm", actor="e2e-tester",
        reason="re-test confirms",
    )
    assert ev3.prior_status == "rejected" and ev3.new_status == "confirmed"
    assert len(fledger.events) == 3
    # #125: after the fresh decision, no longer re-asserted (decision ≥ last_seen).
    assert list_reasserted_findings(neo4j_client, EngagementId(ENG), fledger) == []

    # --- kill the lease → next send is `dispatcher_blocked('kill_switch')`. ---
    lease.release()
    run2 = arm_run(
        config=engagement_config,
        # #180: re-attempt the already-completed TestCase to exercise the
        # kill-switch gate; opt out of resume-skip so it is selected.
        selection=DispatchSelection(
            test_classes=("idor",), limit=1, skip_completed=False
        ),
        actor="e2e-tester",
    )
    result2 = execute_run(run2, deps)
    assert len(result2.outcomes) == 1
    assert result2.outcomes[0].outcome == "dispatcher_blocked"
    assert result2.outcomes[0].reason == "kill_switch"
    # No additional wire send.
    assert len(sender.sent) == 1


def test_resumable_dispatch_skip_completed_e2e(
    neo4j_client: Neo4jClient, redis_url: str, engagement_config: EngagementConfig
) -> None:
    """#180: a re-run skips TestCases that already have an `ok` primary; --force re-sends.

    Run once (commit an `ok` primary). Re-run with the default resume semantics →
    nothing drains, the finished TestCase is counted as skipped, no new wire send.
    Re-run with `skip_completed=False` → it re-sends. Also assert `--select
    key_hash=` scopes the selection to the named TestCase.
    """
    env = {"E2E_VICTIM": VICTIM_TOKEN, "E2E_ATTACKER": ATTACKER_TOKEN}
    secrets = EnvSecretStore.from_config(engagement_config, env=env)
    attacker_ac_id = auth_context_id(
        EngagementId(ENG), compute_auth_hash("bearer", ATTACKER_TOKEN)
    )
    key_hash_a = _seed_graph(neo4j_client, attacker_ac_id=attacker_ac_id)
    key_hash_b = _seed_second_idor_testcase(
        neo4j_client, attacker_ac_id=attacker_ac_id
    )

    rclient = redis.Redis.from_url(redis_url)
    lease = RedisLease(rclient, EngagementId(ENG))
    lease.set_active(ttl_seconds=60)

    def _deps() -> RunDependencies:
        return RunDependencies(
            neo4j=neo4j_client,
            lease=RedisLeaseReader(lease=lease),
            opa=StubOpaClient(allow=True),
            sender=StubSender(
                response=HttpResponse(
                    status=200, body=b'{"order_id":123,"owner":"victim"}'
                )
            ),
            secrets=secrets,
            bodies=NoopBodyStore(),
            ledger=InMemoryDispatchLedger(),
        )

    # --- Run 1: drain both → two `ok` primaries committed. ---
    run1 = arm_run(
        config=engagement_config,
        selection=DispatchSelection(test_classes=("idor",)),
        actor="e2e-tester",
    )
    result1 = execute_run(run1, _deps())
    assert {o.outcome for o in result1.outcomes} == {"executed"}
    assert len(result1.outcomes) == 2
    assert result1.skipped_completed == 0

    # --- Run 2: resume (default) → both already done, nothing drains. ---
    run2 = arm_run(
        config=engagement_config,
        selection=DispatchSelection(test_classes=("idor",)),
        actor="e2e-tester",
    )
    deps2 = _deps()
    result2 = execute_run(run2, deps2)
    assert result2.outcomes == ()
    assert result2.skipped_completed == 2
    assert deps2.sender.sent == []  # type: ignore[attr-defined]

    # --- count_already_completed agrees with the resume skip. ---
    assert (
        count_already_completed(
            neo4j_client,
            engagement_id=EngagementId(ENG),
            selection=DispatchSelection(test_classes=("idor",)),
        )
        == 2
    )

    # --- Run 3: --force (skip_completed=False) → both re-sent. ---
    run3 = arm_run(
        config=engagement_config,
        selection=DispatchSelection(test_classes=("idor",), skip_completed=False),
        actor="e2e-tester",
    )
    deps3 = _deps()
    result3 = execute_run(run3, deps3)
    assert len(result3.outcomes) == 2
    assert result3.skipped_completed == 0
    assert len(deps3.sender.sent) == 2  # type: ignore[attr-defined]

    # --- key_hash scoping: select only one TestCase by content address. ---
    scoped = select_testcases(
        neo4j_client,
        engagement_id=EngagementId(ENG),
        selection=DispatchSelection(
            key_hashes=(TestCaseKeyHash(key_hash_a),), skip_completed=False
        ),
    )
    assert [tc.key_hash for tc in scoped] == [key_hash_a]
    assert key_hash_b not in {tc.key_hash for tc in scoped}


def _resumable_deps(
    neo4j: Neo4jClient, lease: RedisLease, secrets: EnvSecretStore
) -> RunDependencies:
    """Minimal deps for the #181 drain tests: StubSender 200, in-memory ledger."""
    return RunDependencies(
        neo4j=neo4j,
        lease=RedisLeaseReader(lease=lease),
        opa=StubOpaClient(allow=True),
        sender=StubSender(
            response=HttpResponse(status=200, body=b'{"order_id":123,"owner":"victim"}')
        ),
        secrets=secrets,
        bodies=NoopBodyStore(),
        ledger=InMemoryDispatchLedger(),
    )


def test_dispatch_run_interrupt_preserves_partial_summary_e2e(
    neo4j_client: Neo4jClient,
    redis_url: str,
    engagement_config: EngagementConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#181: a raise mid-drain returns a partial RunResult (interrupted=True).

    Two TestCases; the second `_execute_one` raises `KeyboardInterrupt`. The run
    does not propagate — it stops, the first (drained) outcome is preserved, and
    `interrupted` is set so the CLI still renders the summary.
    """
    from doo.dispatch import run as run_module

    env = {"E2E_VICTIM": VICTIM_TOKEN, "E2E_ATTACKER": ATTACKER_TOKEN}
    secrets = EnvSecretStore.from_config(engagement_config, env=env)
    attacker_ac_id = auth_context_id(
        EngagementId(ENG), compute_auth_hash("bearer", ATTACKER_TOKEN)
    )
    _seed_graph(neo4j_client, attacker_ac_id=attacker_ac_id)
    _seed_second_idor_testcase(neo4j_client, attacker_ac_id=attacker_ac_id)
    lease = RedisLease(redis.Redis.from_url(redis_url), EngagementId(ENG))
    lease.set_active(ttl_seconds=60)

    real_execute_one = run_module._execute_one
    calls = {"n": 0}

    def _raise_on_second(*args: object, **kwargs: object) -> RunOutcome:
        calls["n"] += 1
        if calls["n"] >= 2:
            raise KeyboardInterrupt
        return real_execute_one(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(run_module, "_execute_one", _raise_on_second)

    run = arm_run(
        config=engagement_config,
        # force so both are selected regardless of the (wiped, but explicit) state.
        selection=DispatchSelection(test_classes=("idor",), skip_completed=False),
        actor="e2e-tester",
    )
    result = execute_run(run, _resumable_deps(neo4j_client, lease, secrets))

    assert result.interrupted is True
    assert len(result.outcomes) == 1
    assert result.outcomes[0].outcome == "executed"


def test_dispatch_run_progress_and_injected_skip_count_e2e(
    neo4j_client: Neo4jClient,
    redis_url: str,
    engagement_config: EngagementConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#181: `on_progress` fires per TestCase; injected `skipped_completed` flows through.

    With `_PROGRESS_EVERY` forced to 1, the callback sees `(sent, drained, selected)`
    after each TestCase. Separately, a caller that injects `testcases` (the CLI
    pre-run path) can pass the resume-skipped count it already computed.
    """
    from doo.dispatch import run as run_module

    env = {"E2E_VICTIM": VICTIM_TOKEN, "E2E_ATTACKER": ATTACKER_TOKEN}
    secrets = EnvSecretStore.from_config(engagement_config, env=env)
    attacker_ac_id = auth_context_id(
        EngagementId(ENG), compute_auth_hash("bearer", ATTACKER_TOKEN)
    )
    _seed_graph(neo4j_client, attacker_ac_id=attacker_ac_id)
    _seed_second_idor_testcase(neo4j_client, attacker_ac_id=attacker_ac_id)
    lease = RedisLease(redis.Redis.from_url(redis_url), EngagementId(ENG))
    lease.set_active(ttl_seconds=60)

    monkeypatch.setattr(run_module, "_PROGRESS_EVERY", 1)
    seen: list[tuple[int, int, int]] = []

    run = arm_run(
        config=engagement_config,
        selection=DispatchSelection(test_classes=("idor",), skip_completed=False),
        actor="e2e-tester",
    )
    result = execute_run(
        run,
        _resumable_deps(neo4j_client, lease, secrets),
        on_progress=lambda s, d, t: seen.append((s, d, t)),
    )
    assert len(result.outcomes) == 2
    assert result.interrupted is False
    # key_hash_a (yield 0.9) drains before key_hash_b (0.8); one send each.
    assert seen == [(1, 1, 2), (2, 2, 2)]

    # Injected `testcases` + `skipped_completed` (the CLI pre-run path): the count
    # flows onto the result; no graph-backed selection runs.
    run2 = arm_run(
        config=engagement_config,
        selection=DispatchSelection(test_classes=("idor",)),
        actor="e2e-tester",
    )
    result2 = execute_run(
        run2,
        _resumable_deps(neo4j_client, lease, secrets),
        testcases=[],
        skipped_completed=7,
    )
    assert result2.skipped_completed == 7
    assert result2.outcomes == ()


# --- #183: early warning — auth failures climbing, nothing rotating ----------

ENG_STALL = "eng-dispatch-stall-e2e"


def _seed_attacker_principal(
    neo4j: Neo4jClient, *, eng: str, label: str, slot: str, first_seen: datetime
) -> None:
    """Seed a Principal + one `active` `declared` AuthContext on `slot` (the
    rotation axis `_rotated_since` reads). `first_seen` controls whether it counts
    as a rotation after the run armed."""
    cross = _cross(first_seen)
    neo4j.execute_write(
        """
        MERGE (p:Principal {engagement_id: $eid, label: $label})
        ON CREATE SET p += $cross
        MERGE (ac:AuthContext {engagement_id: $eid, id: $ac_id})
        ON CREATE SET ac.tier = 'declared', ac.is_anonymous = false,
                      ac.token_kind = 'bearer', ac.slot = $slot,
                      ac.auth_hash = $ac_id, ac += $cross
        SET ac.first_seen = $first_seen, ac.status = 'active'
        MERGE (ac)-[:OF_PRINCIPAL]->(p)
        """,
        eid=eng,
        label=label,
        ac_id=f"ac-{label}-{slot}",
        slot=slot,
        first_seen=first_seen,
        cross=cross,
    )


def _stall_tc(key_hash: str, *, principal: str = "attacker-b", slot: str = "bearer") -> DispatchTestCase:
    return DispatchTestCase(
        engagement_id=EngagementId(ENG_STALL),
        key_hash=TestCaseKeyHash(key_hash),
        test_class="idor",
        payload_class="auth-token-swap",
        auth_context_id=AuthContextId("ac-attacker"),
        target_endpoint_id="ep-x",
        target_parameter_id=None,
        target_trust_boundary_id=None,
        hold=(),
        replay_hazards=(),
        attacker_principal=principal,
        attacker_slot=slot,
    )


def _auth_fail(key_hash: str, *, via_invalid_send: bool = False) -> RunOutcome:
    """An auth-failure outcome: an `auth_unverified` refusal, or (when
    `via_invalid_send`) an `auth_invalid` `primary` send on an `executed` outcome."""
    if via_invalid_send:
        return RunOutcome(
            engagement_id=EngagementId(ENG_STALL),
            run_id=DispatchRunId("run-stall"),
            key_hash=TestCaseKeyHash(key_hash),
            test_class="idor",
            outcome="executed",
            sends=(("primary", "auth_invalid", None),),
            at=datetime.now(UTC),
        )
    return RunOutcome(
        engagement_id=EngagementId(ENG_STALL),
        run_id=DispatchRunId("run-stall"),
        key_hash=TestCaseKeyHash(key_hash),
        test_class="idor",
        outcome="auth_unverified",
        at=datetime.now(UTC),
    )


def test_detect_stalled_auth_slots_fires_when_no_rotation_e2e(
    neo4j_client: Neo4jClient,
) -> None:
    """#183: ≥threshold auth failures on a slot with no rotation since armed → stalled."""
    armed_at = datetime.now(UTC)
    # Declared creds exist but are STALE (older than the run) — nothing rotated.
    _seed_attacker_principal(
        neo4j_client,
        eng=ENG_STALL,
        label="attacker-b",
        slot="bearer",
        first_seen=armed_at - timedelta(hours=1),
    )
    keys = [f"{i:064x}" for i in range(AUTH_STALL_THRESHOLD)]
    selected = [_stall_tc(k) for k in keys]
    # Mix the two failure shapes: auth_unverified + an auth_invalid primary send.
    outcomes = [_auth_fail(keys[0], via_invalid_send=True)] + [
        _auth_fail(k) for k in keys[1:]
    ]

    stalled = detect_stalled_auth_slots(
        neo4j_client,
        engagement_id=EngagementId(ENG_STALL),
        armed_at=armed_at,
        selected=selected,
        outcomes=outcomes,
    )
    assert stalled == (
        StalledSlot(
            principal_label="attacker-b",
            slot="bearer",
            auth_failures=AUTH_STALL_THRESHOLD,
        ),
    )


def test_detect_stalled_auth_slots_silent_when_rotated_e2e(
    neo4j_client: Neo4jClient,
) -> None:
    """#183: no alarm when a declared AuthContext rotated AFTER the run armed."""
    armed_at = datetime.now(UTC)
    # Helper is up: a fresh generation appeared after the run armed.
    _seed_attacker_principal(
        neo4j_client,
        eng=ENG_STALL,
        label="attacker-b",
        slot="bearer",
        first_seen=armed_at + timedelta(minutes=1),
    )
    keys = [f"{i:064x}" for i in range(AUTH_STALL_THRESHOLD)]
    selected = [_stall_tc(k) for k in keys]
    outcomes = [_auth_fail(k) for k in keys]

    stalled = detect_stalled_auth_slots(
        neo4j_client,
        engagement_id=EngagementId(ENG_STALL),
        armed_at=armed_at,
        selected=selected,
        outcomes=outcomes,
    )
    assert stalled == ()


def test_detect_stalled_auth_slots_silent_below_threshold_e2e(
    neo4j_client: Neo4jClient,
) -> None:
    """#183: below the threshold, no alarm (a couple of failures is just noise)."""
    armed_at = datetime.now(UTC)
    _seed_attacker_principal(
        neo4j_client,
        eng=ENG_STALL,
        label="attacker-b",
        slot="bearer",
        first_seen=armed_at - timedelta(hours=1),
    )
    keys = [f"{i:064x}" for i in range(AUTH_STALL_THRESHOLD - 1)]
    selected = [_stall_tc(k) for k in keys]
    outcomes = [_auth_fail(k) for k in keys]

    stalled = detect_stalled_auth_slots(
        neo4j_client,
        engagement_id=EngagementId(ENG_STALL),
        armed_at=armed_at,
        selected=selected,
        outcomes=outcomes,
    )
    assert stalled == ()
