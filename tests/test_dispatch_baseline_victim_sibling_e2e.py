"""ADR-0052 e2e: baseline_victim sibling-walk at evidence-load over Neo4j.

The shape the issue (#159) is about: an `auth-bypass` (idor) TestCase whose
evidence was observed under a **discovered-tier** HAR `AuthContext` (expired,
`slot=None`) that has *already* converged onto a **declared** Principal (ADR-0048;
the `OF_PRINCIPAL` edge L3 drew). That declared Principal owns a live declared
credential. `load_evidence` must walk the shared Principal and substitute the
declared sibling whose carrier matches the observed session's carrier, so
`baseline_victim` can actually arm instead of dead-ending un-armable (#160).

Two cases:
- WIN: discovered cookie session + declared cookie sibling → substitution to the
  declared id, plus the INFO `dispatch.evidence.baseline_victim_resolved_via_sibling`.
- DECLINE: discovered cookie session + declared *bearer* sibling only (no carrier
  match) → no substitution; the observed (discovered) id is left in place → the
  existing un-armable path (acceptance criterion 2).

Skips cleanly when docker / testcontainers is unavailable.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
import structlog

from doo.dispatch.executor.evidence import DispatchTestCase, load_evidence
from doo.events.execution import compute_testcase_key_hash
from doo.ids import AuthContextId, EngagementId, TestCaseKeyHash
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.schema import apply_schema

ENG = "eng-baseline-sibling-e2e"
HOST_ID = "host-shop"
HOSTNAME = "shop.example.com"
EP_ID = "ep-orders"

DISCOVERED_AC = "ac-discovered-har"
DECLARED_COOKIE_AC = "ac-declared-cookie"
DECLARED_BEARER_AC = "ac-declared-bearer"
PRINCIPAL_ID = "p-victim"
ATTACKER_AC = "ac-attacker"


@pytest.fixture
def neo4j_client(neo4j_container: Any) -> Iterator[Neo4jClient]:
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


def _seed(neo4j: Neo4jClient, *, declared_sibling_carrier: str) -> TestCaseKeyHash:
    """Seed the converged-identity shape and return the approved TestCase key_hash.

    A discovered-tier cookie `AuthContext` (slot=None) is OBSERVED_UNDER the
    victim observation and OF_PRINCIPAL the declared Principal. The Principal also
    owns a declared credential whose carrier is `declared_sibling_carrier`
    (`cookie` for the WIN case, `bearer` for the DECLINE case).
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
        MERGE (p:Principal {engagement_id: $eid, identity_key: $pid})
        ON CREATE SET p.id = $pid, p.label = 'victim-a', p.tier = 'declared',
                      p += $cross
        // Discovered HAR session (expired, no slot) — the observed victim AC.
        MERGE (disc:AuthContext {engagement_id: $eid, id: $disc_ac})
        ON CREATE SET disc.auth_hash = 'ah-disc', disc.tier = 'discovered',
                      disc.is_anonymous = false, disc.token_kind = 'cookie',
                      disc.slot = null, disc += $cross
        MERGE (disc)-[:OF_PRINCIPAL]->(p)
        // Declared live sibling on the SAME Principal.
        MERGE (decl:AuthContext {engagement_id: $eid, id: $decl_ac})
        ON CREATE SET decl.auth_hash = 'ah-decl', decl.tier = 'declared',
                      decl.is_anonymous = false, decl.token_kind = $decl_carrier,
                      decl.slot = $decl_carrier, decl += $cross
        MERGE (decl)-[:OF_PRINCIPAL]->(p)
        // Attacker declared AC (the TestCase's auth_context_id).
        MERGE (atk:AuthContext {engagement_id: $eid, id: $atk_ac})
        ON CREATE SET atk.auth_hash = 'ah-atk', atk.tier = 'declared',
                      atk.is_anonymous = false, atk.token_kind = 'bearer',
                      atk.slot = 'bearer', atk += $cross
        // Victim-side observation OBSERVED_UNDER the discovered session.
        MERGE (r:RequestObservation {engagement_id: $eid, observation_id: 'obs-disc-1'})
        ON CREATE SET r.id = 'obs-disc-1', r.method = 'GET',
                      r.concrete_path = '/orders/123', r.response_status = 200,
                      r.headers = ['Accept=application/json'], r.query = [],
                      r.cookies = ['session=stale'], r += $cross
        MERGE (r)-[:HIT]->(e)
        MERGE (r)-[:ON_HOST]->(h)
        MERGE (r)-[:OBSERVED_UNDER]->(disc)
        """,
        eid=ENG,
        hid=HOST_ID,
        hostname=HOSTNAME,
        epid=EP_ID,
        pid=PRINCIPAL_ID,
        disc_ac=DISCOVERED_AC,
        decl_ac=DECLARED_COOKIE_AC
        if declared_sibling_carrier == "cookie"
        else DECLARED_BEARER_AC,
        decl_carrier=declared_sibling_carrier,
        atk_ac=ATTACKER_AC,
        cross=cross,
    )

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
                      t.payload_hash = $ph, t.auth_context_id = $atk_ac,
                      t.attacker_principal = 'attacker', t.attacker_slot = 'bearer',
                      t.target_endpoint_id = $epid, t.status = 'active',
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
        atk_ac=ATTACKER_AC,
        cross=cross,
    )
    return TestCaseKeyHash(key_hash)


def _dispatch_testcase(key_hash: TestCaseKeyHash) -> DispatchTestCase:
    return DispatchTestCase(
        engagement_id=EngagementId(ENG),
        key_hash=key_hash,
        test_class="idor",
        payload_class="auth-token-swap",
        auth_context_id=AuthContextId(ATTACKER_AC),
        target_endpoint_id=EP_ID,
        target_parameter_id=None,
        target_trust_boundary_id=None,
        hold=("order_id",),
        replay_hazards=(),
        expected_yield=0.9,
        generator="c2",
        confidence=0.99,
        attacker_principal="attacker",
        attacker_slot="bearer",
    )


def test_baseline_victim_resolves_to_declared_sibling_e2e(
    neo4j_client: Neo4jClient,
) -> None:
    # WIN: discovered cookie session converged onto a declared Principal that
    # owns a live declared cookie credential → substitution + INFO event.
    key_hash = _seed(neo4j_client, declared_sibling_carrier="cookie")
    with structlog.testing.capture_logs() as caplog:
        evidence = load_evidence(
            neo4j_client,
            engagement_id=EngagementId(ENG),
            testcase=_dispatch_testcase(key_hash),
        )

    assert evidence is not None
    # The send AC is the DECLARED sibling, not the observed discovered session.
    assert evidence.baseline_victim_auth_context_id == AuthContextId(
        DECLARED_COOKIE_AC
    )
    # Observed provenance is still recoverable via the observation id.
    assert str(evidence.observation_id) == "obs-disc-1"

    resolved_events = [
        e
        for e in caplog
        if e.get("event") == "dispatch.evidence.baseline_victim_resolved_via_sibling"
    ]
    assert len(resolved_events) == 1
    event = resolved_events[0]
    assert event["observed_auth_context_id"] == DISCOVERED_AC
    assert event["resolved_auth_context_id"] == DECLARED_COOKIE_AC
    assert event["principal_id"] == PRINCIPAL_ID
    assert event["carrier"] == "cookie"


def test_baseline_victim_no_carrier_match_stays_unarmable_e2e(
    neo4j_client: Neo4jClient,
) -> None:
    # DECLINE: the declared sibling is a bearer credential — no carrier match for
    # a discovered cookie session. The observed (discovered) AC is left in place,
    # so material_for(...) will still miss → the existing un-armable path (#160).
    key_hash = _seed(neo4j_client, declared_sibling_carrier="bearer")
    with structlog.testing.capture_logs() as caplog:
        evidence = load_evidence(
            neo4j_client,
            engagement_id=EngagementId(ENG),
            testcase=_dispatch_testcase(key_hash),
        )

    assert evidence is not None
    # No substitution: the observed discovered AC is unchanged.
    assert evidence.baseline_victim_auth_context_id == AuthContextId(DISCOVERED_AC)
    # No resolve event fired.
    assert not [
        e
        for e in caplog
        if e.get("event") == "dispatch.evidence.baseline_victim_resolved_via_sibling"
    ]
