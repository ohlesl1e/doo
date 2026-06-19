"""ADR-0049 / #120: `doo engagement migrate-testcase-keys`.

Covers, against a real Neo4j:
- a rotation-churn collision (two pre-0049 TestCases differing only by
  `auth_context_id`) collapses to one new key — survivor re-keyed, loser
  retracted with a `MERGED_INTO` edge;
- the anonymous AuthContext maps to the `("anonymous","anonymous")` sentinel;
- a dangling `auth_context_id` is reported as `unresolved` and left untouched;
- a second `plan_migration` finds 0 rows (idempotent).

Plus a fast unit test for `pick_survivor` (no Neo4j).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from doo.canonical.identity import auth_context_id, compute_anonymous_auth_hash
from doo.engagement.cli_migrate import (
    MigrationPlan,
    _OldRow,
    apply_migration,
    pick_survivor,
    plan_migration,
)
from doo.events.execution import compute_testcase_key_hash
from doo.ids import EngagementId, Sha256Hex
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.schema import apply_schema

ENG = "eng-migrate"
PAYLOAD_HASH = hashlib.sha256(b"").hexdigest()


@pytest.fixture
def neo4j_client(neo4j_container) -> Iterator[Neo4jClient]:  # type: ignore[no-untyped-def]
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


def _seed_principal_with_acs(neo4j: Neo4jClient) -> None:
    """Principal `alice` + two declared AuthContexts (`ac-gen1`, `ac-gen2`),
    same `slot='cookie'`, both `OF_PRINCIPAL → alice`."""

    neo4j.execute_write(
        """
        CREATE (p:Principal {engagement_id: $eid, identity_key: 'alice',
                             label: 'alice', tier: 'declared',
                             status: 'active', source: 'test',
                             confidence: 1.0, confidence_method: 'declared',
                             first_seen: datetime(), last_seen: datetime(),
                             ingested_at: datetime()})
        CREATE (a1:AuthContext {engagement_id: $eid, id: 'ac-gen1',
                                auth_hash: 'h1', tier: 'declared',
                                token_kind: 'cookie', slot: 'cookie',
                                status: 'active', source: 'test',
                                confidence: 1.0, confidence_method: 'declared',
                                first_seen: datetime(), last_seen: datetime(),
                                ingested_at: datetime()})
        CREATE (a2:AuthContext {engagement_id: $eid, id: 'ac-gen2',
                                auth_hash: 'h2', tier: 'declared',
                                token_kind: 'cookie', slot: 'cookie',
                                status: 'expired', source: 'test',
                                confidence: 1.0, confidence_method: 'declared',
                                first_seen: datetime(), last_seen: datetime(),
                                ingested_at: datetime()})
        CREATE (a1)-[:OF_PRINCIPAL]->(p)
        CREATE (a2)-[:OF_PRINCIPAL]->(p)
        """,
        eid=ENG,
    )


def _seed_old_testcase(
    neo4j: Neo4jClient,
    *,
    key_hash: str,
    ac_id: str,
    last_seen: datetime,
    target_endpoint_id: str = "ep-1",
) -> None:
    """A pre-ADR-0049 TestCase node: `attacker_principal IS NULL`, status active."""

    neo4j.execute_write(
        """
        CREATE (tc:TestCase {
            engagement_id: $eid, key_hash: $kh, status: 'active',
            test_class: 'idor', target_endpoint_id: $tep,
            target_parameter_id: null, target_trust_boundary_id: null,
            payload_class: 'benign-probe', payload_hash: $ph,
            auth_context_id: $ac, review_status: 'proposed',
            source: 'test', confidence: 1.0, confidence_method: 'planner',
            first_seen: $ls, last_seen: $ls, ingested_at: $ls
        })
        """,
        eid=ENG,
        kh=key_hash,
        tep=target_endpoint_id,
        ph=PAYLOAD_HASH,
        ac=ac_id,
        ls=last_seen,
    )


# ---------------------------------------------------------------------------
# Integration tests (testcontainer Neo4j).
# ---------------------------------------------------------------------------


def test_collision_retracts_loser_keeps_survivor(neo4j_client: Neo4jClient) -> None:
    _seed_principal_with_acs(neo4j_client)
    t_old = datetime(2025, 1, 1, tzinfo=UTC)
    t_new = datetime(2025, 6, 1, tzinfo=UTC)
    _seed_old_testcase(neo4j_client, key_hash="old-gen1", ac_id="ac-gen1", last_seen=t_new)
    _seed_old_testcase(neo4j_client, key_hash="old-gen2", ac_id="ac-gen2", last_seen=t_old)

    plan = plan_migration(neo4j_client, EngagementId(ENG))
    assert len(plan.migrated) == 1
    assert len(plan.retracted) == 1
    assert plan.unresolved == []

    expected_new = compute_testcase_key_hash(
        engagement_id=EngagementId(ENG),
        test_class="idor",
        target_endpoint_id="ep-1",
        target_parameter_id=None,
        target_trust_boundary_id=None,
        payload_class="benign-probe",
        payload_hash=Sha256Hex(PAYLOAD_HASH),
        attacker_principal="alice",
        attacker_slot="cookie",
    )
    assert plan.migrated[0] == ("old-gen1", str(expected_new), "alice", "cookie")
    assert plan.retracted[0] == ("old-gen2", str(expected_new))

    apply_migration(neo4j_client, EngagementId(ENG), plan)

    rows = neo4j_client.execute_read(
        """
        MATCH (tc:TestCase {engagement_id: $eid})
        OPTIONAL MATCH (tc)-[:MERGED_INTO]->(w:TestCase)
        RETURN tc.key_hash AS kh, tc.status AS status,
               tc.attacker_principal AS ap, tc.attacker_slot AS slot,
               tc.retracted_reason AS rr, w.key_hash AS merged_into
        ORDER BY tc.key_hash
        """,
        eid=ENG,
    )
    by_kh = {r["kh"]: r for r in rows}
    # Survivor re-keyed.
    assert str(expected_new) in by_kh
    surv = by_kh[str(expected_new)]
    assert surv["status"] == "active"
    assert surv["ap"] == "alice" and surv["slot"] == "cookie"
    assert surv["merged_into"] is None
    # Loser retracted + lineage edge.
    loser = by_kh["old-gen2"]
    assert loser["status"] == "retracted"
    assert loser["rr"] == "adr-0049-key-migration"
    assert loser["merged_into"] == str(expected_new)

    # Idempotent: a second plan finds nothing.
    plan2 = plan_migration(neo4j_client, EngagementId(ENG))
    assert plan2 == MigrationPlan(migrated=[], retracted=[], unresolved=[])


def test_anonymous_testcase_migrates_to_sentinel(neo4j_client: Neo4jClient) -> None:
    anon_id = str(auth_context_id(EngagementId(ENG), compute_anonymous_auth_hash()))
    _seed_old_testcase(
        neo4j_client,
        key_hash="old-anon",
        ac_id=anon_id,
        last_seen=datetime(2025, 1, 1, tzinfo=UTC),
    )

    plan = plan_migration(neo4j_client, EngagementId(ENG))
    assert len(plan.migrated) == 1 and plan.retracted == [] and plan.unresolved == []
    _, _, principal, slot = plan.migrated[0]
    assert (principal, slot) == ("anonymous", "anonymous")


def test_dangling_auth_context_id_reported_unresolved(
    neo4j_client: Neo4jClient,
) -> None:
    _seed_old_testcase(
        neo4j_client,
        key_hash="old-dangling",
        ac_id="ac-nonexistent",
        last_seen=datetime(2025, 1, 1, tzinfo=UTC),
    )

    plan = plan_migration(neo4j_client, EngagementId(ENG))
    assert plan.migrated == [] and plan.retracted == []
    assert plan.unresolved == [("old-dangling", "ac-nonexistent")]

    apply_migration(neo4j_client, EngagementId(ENG), plan)
    rows = neo4j_client.execute_read(
        "MATCH (tc:TestCase {engagement_id: $eid, key_hash: 'old-dangling'}) "
        "RETURN tc.status AS s, tc.attacker_principal AS ap",
        eid=ENG,
    )
    assert rows[0]["s"] == "active" and rows[0]["ap"] is None


# ---------------------------------------------------------------------------
# Unit test (no Neo4j): survivor selection.
# ---------------------------------------------------------------------------


def _row(key_hash: str, last_seen: datetime | None) -> _OldRow:
    return _OldRow(
        key_hash=key_hash,
        test_class="idor",
        target_endpoint_id="ep-1",
        target_parameter_id=None,
        target_trust_boundary_id=None,
        payload_class="benign-probe",
        payload_hash=PAYLOAD_HASH,
        auth_context_id="ac-x",
        last_seen=last_seen,
        label="alice",
        slot="cookie",
    )


def test_pick_survivor_prefers_latest_last_seen_then_lex() -> None:
    a = _row("a", datetime(2025, 1, 1, tzinfo=UTC))
    b = _row("b", datetime(2025, 6, 1, tzinfo=UTC))
    c = _row("c", None)
    assert pick_survivor([a, b, c], engagement_id=EngagementId(ENG), ledger=None) is b

    # Tie on last_seen → smallest key_hash.
    d = _row("d", datetime(2025, 6, 1, tzinfo=UTC))
    assert pick_survivor([d, b], engagement_id=EngagementId(ENG), ledger=None) is b
