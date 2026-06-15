"""C5 / C5a / C5b TrustBoundary-coverage query tests (S7/#92, ADR-0047).

Seeds three `TrustBoundary`s in distinct coverage states and asserts the three
nested gap queries:

- tb1: an `approved` TestCase, executed `ok`, with an Interpreter verdict →
  covered at every stage (a gap in none).
- tb2: a `proposed`-only TestCase → covered for C5a (a TC exists), a gap for C5b
  (not approved) and C5 (no verdict).
- tb3: no TestCase at all → a gap in all three.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from doo.coverage.queries import run_c5, run_c5a, run_c5b
from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.schema import apply_schema

ENG = "eng-c5"


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


def _seed(neo4j: Neo4jClient) -> None:
    now = datetime.now(UTC)
    cross = {
        "source": "manual", "confidence": 1.0, "confidence_method": "manual",
        "first_seen": now, "last_seen": now, "ingested_at": now, "status": "active",
    }
    # Three capability boundaries between AuthContext pairs.
    neo4j.execute_write(
        """
        UNWIND ['tb1','tb2','tb3'] AS bid
        MERGE (a:AuthContext {engagement_id:$eid, id: bid+'-a'}) ON CREATE SET a += $cross
        MERGE (b:AuthContext {engagement_id:$eid, id: bid+'-b'}) ON CREATE SET b += $cross
        MERGE (tb:TrustBoundary {engagement_id:$eid, id: bid})
        ON CREATE SET tb.kind='scope', tb.between_a_id=bid+'-a',
                      tb.between_b_id=bid+'-b', tb += $cross
        MERGE (tb)-[:BETWEEN]->(a)
        MERGE (tb)-[:BETWEEN]->(b)
        """,
        eid=ENG, cross=cross,
    )
    # tb1: approved + executed-ok + verdict → covered everywhere.
    neo4j.execute_write(
        """
        MATCH (tb:TrustBoundary {engagement_id:$eid, id:'tb1'})
        MERGE (t:TestCase {engagement_id:$eid, key_hash:'kh-1'})
        ON CREATE SET t.test_class='boundary-violation', t.review_status='approved',
                      t.interpreter_verdict='not_vulnerable', t += $cross
        MERGE (t)-[:TARGETS_BOUNDARY]->(tb)
        MERGE (r:RequestObservation {engagement_id:$eid, observation_id:'o-1'})
        ON CREATE SET r += $cross
        MERGE (t)-[x:EXECUTED_AS {run_id:'run-1', request_role:'primary'}]->(r)
        ON CREATE SET x.dispatch_status='ok'
        """,
        eid=ENG, cross=cross,
    )
    # tb2: proposed-only (no verdict, not approved).
    neo4j.execute_write(
        """
        MATCH (tb:TrustBoundary {engagement_id:$eid, id:'tb2'})
        MERGE (t:TestCase {engagement_id:$eid, key_hash:'kh-2'})
        ON CREATE SET t.test_class='boundary-violation', t.review_status='proposed', t += $cross
        MERGE (t)-[:TARGETS_BOUNDARY]->(tb)
        """,
        eid=ENG, cross=cross,
    )
    # tb3: no TestCase at all.


def _ids(rows: list) -> set[str]:
    return {r.boundary_id for r in rows}


def test_c5_family(neo4j_client: Neo4jClient) -> None:
    _seed(neo4j_client)
    eid = EngagementId(ENG)

    # C5: not tested-to-verdict → tb2 (no verdict) + tb3 (no TC); tb1 covered.
    assert _ids(run_c5(neo4j_client, eid)) == {"tb2", "tb3"}
    # C5b: no approved TC → tb2 (proposed only) + tb3; tb1 approved.
    assert _ids(run_c5b(neo4j_client, eid)) == {"tb2", "tb3"}
    # C5a: no TC at all → only tb3.
    assert _ids(run_c5a(neo4j_client, eid)) == {"tb3"}

    # Rows carry the boundary descriptors + decayed confidence.
    row = next(r for r in run_c5a(neo4j_client, eid) if r.boundary_id == "tb3")
    assert row.kind == "scope"
    assert row.between_a_id == "tb3-a" and row.between_b_id == "tb3-b"
    assert row.query_id == "C5a"
    assert 0.0 < row.effective_confidence <= 1.0
