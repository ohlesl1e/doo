"""Neo4j schema bootstrap tests (ADR-0017).

The fake-session test exercises the statement list and applies idempotently
without needing docker. The testcontainer-backed test exercises the live
Neo4j path — skipped automatically if testcontainers / docker is unavailable.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from doo.ontology import (
    ENGAGEMENT_SCOPED_NODE_LABELS,
    apply_schema,
    schema_statements,
)


class _RecordingSession:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def run(self, cypher: str) -> object:
        self.calls.append(cypher)
        return None


def test_schema_statements_are_deterministic_and_idempotent_shape() -> None:
    a = schema_statements()
    b = schema_statements()
    assert a == b
    # Every statement uses IF NOT EXISTS.
    for stmt in a:
        assert "IF NOT EXISTS" in stmt.cypher, stmt


def test_every_scoped_label_has_uniqueness_constraint_and_engagement_id_index() -> None:
    stmts = schema_statements()
    cypher_blob = "\n".join(s.cypher for s in stmts)
    for label in ENGAGEMENT_SCOPED_NODE_LABELS:
        assert f"(n:{label})" in cypher_blob, f"no constraint references label {label}"
        # Engagement-id index.
        assert f"{label.lower()}_engagement_id_idx" in cypher_blob


def test_shared_labels_have_their_specific_uniqueness_constraints() -> None:
    cypher_blob = "\n".join(s.cypher for s in schema_statements())
    assert "engagement_id_unique" in cypher_blob
    assert "scope_content_hash_unique" in cypher_blob


def test_cross_cutting_property_existence_per_label() -> None:
    cypher_blob = "\n".join(s.cypher for s in schema_statements())
    required = ("source", "confidence", "first_seen", "last_seen", "ingested_at", "status")
    for label in ENGAGEMENT_SCOPED_NODE_LABELS:
        for field in required:
            assert f"{label.lower()}_{field}_exists" in cypher_blob


def test_apply_schema_issues_every_statement_in_order() -> None:
    session = _RecordingSession()
    applied = apply_schema(session)
    assert tuple(s.cypher for s in applied) == tuple(session.calls)


def test_apply_schema_twice_is_idempotent_in_call_shape() -> None:
    session = _RecordingSession()
    first = apply_schema(session)
    second = apply_schema(session)
    # Same statements both times; live Neo4j would no-op on the second pass
    # via IF NOT EXISTS. The recorded calls should match.
    assert first == second
    half = len(session.calls) // 2
    assert session.calls[:half] == session.calls[half:]


def test_slice4_hedge_labels_have_constraints() -> None:
    """The hedge applies to schema too — TestCase / Finding constraints must
    exist now so slice 4 doesn't migrate under live data."""
    cypher_blob = "\n".join(s.cypher for s in schema_statements())
    assert "testcase_identity_unique" in cypher_blob
    assert "finding_identity_unique" in cypher_blob


# --- Live Neo4j testcontainer path -----------------------------------------


@pytest.fixture
def neo4j_session(neo4j_container) -> Iterator[object]:
    from neo4j import GraphDatabase

    uri = neo4j_container.get_connection_url()
    driver = GraphDatabase.driver(
        uri, auth=(neo4j_container.username, neo4j_container.password)
    )
    try:
        with driver.session() as sess:
            yield sess
    finally:
        driver.close()


def test_apply_schema_against_live_neo4j_is_idempotent(neo4j_session) -> None:
    """Run apply_schema twice; second run must not raise and the constraint
    count must be unchanged."""

    # First run.
    apply_schema(neo4j_session)
    counts1 = _count_schema(neo4j_session)
    # Second run — idempotent.
    apply_schema(neo4j_session)
    counts2 = _count_schema(neo4j_session)
    assert counts1 == counts2
    assert counts1["constraints"] > 0
    assert counts1["indexes"] > 0


def _count_schema(session) -> dict[str, int]:
    constraints = list(session.run("SHOW CONSTRAINTS YIELD name RETURN name"))
    indexes = list(session.run("SHOW INDEXES YIELD name RETURN name"))
    return {"constraints": len(constraints), "indexes": len(indexes)}
