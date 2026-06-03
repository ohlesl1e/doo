"""Cross-engagement isolation — negative tests (T8, ADR-0017).

These prove the engagement-scoping invariant holds at the *database* layer, as a
backstop to the code-level checks elsewhere:

- The L3 commit-time scope gate (`EngagementScopeViolation`) is unit-tested in
  `test_commit_unit.py::test_scope_gate_refuses_mismatched_engagement`.
- Full-ingest two-engagement disjointness is exercised in
  `test_pipeline_e2e.py::test_cross_engagement_isolation`.
- Query-time scoping via `for_engagement` is in `test_for_engagement.py`.

Here we assert the Neo4j **uniqueness constraints** themselves: that a duplicate
identity *within* an engagement is rejected, that the *same* identity under a
*different* engagement is allowed (two disjoint nodes), that deleting one
engagement's subgraph leaves another untouched, and that scoped nodes never carry
a null `engagement_id` (no "floating" nodes outside an Engagement).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from doo.ontology.schema import apply_schema

# Endpoint identity per ADR-0017 / schema.py:
# (engagement_id, method, host_id, path_template) IS UNIQUE.
_CREATE_ENDPOINT = (
    "CREATE (e:Endpoint {engagement_id: $eng, method: $method, "
    "host_id: $host_id, path_template: $path}) RETURN e"
)


def _create_endpoint(session: object, **params: str) -> None:
    """Run the CREATE and `.consume()` it so a constraint violation surfaces
    synchronously (neo4j auto-commit results are otherwise lazy)."""
    session.run(_CREATE_ENDPOINT, **params).consume()  # type: ignore[attr-defined]


@pytest.fixture
def neo4j_session(neo4j_container) -> Iterator[object]:
    from neo4j import GraphDatabase

    uri = neo4j_container.get_connection_url()
    driver = GraphDatabase.driver(
        uri, auth=(neo4j_container.username, neo4j_container.password)
    )
    try:
        with driver.session() as sess:
            # Clean slate, then bootstrap the (Community-edition) schema so the
            # uniqueness constraints are live for these synthetic writes.
            sess.run("MATCH (n) DETACH DELETE n")
            apply_schema(sess, edition="community")
            yield sess
    finally:
        driver.close()


def test_duplicate_endpoint_identity_within_engagement_is_rejected(neo4j_session) -> None:
    """A second Endpoint with the same identity tuple in one engagement violates
    the uniqueness constraint (Neo4j Community supports uniqueness constraints)."""
    from neo4j.exceptions import ClientError

    params = {
        "eng": "eng-A",
        "method": "GET",
        "host_id": "host-1",
        "path": "/users/{id}",
    }
    _create_endpoint(neo4j_session, **params)

    with pytest.raises(ClientError) as exc:
        _create_endpoint(neo4j_session, **params)  # identical identity → reject
    assert "ConstraintValidationFailed" in (exc.value.code or "")


def test_same_identity_under_different_engagement_is_allowed(neo4j_session) -> None:
    """The same (method, host, template) under a *different* engagement is a
    distinct node — engagement_id is part of identity (ADR-0017)."""
    base = {"method": "GET", "host_id": "host-1", "path": "/users/{id}"}
    _create_endpoint(neo4j_session, eng="eng-A", **base)
    _create_endpoint(neo4j_session, eng="eng-B", **base)  # must NOT collide

    count = neo4j_session.run(
        "MATCH (e:Endpoint {method: $m, host_id: $h, path_template: $p}) RETURN count(e) AS c",
        m="GET",
        h="host-1",
        p="/users/{id}",
    ).single()["c"]
    assert count == 2  # two disjoint engagement-scoped nodes


def test_deleting_engagement_a_leaves_engagement_b_untouched(neo4j_session) -> None:
    _create_endpoint(neo4j_session, eng="eng-A", method="GET", host_id="h", path="/a")
    _create_endpoint(neo4j_session, eng="eng-B", method="GET", host_id="h", path="/b")

    neo4j_session.run("MATCH (e:Endpoint {engagement_id: 'eng-A'}) DETACH DELETE e").consume()

    remaining = neo4j_session.run(
        "MATCH (e:Endpoint) RETURN e.engagement_id AS eng"
    ).data()
    assert [r["eng"] for r in remaining] == ["eng-B"]


def test_no_scoped_node_carries_a_null_engagement_id(neo4j_session) -> None:
    """Every scoped node must be rooted in an Engagement via `engagement_id`
    (ADR-0017). A scoped node with a null engagement_id would be a leak risk."""
    _create_endpoint(neo4j_session, eng="eng-A", method="GET", host_id="h", path="/a")

    floating = neo4j_session.run(
        "MATCH (e:Endpoint) WHERE e.engagement_id IS NULL RETURN count(e) AS c"
    ).single()["c"]
    assert floating == 0
