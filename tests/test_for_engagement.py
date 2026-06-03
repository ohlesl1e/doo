"""Tests for the `for_engagement` Cypher helper (ADR-0017) and its use with
`is_in_scope` (ADR-0020).

The pure tests assert the fragment shape and parameter binding. The
testcontainer test seeds two engagements and verifies engagement isolation, then
runs the example "in-scope Endpoints for engagement X" consumer query combining
`for_engagement` + `is_in_scope` over a mix of in-scope and out-of-scope
Endpoints (out-of-scope Endpoints are ingested per ADR-0020 but filtered here).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from doo.canonical.value_objects import Scheme
from doo.ids import EngagementId
from doo.ontology.queries import CypherFragment, for_engagement
from doo.policy.scope import is_in_scope
from doo.setup.config import ScopeRules

# --- Pure fragment tests -----------------------------------------------------


def test_for_engagement_fragment_shape() -> None:
    frag = for_engagement(EngagementId("eng-1"))
    assert isinstance(frag, CypherFragment)
    assert frag.where_clause == "WHERE n.engagement_id = $engagement_id"
    assert frag.parameters == {"engagement_id": "eng-1"}


def test_for_engagement_custom_var() -> None:
    frag = for_engagement(EngagementId("eng-1"), var="e")
    assert frag.where_clause == "WHERE e.engagement_id = $engagement_id"


def test_for_engagement_value_is_parameterised_not_interpolated() -> None:
    # The id value must never appear in the clause string (injection / plan-cache).
    frag = for_engagement(EngagementId("eng-injection-attempt'"))
    assert "eng-injection-attempt" not in frag.where_clause
    assert frag.parameters["engagement_id"] == "eng-injection-attempt'"


def test_and_helper_appends_predicate() -> None:
    frag = for_engagement(EngagementId("eng-1"))
    assert frag.and_("n.status = 'active'") == (
        "WHERE n.engagement_id = $engagement_id AND n.status = 'active'"
    )


# --- Example consumer query: in-scope Endpoints via for_engagement + is_in_scope


@dataclass(frozen=True)
class FakeHost:
    scheme: Scheme
    canonical_hostname: str
    port: int | None = None
    is_ip_literal: bool = False


@dataclass(frozen=True)
class FakeEndpoint:
    method: str
    host: FakeHost
    path_template: str


def in_scope_endpoints(
    endpoints: list[FakeEndpoint], scope: ScopeRules
) -> list[FakeEndpoint]:
    """The example consumer combinator: filter graph-returned Endpoints by scope.

    In a real query the `endpoints` list comes from a Cypher `MATCH` scoped with
    `for_engagement(...)`; `is_in_scope` then drops the out-of-scope ones (which
    are ingested per ADR-0020 but must not be surfaced to the planner).
    """

    return [ep for ep in endpoints if is_in_scope(ep, scope)]


def test_in_scope_endpoint_filter_drops_out_of_scope() -> None:
    scope = ScopeRules(
        host_patterns=("api.example.com",),
        allowed_methods=("GET",),
        allowed_path_patterns=("/users/*",),
    )
    endpoints = [
        FakeEndpoint("GET", FakeHost("https", "api.example.com"), "/users/{id}"),  # in
        FakeEndpoint("GET", FakeHost("https", "evil.test"), "/users/{id}"),  # out: host
        FakeEndpoint("POST", FakeHost("https", "api.example.com"), "/users/{id}"),  # out: method
        FakeEndpoint("GET", FakeHost("https", "api.example.com"), "/admin"),  # out: path
    ]
    result = in_scope_endpoints(endpoints, scope)
    assert len(result) == 1
    assert result[0].path_template == "/users/{id}"


# --- Live Neo4j isolation + example query -----------------------------------


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


def test_for_engagement_isolates_two_engagements(neo4j_session) -> None:
    """Seed two engagements' Endpoints; `for_engagement` returns only one's."""

    session = neo4j_session
    session.run("MATCH (n) DETACH DELETE n")
    # Seed Endpoints for two engagements (minimal property set for the test).
    session.run(
        "CREATE (:Endpoint {engagement_id: 'eng-A', method: 'GET', "
        "host_canonical: 'api.example.com', path_template: '/users/{id}'}) "
        "CREATE (:Endpoint {engagement_id: 'eng-A', method: 'GET', "
        "host_canonical: 'api.example.com', path_template: '/orders'}) "
        "CREATE (:Endpoint {engagement_id: 'eng-B', method: 'GET', "
        "host_canonical: 'api.example.com', path_template: '/secret'})"
    )

    frag = for_engagement(EngagementId("eng-A"))
    cypher = f"MATCH (n:Endpoint) {frag.where_clause} RETURN n.path_template AS p"
    rows = list(session.run(cypher, **frag.parameters))
    paths = sorted(r["p"] for r in rows)
    assert paths == ["/orders", "/users/{id}"]  # eng-B's /secret excluded


def test_example_in_scope_query_over_mixed_endpoints(neo4j_session) -> None:
    """End-to-end of the two helpers: scope-filter the engagement's Endpoints.

    ADR-0020: out-of-scope Endpoints ARE ingested (here: a different host) but
    the consumer query filters them via `is_in_scope`.
    """

    session = neo4j_session
    session.run("MATCH (n) DETACH DELETE n")
    session.run(
        "CREATE (:Endpoint {engagement_id: 'eng-X', method: 'GET', scheme: 'https', "
        "host_canonical: 'api.example.com', is_ip_literal: false, "
        "path_template: '/users/{id}'}) "  # in scope
        "CREATE (:Endpoint {engagement_id: 'eng-X', method: 'GET', scheme: 'https', "
        "host_canonical: 'tracker.evil.test', is_ip_literal: false, "
        "path_template: '/users/{id}'}) "  # out of scope: host (e.g. SSRF callback host)
        "CREATE (:Endpoint {engagement_id: 'eng-X', method: 'DELETE', scheme: 'https', "
        "host_canonical: 'api.example.com', is_ip_literal: false, "
        "path_template: '/users/{id}'})"  # out of scope: method
    )

    scope = ScopeRules(
        host_patterns=("api.example.com",),
        allowed_methods=("GET",),
        allowed_path_patterns=("/users/*",),
    )

    frag = for_engagement(EngagementId("eng-X"))
    cypher = (
        "MATCH (n:Endpoint) "
        f"{frag.where_clause} "
        "RETURN n.method AS method, n.scheme AS scheme, "
        "n.host_canonical AS host, n.is_ip_literal AS ip, "
        "n.path_template AS path"
    )
    rows = list(session.run(cypher, **frag.parameters))

    endpoints = [
        FakeEndpoint(
            r["method"],
            FakeHost(r["scheme"], r["host"], is_ip_literal=r["ip"]),
            r["path"],
        )
        for r in rows
    ]
    in_scope = in_scope_endpoints(endpoints, scope)
    assert len(in_scope) == 1
    assert in_scope[0].host.canonical_hostname == "api.example.com"
    assert in_scope[0].method == "GET"
