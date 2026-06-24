"""Real-Neo4j regression for `infer_self_endpoint` (ADR-0044 fallback path).

The unit suite (`test_dispatch_liveness.py`) uses a duck-typed fake client that
never parses Cypher, so a double-`WHERE` in the query template
(`frag.and_(...)` already emits the `WHERE`, then a second literal `WHERE`
follows) shipped undetected and only surfaced at dispatch time as a
`CypherSyntaxError`. This test exercises the fallback against a real Neo4j
parser so that class of bug is caught at the correct seam.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from doo.dispatch.executor.liveness import LivenessEndpointSpec, infer_self_endpoint
from doo.ids import AuthContextId, EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.schema import apply_schema

ENG = EngagementId("eng-liveness-e2e")
AC = AuthContextId("ac-liveness-e2e")


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


def _seed_self_observation(neo4j: Neo4jClient) -> None:
    """One active 2xx `RequestObservation` on `/api/v1/me` under `AC`."""

    now = datetime.now(UTC)
    with neo4j.driver.session() as s:
        s.run(
            """
            CREATE (ac:AuthContext {id: $ac, engagement_id: $eng, status: 'active'})
            CREATE (r:RequestObservation {
                id: 'ro-1',
                engagement_id: $eng,
                status: 'active',
                method: 'GET',
                concrete_path: '/api/v1/me',
                response_status: 200,
                confidence: 0.95,
                last_seen: $now
            })
            CREATE (r)-[:OBSERVED_UNDER]->(ac)
            """,
            ac=str(AC),
            eng=str(ENG),
            now=now,
        )


def test_infer_self_endpoint_parses_and_returns_match(
    neo4j_client: Neo4jClient,
) -> None:
    """Fallback query parses under real Neo4j and returns the seeded `/me` hit.

    Regression for the double-`WHERE` CypherSyntaxError: `frag.and_(...)` emits
    the engagement-scope `WHERE`, so additional predicates must be AND-folded
    into its argument, not started as a second `WHERE`.
    """

    _seed_self_observation(neo4j_client)
    spec = infer_self_endpoint(
        neo4j_client, engagement_id=ENG, auth_context_id=AC
    )
    assert spec == LivenessEndpointSpec(method="GET", path="/api/v1/me")


def test_infer_self_endpoint_parses_when_no_rows(neo4j_client: Neo4jClient) -> None:
    """Empty graph: the query still has to *parse* (regression seam) and return None."""

    spec = infer_self_endpoint(
        neo4j_client, engagement_id=ENG, auth_context_id=AC
    )
    assert spec is None
