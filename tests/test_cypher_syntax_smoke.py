"""Layer 1 — Cypher syntax smoke against a real Neo4j parser (issue #156).

Regression seam for the #157 bug class: Cypher templates built via f-string +
`CypherFragment.and_(...)` / `for_engagement(...)` that are only *parsed* at
dispatch runtime, because every unit suite drives the emitters against a
duck-typed fake that never parses the query string (the double-`WHERE` in
`infer_self_endpoint` shipped this way — `cc61f22`).

Each registered entrypoint (`tests/_cypher_registry.py`) is driven with a
`RecordingClient`, which captures every rendered Cypher string without touching a
database. We then run `EXPLAIN <query>` against the Neo4j testcontainer for each
captured string. `EXPLAIN` parses + plans the query *without executing* it, so
no seed data is needed — it is a pure syntax/semantics check that surfaces a
`CypherSyntaxError` exactly as a real dispatch would.

Gated behind the session-scoped `neo4j_container` fixture, which skips under
`DOO_SKIP_TESTCONTAINERS` / no-docker (see `tests/conftest.py`). The Layer-2
static guard (`tests/test_cypher_static_guard.py`) is the no-Neo4j net that runs
even when this is skipped.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from neo4j.exceptions import CypherSyntaxError

from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.schema import apply_schema
from tests._cypher_registry import REGISTRY, RecordingClient


@pytest.fixture
def neo4j_client(neo4j_container) -> Iterator[Neo4jClient]:  # type: ignore[no-untyped-def]
    client = Neo4jClient.connect(
        neo4j_container.get_connection_url(),
        neo4j_container.username,
        neo4j_container.password,
    )
    # Apply the schema so property/label references plan against the real
    # constraints + indexes, mirroring the dispatch-time environment.
    with client.driver.session() as session:
        apply_schema(session, edition=client.server_edition())
    try:
        yield client
    finally:
        client.close()


@pytest.mark.parametrize(
    "label,driver",
    REGISTRY,
    ids=[label for label, _ in REGISTRY],
)
def test_entrypoint_cypher_parses(
    label: str,
    driver,  # type: ignore[no-untyped-def]
    neo4j_client: Neo4jClient,
) -> None:
    """Every Cypher string the entrypoint emits must `EXPLAIN` cleanly.

    Reintroducing the #157 double-`WHERE` (or any other template syntax error)
    in a covered helper makes the corresponding `EXPLAIN` raise
    `CypherSyntaxError`, turning this red at the correct (real-parser) seam.
    """

    recording = RecordingClient()
    driver(recording)

    assert recording.calls, f"{label}: entrypoint emitted no Cypher to check"

    with neo4j_client.driver.session() as session:
        for cypher, params in recording.calls:
            try:
                session.run(f"EXPLAIN {cypher}", **params).consume()
            except CypherSyntaxError as exc:  # noqa: PERF203 - clarity over micro-perf
                pytest.fail(
                    f"{label}: CypherSyntaxError under EXPLAIN — "
                    f"{exc}\n--- query ---\n{cypher}"
                )
