"""ADR-0049 credential-slot integration (#116): persisted property + backfill.

Covers, against a real Neo4j:
- the loader persists `slot` on a freshly-declared AuthContext node;
- `backfill_auth_context_slots` stamps `slot = token_kind` on slot-less
  declared ACs of every status (incl. `expired`), idempotently.

Skips cleanly when docker / testcontainers is unavailable.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.graph_state import Neo4jGraphState
from doo.ontology.schema import apply_schema
from doo.setup.config import EngagementConfig
from doo.setup.loader import load_engagement

ENG = "eng-slot-e2e"


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


def _config() -> EngagementConfig:
    return EngagementConfig.model_validate(
        {
            "engagement": {"id": ENG, "name": "slot e2e"},
            "environment": "staging",
            "scope": {
                "host_patterns": ["api.example.com"],
                "allowed_methods": ["GET"],
                "allowed_path_patterns": ["/**"],
            },
            "principals": [
                {
                    "label": "alice",
                    "auth_contexts": [
                        {"kind": "cookie", "token": "${SLOT_TOK}", "slot": "session"}
                    ],
                }
            ],
        }
    )


def test_loader_persists_slot_on_declared_ac(neo4j_client: Neo4jClient) -> None:
    state = Neo4jGraphState(neo4j_client)
    load_engagement(_config(), state, env={"SLOT_TOK": "sid=abc"})
    rows = neo4j_client.execute_read(
        """
        MATCH (ac:AuthContext {engagement_id: $eid, tier: 'declared'})
        RETURN ac.slot AS slot, ac.token_kind AS kind
        """,
        eid=ENG,
    )
    assert rows and rows[0]["slot"] == "session" and rows[0]["kind"] == "cookie"


def test_backfill_stamps_slotless_declared_acs_idempotently(
    neo4j_client: Neo4jClient,
) -> None:
    """Pre-ADR-0049 nodes (no `slot`) — including `status='expired'` ones — are
    stamped `slot = token_kind`; a second run is a no-op."""

    neo4j_client.execute_write(
        """
        CREATE (a:AuthContext {engagement_id: $eid, id: 'ac-old-active',
                               auth_hash: 'h1', tier: 'declared',
                               token_kind: 'cookie', status: 'active'})
        CREATE (b:AuthContext {engagement_id: $eid, id: 'ac-old-expired',
                               auth_hash: 'h2', tier: 'declared',
                               token_kind: 'bearer', status: 'expired'})
        CREATE (c:AuthContext {engagement_id: $eid, id: 'ac-discovered',
                               auth_hash: 'h3', tier: 'discovered',
                               token_kind: 'cookie', status: 'active'})
        """,
        eid=ENG,
    )
    state = Neo4jGraphState(neo4j_client)

    n = state.backfill_auth_context_slots(EngagementId(ENG))
    assert n == 2

    rows = neo4j_client.execute_read(
        "MATCH (ac:AuthContext {engagement_id: $eid}) "
        "RETURN ac.id AS id, ac.slot AS slot ORDER BY ac.id",
        eid=ENG,
    )
    by_id = {r["id"]: r["slot"] for r in rows}
    assert by_id["ac-old-active"] == "cookie"
    assert by_id["ac-old-expired"] == "bearer"
    # Discovered-tier untouched (no slot — no declaration).
    assert by_id["ac-discovered"] is None

    # Idempotent.
    assert state.backfill_auth_context_slots(EngagementId(ENG)) == 0
