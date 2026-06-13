"""Auth-helper integration e2e (S6/#91): reactive rotation over Redis + Neo4j.

Declares a Principal whose bearer AuthContext has a `command` refresh mechanism,
seeds the AuthContext (+ `OF_PRINCIPAL`) in the graph, emits the `auth_invalid`
event the S4 classifier would emit onto the real Redis stream, runs the helper's
reactive poll, and asserts: a NEW active AuthContext (`OF_PRINCIPAL` → the same
Principal), the OLD one `expired`, and the rotated material in the rotation file.

Skips cleanly when docker / testcontainers is unavailable.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import cast

import pytest
import redis

from doo.canonical.identity import auth_context_id, compute_auth_hash
from doo.dispatch.auth_helper import AuthHelper
from doo.dispatch.reactive import StreamReactiveEmitter
from doo.dispatch.secrets import EnvSecretStore, RotatableSecretStore
from doo.ids import DispatchRunId, EngagementId, TestCaseKeyHash
from doo.infra.neo4j_driver import Neo4jClient
from doo.infra.streams import RedisStreamLike, StreamClient
from doo.ontology.schema import apply_schema
from doo.setup.config import EngagementConfig

ENG = "eng-authhelper-e2e"
ATTACKER_TOKEN = "old-attacker-token"  # noqa: S105 - test fixture


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
            "engagement": {"id": ENG, "name": "auth-helper e2e"},
            "environment": "staging",
            "scope": {
                "host_patterns": ["shop.example.com"],
                "allowed_methods": ["GET"],
                "allowed_path_patterns": ["/**"],
            },
            "principals": [
                {
                    "label": "attacker-b",
                    "auth_contexts": [
                        {
                            "kind": "bearer",
                            "token": "${AH_ATTACKER}",
                            "refresh": {
                                "mechanism": "command",
                                "command": "printf %s NEW-ROTATED-TOKEN",
                                "max_refreshes_per_hour": 3,
                            },
                        }
                    ],
                }
            ],
        }
    )


def test_auth_helper_reactive_rotation_e2e(
    neo4j_client: Neo4jClient, redis_url: str, tmp_path
) -> None:
    config = _config()
    env = {"AH_ATTACKER": ATTACKER_TOKEN}
    old_ac = auth_context_id(EngagementId(ENG), compute_auth_hash("bearer", ATTACKER_TOKEN))

    # Seed a declared Principal + the old AuthContext + OF_PRINCIPAL.
    neo4j_client.execute_write(
        """
        MERGE (p:Principal {engagement_id: $eid, identity_key: 'attacker-b'})
        ON CREATE SET p.tier='declared', p.status='active'
        MERGE (ac:AuthContext {engagement_id: $eid, id: $old_id})
        ON CREATE SET ac.auth_hash=$old_hash, ac.tier='declared', ac.token_kind='bearer',
                      ac.is_anonymous=false, ac.status='active'
        MERGE (ac)-[:OF_PRINCIPAL]->(p)
        """,
        eid=ENG,
        old_id=str(old_ac),
        old_hash=compute_auth_hash("bearer", ATTACKER_TOKEN),
    )

    rclient = redis.Redis.from_url(redis_url)
    streams = StreamClient(cast(RedisStreamLike, rclient))
    rotation_path = tmp_path / "rotation.json"

    helper = AuthHelper.from_config(
        config, neo4j=neo4j_client, rotation_path=rotation_path, streams=streams, env=env
    )
    assert old_ac in helper.managed

    # The dispatcher would emit this when the liveness probe shows the token dead.
    StreamReactiveEmitter(streams).emit_auth_invalid(
        engagement_id=EngagementId(ENG),
        run_id=DispatchRunId("run-x"),
        auth_context_id=old_ac,
        principal_label="attacker-b",
        key_hash=TestCaseKeyHash("kh-x"),
    )

    rotations = helper.poll_reactive(block_ms=500)
    assert rotations == 1

    # --- graph: new active AuthContext under the same Principal; old expired. ---
    new_ac = auth_context_id(EngagementId(ENG), compute_auth_hash("bearer", "NEW-ROTATED-TOKEN"))
    rows = neo4j_client.execute_read(
        """
        MATCH (p:Principal {engagement_id: $eid, identity_key: 'attacker-b'})
        OPTIONAL MATCH (old:AuthContext {engagement_id: $eid, id: $old_id})
        OPTIONAL MATCH (new:AuthContext {engagement_id: $eid, id: $new_id})-[:OF_PRINCIPAL]->(p)
        RETURN old.status AS old_status, new.status AS new_status,
               new.source AS new_source
        """,
        eid=ENG,
        old_id=str(old_ac),
        new_id=str(new_ac),
    )
    assert rows[0]["old_status"] == "expired"
    assert rows[0]["new_status"] == "active"
    assert rows[0]["new_source"] == "auth-helper"

    # --- rotation file: the Executor's store now serves NEW material for both ids. ---
    data = json.loads(rotation_path.read_text())
    assert data[str(old_ac)]["raw"] == "NEW-ROTATED-TOKEN"
    assert data[str(new_ac)]["raw"] == "NEW-ROTATED-TOKEN"
    store = RotatableSecretStore(
        base=EnvSecretStore.from_config(config, env=env), rotation_path=rotation_path
    )
    mat = store.material_for(old_ac)
    assert mat is not None and mat.raw == "NEW-ROTATED-TOKEN"

    # --- rate limit: a 4th reactive within the hour is refused (max 3). ---
    for _ in range(3):
        helper.rotate(old_ac, reason="reactive")
    assert helper.rotate(old_ac, reason="reactive") is False
