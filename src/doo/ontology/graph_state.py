"""Neo4j-backed `GraphState` for the engagement loader (slice-1 T2).

T1 shipped the loader logic against a `GraphState` Protocol and a fake; T2
provides the real Neo4j implementation, closing the `_build_graph_state` gap in
`cli.py`. It translates the loader's `PlannedMutation`s into MERGE statements for
the `Engagement` + `Scope` shared structural nodes (ADR-0017) and reads the
current engagement subgraph for diffing.

Also exposes `engagement_exists` for the L1 intake gate (a bad engagement_id is
rejected before any write).
"""

from __future__ import annotations

from doo.ids import EngagementId, ScopeContentHash
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
from doo.setup.loader import CurrentEngagementState, PlannedMutation

log = get_logger(__name__)


class Neo4jGraphState:
    """Neo4j implementation of the loader's `GraphState` Protocol."""

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    def engagement_exists(self, engagement_id: EngagementId) -> bool:
        """True if an `Engagement` node with this id exists (intake gate).

        `Engagement` is a shared structural node whose identity property is `id`
        (ADR-0017), not `engagement_id`, so this matches on `id` directly rather
        than via the `for_engagement` scoped-read helper.
        """

        rows = self._client.execute_read(
            "MATCH (e:Engagement {id: $engagement_id}) RETURN e.id AS id LIMIT 1",
            engagement_id=engagement_id,
        )
        return len(rows) > 0

    def fetch_engagement_state(
        self, engagement_id: EngagementId
    ) -> CurrentEngagementState | None:
        """Read the current Engagement + Scope subgraph for the loader's diff."""

        rows = self._client.execute_read(
            """
            MATCH (e:Engagement {id: $engagement_id})-[:UNDER_SCOPE]->(s:Scope)
            RETURN e.id AS id, e.name AS name, e.description AS description,
                   s.content_hash AS scope_content_hash,
                   e.kill_switch AS kill_switch
            LIMIT 1
            """,
            engagement_id=engagement_id,
        )
        if not rows:
            return None
        row = rows[0]
        kill_switch = row.get("kill_switch") or {}
        import json

        if isinstance(kill_switch, str):
            kill_switch = json.loads(kill_switch)
        return CurrentEngagementState(
            engagement_id=EngagementId(row["id"]),
            engagement_name=row["name"],
            engagement_description=row.get("description"),
            scope_content_hash=ScopeContentHash(row["scope_content_hash"]),
            kill_switch_ttl_seconds=int(kill_switch.get("lease_ttl_seconds", 60)),
            kill_switch_refresh_seconds=int(kill_switch.get("refresh_interval_seconds", 30)),
        )

    def apply_mutations(self, mutations: tuple[PlannedMutation, ...]) -> None:
        """Translate `PlannedMutation`s into MERGE statements."""

        for mutation in mutations:
            handler = _MUTATION_HANDLERS.get(mutation.kind)
            if handler is None:
                raise ValueError(f"unknown loader mutation kind {mutation.kind!r}")
            handler(self._client, mutation)


def _scope_create(client: Neo4jClient, m: PlannedMutation) -> None:
    import json

    props = dict(m.properties)
    props["rules"] = json.dumps(props.get("rules"), sort_keys=True)
    client.execute_write(
        """
        MERGE (s:Scope {content_hash: $content_hash})
        ON CREATE SET s += $props
        ON MATCH SET s.last_seen = $props.last_seen
        """,
        content_hash=props["content_hash"],
        props=props,
    )


def _engagement_create(client: Neo4jClient, m: PlannedMutation) -> None:
    import json

    props = dict(m.properties)
    props["kill_switch"] = json.dumps(props.get("kill_switch"), sort_keys=True)
    if props.get("time_window") is not None:
        props["time_window"] = json.dumps(props["time_window"], sort_keys=True)
    client.execute_write(
        """
        MERGE (e:Engagement {id: $id})
        ON CREATE SET e += $props
        ON MATCH SET e.last_seen = $props.last_seen
        """,
        id=props["id"],
        props=props,
    )


def _engagement_under_scope(client: Neo4jClient, m: PlannedMutation) -> None:
    client.execute_write(
        """
        MATCH (e:Engagement {id: $engagement_id})
        MATCH (s:Scope {content_hash: $scope_content_hash})
        MERGE (e)-[:UNDER_SCOPE]->(s)
        """,
        engagement_id=m.properties["engagement_id"],
        scope_content_hash=m.properties["scope_content_hash"],
    )


def _engagement_rebind_scope(client: Neo4jClient, m: PlannedMutation) -> None:
    client.execute_write(
        """
        MATCH (e:Engagement {id: $engagement_id})
        OPTIONAL MATCH (e)-[r:UNDER_SCOPE]->(:Scope)
        DELETE r
        WITH e
        MATCH (s:Scope {content_hash: $new_scope_content_hash})
        MERGE (e)-[:UNDER_SCOPE]->(s)
        """,
        engagement_id=m.properties["engagement_id"],
        new_scope_content_hash=m.properties["new_scope_content_hash"],
    )


def _engagement_update(client: Neo4jClient, m: PlannedMutation) -> None:
    import json

    props = dict(m.properties)
    if props.get("kill_switch") is not None:
        props["kill_switch"] = json.dumps(props["kill_switch"], sort_keys=True)
    client.execute_write(
        """
        MATCH (e:Engagement {id: $id})
        SET e.name = $props.name, e.description = $props.description,
            e.kill_switch = $props.kill_switch, e.last_seen = $props.last_seen
        """,
        id=props["id"],
        props=props,
    )


_MUTATION_HANDLERS = {
    "scope_create": _scope_create,
    "scope_create_or_attach": _scope_create,
    "engagement_create": _engagement_create,
    "engagement_under_scope": _engagement_under_scope,
    "engagement_rebind_scope": _engagement_rebind_scope,
    "engagement_update": _engagement_update,
}
