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
                   e.kill_switch AS kill_switch,
                   e.session_cookie_names AS session_cookie_names
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
            session_cookie_names=tuple(row.get("session_cookie_names") or ()),
            declared_principals=self._fetch_declared_principals(engagement_id),
        )

    def get_session_cookie_names(self, engagement_id: EngagementId) -> tuple[str, ...]:
        """The engagement's `session_cookie_names` allowlist (ADR-0026 #28).

        Lightweight read for L1 intake (stamped onto the envelope). Empty tuple
        when unset or the engagement is absent.
        """

        rows = self._client.execute_read(
            "MATCH (e:Engagement {id: $engagement_id}) "
            "RETURN e.session_cookie_names AS names LIMIT 1",
            engagement_id=engagement_id,
        )
        if not rows:
            return ()
        return tuple(rows[0].get("names") or ())

    def _fetch_declared_principals(
        self, engagement_id: EngagementId
    ) -> dict[str, dict[str, object]]:
        """Read declared (active) Principals + their AuthContexts for diffing.

        Returns label-keyed `_principal_view`-shaped dicts so the loader's diff is
        a plain dict comparison. Secret-free: only `auth_hash`es and known signals.
        """

        import json

        rows = self._client.execute_read(
            """
            MATCH (p:Principal {engagement_id: $engagement_id, tier: 'declared'})
            WHERE p.status = 'active'
            OPTIONAL MATCH (ac:AuthContext {engagement_id: $engagement_id, tier: 'declared'})
                          -[:OF_PRINCIPAL]->(p)
            WHERE ac.status = 'active'
            RETURN p.label AS label, p.description AS description,
                   p.known_signals AS known_signals,
                   collect(
                     CASE WHEN ac IS NULL THEN NULL
                          ELSE {kind: ac.token_kind, auth_hash: ac.auth_hash,
                                validity_window: ac.validity_window}
                     END
                   ) AS auth_contexts
            """,
            engagement_id=engagement_id,
        )
        out: dict[str, dict[str, object]] = {}
        for row in rows:
            label = row["label"]
            if label is None:
                continue
            known_signals = row.get("known_signals") or {}
            if isinstance(known_signals, str):
                known_signals = json.loads(known_signals)
            auth_contexts = []
            for ac in row.get("auth_contexts") or []:
                if ac is None:
                    continue
                vw = ac.get("validity_window")
                if isinstance(vw, str):
                    vw = json.loads(vw)
                auth_contexts.append(
                    {
                        "kind": ac.get("kind"),
                        "auth_hash": ac.get("auth_hash"),
                        "validity_window": vw,
                    }
                )
            # Sort for stable comparison with the desired view (which lists in
            # declaration order; both sides are content-compared, so sort both by
            # auth_hash for determinism).
            auth_contexts.sort(key=lambda a: a.get("auth_hash") or "")
            out[label] = {
                "label": label,
                "description": row.get("description"),
                "auth_contexts": auth_contexts,
                "known_signals": {
                    "jwt_sub": known_signals.get("jwt_sub"),
                    "me_user_id": known_signals.get("me_user_id"),
                    "email": known_signals.get("email"),
                    "headers": dict(sorted((known_signals.get("headers") or {}).items())),
                },
            }
        return out

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
            e.kill_switch = $props.kill_switch,
            e.session_cookie_names = $props.session_cookie_names,
            e.last_seen = $props.last_seen
        """,
        id=props["id"],
        props=props,
    )


def _principal_declare(client: Neo4jClient, m: PlannedMutation) -> None:
    """Upsert a declared Principal (ADR-0010 tier='declared').

    Engagement-scoped on `(engagement_id, identity_key)`. `known_signals` is
    stored as a JSON string (Neo4j has no nested-map property type). On re-declare
    (token/known-signals change) the properties are overwritten.
    """

    import json

    props = dict(m.properties)
    props["known_signals"] = json.dumps(props.get("known_signals") or {}, sort_keys=True)
    client.execute_write(
        """
        MERGE (p:Principal {engagement_id: $engagement_id, identity_key: $identity_key})
        SET p.id = $props.id, p.tier = $props.tier, p.label = $props.label,
            p.description = $props.description, p.known_signals = $props.known_signals,
            p.is_anonymous = false,
            p.source = $props.source, p.source_id = $props.source_id,
            p.confidence = $props.confidence, p.confidence_method = $props.confidence_method,
            p.first_seen = coalesce(p.first_seen, $props.first_seen),
            p.last_seen = $props.last_seen, p.ingested_at = $props.ingested_at,
            p.status = 'active'
        """,
        engagement_id=props["engagement_id"],
        identity_key=props["identity_key"],
        props=props,
    )


def _auth_context_declare(client: Neo4jClient, m: PlannedMutation) -> None:
    """Upsert a declared AuthContext + its `OF_PRINCIPAL` edge (ADR-0010).

    Engagement-scoped on `(engagement_id, auth_hash)`. `validity_window` and
    `bearer_claims` are JSON-encoded. Carries only secret-free derived material.
    """

    import json

    props = dict(m.properties)
    vw = props.get("validity_window")
    props["validity_window"] = json.dumps(vw, sort_keys=True) if vw is not None else None
    props["bearer_claims"] = json.dumps(props.get("bearer_claims") or {}, sort_keys=True)
    client.execute_write(
        """
        MATCH (p:Principal {engagement_id: $engagement_id,
                            identity_key: $principal_identity_key})
        MERGE (ac:AuthContext {engagement_id: $engagement_id, auth_hash: $auth_hash})
        SET ac.id = $props.id, ac.token_kind = $props.token_kind, ac.tier = $props.tier,
            ac.is_anonymous = false, ac.validity_window = $props.validity_window,
            ac.bearer_claims = $props.bearer_claims,
            ac.source = $props.source, ac.source_id = $props.source_id,
            ac.confidence = $props.confidence, ac.confidence_method = $props.confidence_method,
            ac.first_seen = coalesce(ac.first_seen, $props.first_seen),
            ac.last_seen = $props.last_seen, ac.ingested_at = $props.ingested_at,
            ac.status = 'active'
        MERGE (ac)-[:OF_PRINCIPAL]->(p)
        """,
        engagement_id=props["engagement_id"],
        principal_identity_key=props["principal_identity_key"],
        auth_hash=props["auth_hash"],
        props=props,
    )


def _principal_retract(client: Neo4jClient, m: PlannedMutation) -> None:
    """Retract a declared Principal removed from the YAML (ADR-0001 status flag).

    The node and its declared AuthContexts are flagged `status='retracted'` rather
    than deleted, preserving the audit trail (no node deletion).
    """

    client.execute_write(
        """
        MATCH (p:Principal {engagement_id: $engagement_id, identity_key: $identity_key})
        SET p.status = 'retracted'
        WITH p
        OPTIONAL MATCH (ac:AuthContext {engagement_id: $engagement_id, tier: 'declared'})
                      -[:OF_PRINCIPAL]->(p)
        SET ac.status = 'retracted'
        """,
        engagement_id=m.properties["engagement_id"],
        identity_key=m.properties["identity_key"],
    )


_MUTATION_HANDLERS = {
    "scope_create": _scope_create,
    "scope_create_or_attach": _scope_create,
    "engagement_create": _engagement_create,
    "engagement_under_scope": _engagement_under_scope,
    "engagement_rebind_scope": _engagement_rebind_scope,
    "engagement_update": _engagement_update,
    "principal_declare": _principal_declare,
    "auth_context_declare": _auth_context_declare,
    "principal_retract": _principal_retract,
}
