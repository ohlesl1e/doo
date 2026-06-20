"""ADR-0050 send-as / per-principal AC resolution (#133) — against a real Neo4j.

The send-as identity is the **Principal** that reached the endpoint; the AC is
resolved from that Principal via `_fetch_principal_auth` (with an optional
`prefer_token_kind`). These tests exercise the Cypher that implements that —
ranking and `ORDER BY` clauses are not unit-stubable.

Skips cleanly when docker / testcontainers is unavailable.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.schema import apply_schema
from doo.planner.assemble import _fetch_principal_auth, _fetch_send_as_auth

ENG = EngagementId("eng-send-as-e2e")


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
        client.execute_write(
            "MATCH (n {engagement_id: $e}) DETACH DELETE n", e=str(ENG)
        )
        client.close()


def _seed_principal(
    client: Neo4jClient,
    *,
    pid: str,
    label: str,
    p_tier: str,
    is_anon: bool = False,
) -> None:
    client.execute_write(
        """
        CREATE (p:Principal {engagement_id: $e, id: $pid, label: $label,
                             identity_key: $label, tier: $tier,
                             is_anonymous: $anon, status: 'active'})
        """,
        e=str(ENG), pid=pid, label=label, tier=p_tier, anon=is_anon,
    )


def _seed_ac(
    client: Neo4jClient,
    *,
    acid: str,
    pid: str,
    tier: str,
    kind: str,
    slot: str | None = None,
    is_anon: bool = False,
) -> None:
    client.execute_write(
        """
        MATCH (p:Principal {engagement_id: $e, id: $pid})
        CREATE (ac:AuthContext {engagement_id: $e, id: $acid, auth_hash: $acid,
                                tier: $tier, token_kind: $kind, slot: $slot,
                                is_anonymous: $anon, status: 'active'})
        CREATE (ac)-[:OF_PRINCIPAL]->(p)
        """,
        e=str(ENG), acid=acid, pid=pid, tier=tier, kind=kind, slot=slot, anon=is_anon,
    )


def _seed_hit(client: Neo4jClient, *, ep: str, acid: str, rid: str) -> None:
    client.execute_write(
        """
        MERGE (e:Endpoint {engagement_id: $e, id: $ep})
          ON CREATE SET e.status = 'active'
        WITH e
        MATCH (ac:AuthContext {engagement_id: $e, id: $acid})
        CREATE (r:RequestObservation {engagement_id: $e, id: $rid,
                                      status: 'active'})
        CREATE (r)-[:HIT]->(e)
        CREATE (r)-[:OBSERVED_UNDER]->(ac)
        """,
        e=str(ENG), ep=ep, acid=acid, rid=rid,
    )


# ---------------------------------------------------------------------------
# `_fetch_send_as_auth` — Principal-first ranking + declared-AC substitution.
# ---------------------------------------------------------------------------


def test_send_as_substitutes_declared_ac_for_discovered_hit(
    neo4j_client: Neo4jClient,
) -> None:
    """Core ADR-0050 case: endpoint hit ONLY under a discovered cookie of a
    declared Principal → send-as resolves to that Principal's *declared* AC.
    """
    _seed_principal(neo4j_client, pid="p-admin", label="admin", p_tier="declared")
    _seed_ac(neo4j_client, acid="ac-decl", pid="p-admin", tier="declared",
             kind="cookie", slot="cookie")
    _seed_ac(neo4j_client, acid="ac-disc", pid="p-admin", tier="discovered",
             kind="cookie")
    _seed_hit(neo4j_client, ep="ep-1", acid="ac-disc", rid="r-1")

    out = _fetch_send_as_auth(neo4j_client, ENG, "ep-1")
    assert out is not None
    view, label = out
    assert label == "admin"
    # The *declared* AC (the armable resolution handle), NOT the observed one.
    assert str(view.auth_context_id) == "ac-decl"
    assert view.tier == "declared"
    assert view.slot == "cookie"


def test_send_as_ranks_declared_principal_over_discovered_principal(
    neo4j_client: Neo4jClient,
) -> None:
    """Endpoint hit by {discovered AC of declared P, discovered AC of discovered
    P} → the declared Principal wins (ADR-0050 Q5: Principal-first, not AC-first
    + substitute), regardless of `ac.id` ordering.
    """
    _seed_principal(neo4j_client, pid="p-admin", label="admin", p_tier="declared")
    _seed_ac(neo4j_client, acid="ac-decl", pid="p-admin", tier="declared",
             kind="cookie", slot="cookie")
    # admin's discovered cookie sorts AFTER stranger's by ac.id ('zz…' > 'aa…').
    _seed_ac(neo4j_client, acid="zz-admin-disc", pid="p-admin", tier="discovered",
             kind="cookie")
    _seed_principal(neo4j_client, pid="p-stranger", label="stranger",
                    p_tier="discovered")
    _seed_ac(neo4j_client, acid="aa-stranger-disc", pid="p-stranger",
             tier="discovered", kind="cookie")
    _seed_hit(neo4j_client, ep="ep-2", acid="zz-admin-disc", rid="r-2a")
    _seed_hit(neo4j_client, ep="ep-2", acid="aa-stranger-disc", rid="r-2b")

    out = _fetch_send_as_auth(neo4j_client, ENG, "ep-2")
    assert out is not None
    view, label = out
    assert label == "admin"
    assert str(view.auth_context_id) == "ac-decl"
    assert view.slot == "cookie"


def test_send_as_discovered_principal_only_yields_slotless_view(
    neo4j_client: Neo4jClient,
) -> None:
    """Endpoint hit only by a discovered AC of a *discovered* Principal → no
    substitution possible; `slot is None` so the resolver will reject (#129
    invariant unchanged).
    """
    _seed_principal(neo4j_client, pid="p-stranger", label="stranger",
                    p_tier="discovered")
    _seed_ac(neo4j_client, acid="ac-stranger", pid="p-stranger",
             tier="discovered", kind="cookie")
    _seed_hit(neo4j_client, ep="ep-3", acid="ac-stranger", rid="r-3")

    out = _fetch_send_as_auth(neo4j_client, ENG, "ep-3")
    assert out is not None
    view, _ = out
    assert view.tier == "discovered"
    assert view.slot is None


def test_send_as_anonymous_only_regression(neo4j_client: Neo4jClient) -> None:
    """#129 regression: endpoint hit only by the anonymous AC → `slot='anonymous'`
    (armable via the no-auth sentinel). The anonymous *Principal* has
    `tier='discovered'` per `resolve.py`, so this exercises the rank's
    `p.is_anonymous` arm.
    """
    _seed_principal(neo4j_client, pid="p-anon", label="anon",
                    p_tier="discovered", is_anon=True)
    _seed_ac(neo4j_client, acid="ac-anon", pid="p-anon", tier="anonymous",
             kind="anonymous", is_anon=True)
    _seed_hit(neo4j_client, ep="ep-4", acid="ac-anon", rid="r-4")

    out = _fetch_send_as_auth(neo4j_client, ENG, "ep-4")
    assert out is not None
    view, label = out
    assert label == "anon"
    assert view.tier == "anonymous"
    assert view.slot == "anonymous"


# ---------------------------------------------------------------------------
# `_fetch_principal_auth` — `prefer_token_kind` ordering (ADR-0050 Q3).
# ---------------------------------------------------------------------------


def test_prefer_token_kind_picks_same_kind_default_slot(
    neo4j_client: Neo4jClient,
) -> None:
    """A Principal with two declared slots of *different* kinds: `prefer_token_kind`
    steers the pick; `None` falls back to the pre-ADR-0050 ordering (which, with
    both same-tier, lands on `ac.id`).
    """
    _seed_principal(neo4j_client, pid="p-multi", label="multi", p_tier="declared")
    _seed_ac(neo4j_client, acid="ac-1-cookie", pid="p-multi", tier="declared",
             kind="cookie", slot="cookie")
    _seed_ac(neo4j_client, acid="ac-2-bearer", pid="p-multi", tier="declared",
             kind="bearer", slot="api")

    cookie = _fetch_principal_auth(neo4j_client, ENG, "p-multi",
                                   prefer_token_kind="cookie")
    assert cookie is not None and str(cookie.auth_context_id) == "ac-1-cookie"
    assert cookie.slot == "cookie"

    bearer = _fetch_principal_auth(neo4j_client, ENG, "p-multi",
                                   prefer_token_kind="bearer")
    assert bearer is not None and str(bearer.auth_context_id) == "ac-2-bearer"
    assert bearer.slot == "api"

    # `prefer_token_kind=None` → both extra ORDER BY terms compare against null
    # → tie → falls through to `ac.id ASC` (pre-ADR-0050 behaviour).
    none = _fetch_principal_auth(neo4j_client, ENG, "p-multi")
    assert none is not None and str(none.auth_context_id) == "ac-1-cookie"


def test_prefer_token_kind_prefers_default_slot_among_same_kind(
    neo4j_client: Neo4jClient,
) -> None:
    """Two declared cookies (`slot='cookie'` default + `slot='stepup'`):
    `prefer_token_kind='cookie'` prefers the default-slot one (ADR-0049
    convention). The non-default's id sorts FIRST so this proves the
    `(ac.slot = $kind)` term, not the id tie-break, is doing the work.
    """
    _seed_principal(neo4j_client, pid="p-two", label="two", p_tier="declared")
    _seed_ac(neo4j_client, acid="ac-a-stepup", pid="p-two", tier="declared",
             kind="cookie", slot="stepup")
    _seed_ac(neo4j_client, acid="ac-b-default", pid="p-two", tier="declared",
             kind="cookie", slot="cookie")

    out = _fetch_principal_auth(neo4j_client, ENG, "p-two",
                                prefer_token_kind="cookie")
    assert out is not None and str(out.auth_context_id) == "ac-b-default"
    assert out.slot == "cookie"
