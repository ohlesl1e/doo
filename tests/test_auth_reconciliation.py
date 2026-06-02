"""L3 declared-vs-discovered Principal reconciliation (T4: ADR-0010).

Integration tests against a real Neo4j (testcontainer). Exercises:
- a declared Principal loaded at setup,
- a discovered bearer AuthContext whose JWT `sub` matches the declared
  `known_signals.jwt_sub` reconciles to the declared Principal (no phantom twin),
- a bearer token matching no declared signal yields a discovered Principal with
  `tier='discovered'`, `unmerged=true`,
- anonymous requests still resolve to the per-engagement singleton,
- cookie- and api-key-auth requests produce their own AuthContexts,
- the secrets-discipline invariant: no raw token bytes appear in any node
  property anywhere in the graph (acceptance criterion).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime

import jwt
import pytest

from doo.canonical.value_objects import AuthContextCue
from doo.extraction.har import extract_auth_context_cue
from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.graph_state import Neo4jGraphState
from doo.ontology.resolve import resolve_auth_context
from doo.ontology.schema import apply_schema
from doo.setup import EngagementConfig, load_engagement
from tests.test_loader import _base_config_dict

SIGNING_KEY = "irrelevant-signing-key-at-least-32-bytes-long!"
TOKEN_A = jwt.encode({"sub": "uuid-aaa", "exp": 4102444800}, SIGNING_KEY, algorithm="HS256")
TOKEN_UNKNOWN = jwt.encode({"sub": "uuid-zzz", "exp": 4102444800}, SIGNING_KEY, algorithm="HS256")


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


def _now() -> datetime:
    return datetime.now(UTC)


def _seed_declared_principal(neo4j: Neo4jClient, engagement_id: str) -> None:
    d = _base_config_dict()
    d["engagement"]["id"] = engagement_id
    d["principals"] = [
        {
            "label": "test-user-a",
            "auth_contexts": [{"kind": "bearer", "token": "${TOK_A}"}],
            "known_signals": {"jwt_sub": "uuid-aaa"},
        }
    ]
    config = EngagementConfig.model_validate(d)
    load_engagement(config, Neo4jGraphState(neo4j), env={"TOK_A": TOKEN_A})


def _resolve(neo4j: Neo4jClient, engagement_id: str, cue: AuthContextCue):
    return resolve_auth_context(
        neo4j,
        engagement_id=EngagementId(engagement_id),
        observed_at=_now(),
        ingested_at=_now(),
        cue=cue,
    )


def test_declared_principal_loaded_into_graph(neo4j_client) -> None:
    eid = "eng-recon-decl"
    _seed_declared_principal(neo4j_client, eid)
    rows = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, tier: 'declared'}) "
        "RETURN p.label AS label, p.confidence AS conf",
        eid=eid,
    )
    assert len(rows) == 1
    assert rows[0]["label"] == "test-user-a"
    assert rows[0]["conf"] == 1.0
    ac = neo4j_client.execute_read(
        "MATCH (ac:AuthContext {engagement_id: $eid, tier: 'declared'})"
        "-[:OF_PRINCIPAL]->(p:Principal {label: 'test-user-a'}) RETURN count(*) AS c",
        eid=eid,
    )
    assert ac[0]["c"] == 1


def test_declared_principal_reload_is_noop_against_neo4j(neo4j_client) -> None:
    """The graph read-back must match the desired view so a re-load is a noop.

    This exercises `Neo4jGraphState._fetch_declared_principals` against the real
    write path (the round-trip the loader's diff depends on, ADR-0019).
    """

    eid = "eng-recon-noop"
    _seed_declared_principal(neo4j_client, eid)

    d = _base_config_dict()
    d["engagement"]["id"] = eid
    d["principals"] = [
        {
            "label": "test-user-a",
            "auth_contexts": [{"kind": "bearer", "token": "${TOK_A}"}],
            "known_signals": {"jwt_sub": "uuid-aaa"},
        }
    ]
    config = EngagementConfig.model_validate(d)
    result = load_engagement(config, Neo4jGraphState(neo4j_client), env={"TOK_A": TOKEN_A})
    assert result.noop, "re-loading identical principals must be a no-op"


def test_matching_jwt_sub_reconciles_no_phantom_twin(neo4j_client) -> None:
    eid = "eng-recon-match"
    _seed_declared_principal(neo4j_client, eid)
    cue = extract_auth_context_cue(
        {"headers": [{"name": "Authorization", "value": f"Bearer {TOKEN_A}"}], "cookies": []}
    )
    resolved = _resolve(neo4j_client, eid, cue)
    # Same token as the declared AuthContext -> identity collapse (Path 2): the
    # discovered request reuses the declared AuthContext + Principal directly.
    assert resolved.principal_tier == "declared"

    # Exactly one Principal (the declared one); no phantom discovered twin.
    pcount = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid}) WHERE p.is_anonymous = false "
        "RETURN count(p) AS c",
        eid=eid,
    )
    assert pcount[0]["c"] == 1
    # The discovered AuthContext attaches to the declared Principal.
    attached = neo4j_client.execute_read(
        "MATCH (ac:AuthContext {engagement_id: $eid})-[:OF_PRINCIPAL]->"
        "(p:Principal {tier: 'declared', label: 'test-user-a'}) RETURN count(ac) AS c",
        eid=eid,
    )
    # declared AuthContext + discovered AuthContext (same auth_hash) collapse to 1.
    assert attached[0]["c"] == 1


def test_rotated_token_same_sub_reconciles_to_declared(neo4j_client) -> None:
    """A *different* token with the same `sub` (rotation) attaches to the declared
    Principal as a new discovered AuthContext — no phantom twin (ADR-0010)."""

    eid = "eng-recon-rotate"
    _seed_declared_principal(neo4j_client, eid)
    # New token: same sub uuid-aaa, different jti -> different bytes -> different hash.
    rotated = jwt.encode(
        {"sub": "uuid-aaa", "jti": "rotated-1", "exp": 4102444800},
        SIGNING_KEY,
        algorithm="HS256",
    )
    cue = extract_auth_context_cue(
        {"headers": [{"name": "Authorization", "value": f"Bearer {rotated}"}], "cookies": []}
    )
    resolved = _resolve(neo4j_client, eid, cue)
    assert resolved.tier == "discovered"
    assert resolved.principal_tier == "declared"
    assert resolved.unmerged is False

    # Still exactly one non-anonymous Principal: the declared one.
    pcount = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid}) WHERE p.is_anonymous = false "
        "RETURN count(p) AS c",
        eid=eid,
    )
    assert pcount[0]["c"] == 1
    # Two AuthContexts now point at the declared Principal: the declared token +
    # the rotated discovered one.
    acs = neo4j_client.execute_read(
        "MATCH (ac:AuthContext {engagement_id: $eid})-[:OF_PRINCIPAL]->"
        "(p:Principal {tier: 'declared'}) RETURN count(ac) AS c",
        eid=eid,
    )
    assert acs[0]["c"] == 2


def test_unknown_sub_creates_discovered_unmerged_principal(neo4j_client) -> None:
    eid = "eng-recon-unknown"
    _seed_declared_principal(neo4j_client, eid)
    cue = extract_auth_context_cue(
        {"headers": [{"name": "Authorization", "value": f"Bearer {TOKEN_UNKNOWN}"}], "cookies": []}
    )
    resolved = _resolve(neo4j_client, eid, cue)
    assert resolved.principal_tier == "discovered"
    assert resolved.unmerged is True

    rows = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, tier: 'discovered'}) "
        "WHERE p.is_anonymous = false AND p.unmerged = true RETURN count(p) AS c",
        eid=eid,
    )
    assert rows[0]["c"] == 1


def test_anonymous_singleton_preserved(neo4j_client) -> None:
    eid = "eng-recon-anon"
    _seed_declared_principal(neo4j_client, eid)
    for _ in range(3):
        resolved = _resolve(neo4j_client, eid, AuthContextCue(is_anonymous=True))
        assert resolved.tier == "anonymous"
    anon = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, is_anonymous: true}) RETURN count(p) AS c",
        eid=eid,
    )
    assert anon[0]["c"] == 1


def test_cookie_and_apikey_auth_contexts(neo4j_client) -> None:
    eid = "eng-recon-cookie"
    _seed_declared_principal(neo4j_client, eid)
    cookie_cue = extract_auth_context_cue(
        {"headers": [], "cookies": [{"name": "session", "value": "sess-xyz"}]}
    )
    apikey_cue = extract_auth_context_cue(
        {"headers": [{"name": "X-API-Key", "value": "key-xyz"}], "cookies": []}
    )
    r1 = _resolve(neo4j_client, eid, cookie_cue)
    r2 = _resolve(neo4j_client, eid, apikey_cue)
    assert r1.auth_context_id != r2.auth_context_id
    # Both are discovered (no declared cookie/api-key signal), each keyed on its hash.
    cnt = neo4j_client.execute_read(
        "MATCH (ac:AuthContext {engagement_id: $eid, tier: 'discovered'}) RETURN count(ac) AS c",
        eid=eid,
    )
    assert cnt[0]["c"] == 2


def test_no_raw_token_bytes_in_any_node_property(neo4j_client) -> None:
    """Acceptance criterion: raw token material never appears in any node prop."""

    eid = "eng-recon-secrets"
    _seed_declared_principal(neo4j_client, eid)
    cue = extract_auth_context_cue(
        {"headers": [{"name": "Authorization", "value": f"Bearer {TOKEN_A}"}], "cookies": []}
    )
    _resolve(neo4j_client, eid, cue)

    # Dump every property of every node in the engagement and assert the raw token
    # (and its components) appear nowhere.
    rows = neo4j_client.execute_read(
        "MATCH (n {engagement_id: $eid}) RETURN properties(n) AS props", eid=eid
    )
    blob = json.dumps([r["props"] for r in rows], default=str)
    assert TOKEN_A not in blob
    # The JWT signature segment in particular must not survive.
    assert TOKEN_A.split(".")[2] not in blob
