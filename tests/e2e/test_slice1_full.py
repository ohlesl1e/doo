"""Comprehensive slice-1 end-to-end (T8 capstone).

One HAR (`tests/fixtures/har/comprehensive.har`), driven through the real
L1->L2->L3 pipeline on Neo4j+Redis+MinIO testcontainers, exercising **every**
T2-T6 capability at once and asserting the integrated graph with explicit
Cypher:

- **T2** pipeline + anonymous singleton + `ParseFailure` (the malformed entry).
- **T3** templating: `/users/42` + `/users/87` collapse to `/users/{user_id}`;
  `/users/settings` stays a literal sibling; `/v1/...` and `/v2/...` keep their
  version segment literal as distinct endpoints.
- **T4** auth reconciliation: the bearer JWT (`sub=uuid-aaa`) reconciles to the
  declared Principal `test-user-a` with **no phantom-twin** discovered Principal;
  anonymous traffic keeps the anonymous singleton.
- **T5** bodies: the POST JSON body lands in MinIO and aggregates body
  `Parameter`s; the in-body refresh token never reaches the graph.
- **T6** response artifacts: the 500 body yields the internal hostname, the
  `/session` JSON yields a secret-shaped JWT (hash+preview only), the `Server`
  header yields a fingerprint — each `YIELDED` from its parent observation.
- **ADR-0015**: no raw token bytes (bearer / refresh / access) appear in any
  Neo4j node property — only in the MinIO blobs.

The per-feature pipeline behaviour is also covered in `tests/test_pipeline_e2e.py`;
this is the single integrated exercise that catches cross-feature regressions.
The engagement-start / keepalive-lifecycle / loader-rerun CLI flows are covered by
`tests/test_keepalive.py` and `tests/test_loader.py` (see `tests/coverage-matrix.md`).
"""

from __future__ import annotations

import json as _json

from doo.ontology.graph_state import Neo4jGraphState
from doo.setup import EngagementConfig, load_engagement
from tests.fixtures import COMPREHENSIVE_HAR
from tests.test_loader import _base_config_dict

# Reuse the pipeline driver + count helper; the container fixtures
# (neo4j_client / redis_client / blob_client) come from tests/e2e/conftest.py.
from tests.test_pipeline_e2e import _count, _run_pipeline

# The three JWTs embedded in comprehensive.har. All carry sub=uuid-aaa; their raw
# bytes (and signature segments) must live only in MinIO, never in a graph node.
_BEARER = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJ1dWlkLWFhYSIsImV4cCI6NDEwMjQ0NDgwMH0."
    "g32AFQCk2wGfExJCjL61A7bgUXAqwvfY1AF0-w5I-K0"
)
_ACCESS_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJ1dWlkLWFhYSIsInNjb3BlIjoic2Vzc2lvbiIsImV4cCI6NDEwMjQ0NDgwMH0."
    "JM58J8qBw-prxS7CKqEmRlhvQqf0EWo7JUq9Be5jbzs"
)
_REFRESH_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJ1dWlkLWFhYSIsInR5cCI6InJlZnJlc2giLCJleHAiOjQxMDI0NDQ4MDB9."
    "GRt31K0L22dYSXz-Y8s03VbSK_Rm5l3V_2AcQYo4M08"
)

_EID = "acme-test"


def _load_engagement_with_declared_principal(neo4j_client) -> None:
    """Create the Engagement + Scope + declared Principal `test-user-a`
    (`known_signals.jwt_sub = uuid-aaa`) so the bearer traffic reconciles to it."""

    d = _base_config_dict()
    d["engagement"]["id"] = _EID
    d["scope"]["host_patterns"] = ["^api\\.example\\.com$"]
    d["principals"] = [
        {
            "label": "test-user-a",
            "auth_contexts": [{"kind": "bearer", "token": "${TOK_A}"}],
            "known_signals": {"jwt_sub": "uuid-aaa"},
        }
    ]
    config = EngagementConfig.model_validate(d)
    # The declared token decodes to sub=uuid-aaa, satisfying the loader cross-check.
    load_engagement(config, Neo4jGraphState(neo4j_client), env={"TOK_A": _BEARER})


def _all_node_props_blob(neo4j_client) -> str:
    nodes = neo4j_client.execute_read(
        "MATCH (n {engagement_id: $eid}) RETURN properties(n) AS props", eid=_EID
    )
    return _json.dumps([n["props"] for n in nodes], default=str)


def test_slice1_comprehensive_pipeline(neo4j_client, redis_client, blob_client) -> None:
    _load_engagement_with_declared_principal(neo4j_client)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=_EID,
        har_bytes=COMPREHENSIVE_HAR.read_bytes(),
        filename="comprehensive.har",
    )

    # --- T2: 9 well-formed entries -> 9 ROs + 1 ParseFailure; one Host. ---
    assert _count(neo4j_client, "RequestObservation", _EID) == 9
    assert _count(neo4j_client, "ParseFailure", _EID) == 1
    assert _count(neo4j_client, "Host", _EID) == 1

    # --- T3: templating. /users/42 + /users/87 -> one /users/{...} endpoint with
    # 2 HITs; /users/settings is a distinct literal sibling; v1/v2 stay literal. ---
    templated = neo4j_client.execute_read(
        "MATCH (e:Endpoint {engagement_id: $eid}) WHERE e.path_template STARTS WITH '/users/' "
        "AND e.path_template CONTAINS '{' "
        "MATCH (:RequestObservation {engagement_id: $eid})-[:HIT]->(e) "
        "RETURN e.path_template AS t, count(*) AS hits",
        eid=_EID,
    )
    assert templated and templated[0]["hits"] == 2  # /users/42 + /users/87
    literal_sibling = neo4j_client.execute_read(
        "MATCH (e:Endpoint {engagement_id: $eid, path_template: '/users/settings'}) "
        "RETURN count(e) AS c",
        eid=_EID,
    )
    assert literal_sibling[0]["c"] == 1
    version_literals = neo4j_client.execute_read(
        "MATCH (e:Endpoint {engagement_id: $eid}) "
        "WHERE e.path_template STARTS WITH '/v1/' OR e.path_template STARTS WITH '/v2/' "
        "RETURN count(e) AS c",
        eid=_EID,
    )
    assert version_literals[0]["c"] == 2  # /v1/... and /v2/... are distinct endpoints

    # --- T4: bearer (sub=uuid-aaa) reconciles to declared test-user-a; no phantom. ---
    declared = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, tier: 'declared', label: 'test-user-a'}) "
        "RETURN count(p) AS c",
        eid=_EID,
    )
    assert declared[0]["c"] == 1
    phantom = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, tier: 'discovered'}) "
        "WHERE p.is_anonymous = false RETURN count(p) AS c",
        eid=_EID,
    )
    assert phantom[0]["c"] == 0  # no phantom-twin discovered Principal
    # The anonymous singleton is intact (exactly one anonymous Principal).
    anon = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, is_anonymous: true}) RETURN count(p) AS c",
        eid=_EID,
    )
    assert anon[0]["c"] == 1
    # Every authenticated observation's AuthContext traces to test-user-a.
    authed = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid})-[:OBSERVED_UNDER]->"
        "(:AuthContext)-[:OF_PRINCIPAL]->(p:Principal {label: 'test-user-a'}) "
        "RETURN count(DISTINCT r) AS c",
        eid=_EID,
    )
    assert authed[0]["c"] >= 1

    # --- T5: POST /api/accounts JSON body -> body Parameters; secret not a value. ---
    body_names = neo4j_client.execute_read(
        "MATCH (:Endpoint {engagement_id: $eid})-[:HAS_PARAMETER]->"
        "(p:Parameter {engagement_id: $eid, location: 'body'}) "
        "RETURN collect(DISTINCT p.name) AS names",
        eid=_EID,
    )
    names = set(body_names[0]["names"])
    assert {"username", "email", "tier"} <= names
    assert "refresh_token" in names  # the param exists; its raw value is suppressed

    # --- T6: response artifacts. ---
    hostname = neo4j_client.execute_read(
        "MATCH (a:ResponseArtifact {engagement_id: $eid, artifact_kind: 'hostname', "
        "value: 'internal-billing.corp.example'}) RETURN a.location_section AS sec",
        eid=_EID,
    )
    assert hostname and hostname[0]["sec"] == "body"
    secret_jwt = neo4j_client.execute_read(
        "MATCH (a:ResponseArtifact {engagement_id: $eid, artifact_kind: 'secret_shaped'}) "
        "WHERE a.extractor = 'regex:jwt_v1' "
        "RETURN a.value AS v, a.value_hash AS h, a.value_preview AS prev",
        eid=_EID,
    )
    assert secret_jwt and secret_jwt[0]["v"] is None and secret_jwt[0]["h"]
    fingerprint = neo4j_client.execute_read(
        "MATCH (a:ResponseArtifact {engagement_id: $eid, artifact_kind: 'fingerprint'}) "
        "RETURN a.location_header_name AS hn, a.value AS v",
        eid=_EID,
    )
    assert fingerprint and fingerprint[0]["hn"] == "Server"
    assert fingerprint[0]["v"] == "nginx/1.21.6"
    # Every ResponseArtifact is YIELDED from a RequestObservation.
    yielded = neo4j_client.execute_read(
        "MATCH (:RequestObservation {engagement_id: $eid})-[:YIELDED]->"
        "(a:ResponseArtifact {engagement_id: $eid}) RETURN count(a) AS c",
        eid=_EID,
    )
    assert yielded[0]["c"] == _count(neo4j_client, "ResponseArtifact", _EID)
    assert yielded[0]["c"] >= 3

    # --- ADR-0015: no raw token bytes anywhere in the graph. ---
    blob = _all_node_props_blob(neo4j_client)
    for tok in (_BEARER, _ACCESS_TOKEN, _REFRESH_TOKEN):
        assert tok not in blob
        assert tok.split(".")[2] not in blob  # not even the signature segment


def test_slice1_comprehensive_reingest_is_idempotent(
    neo4j_client, redis_client, blob_client
) -> None:
    """Re-ingesting the comprehensive HAR is a no-op: every node count is stable
    (L1 + L3 idempotency across templating, auth, bodies, and artifacts)."""

    _load_engagement_with_declared_principal(neo4j_client)
    counts: list[dict[str, int]] = []
    for _ in range(2):
        _run_pipeline(
            neo4j=neo4j_client,
            redis_client=redis_client,
            blob_client=blob_client,
            engagement_id=_EID,
            har_bytes=COMPREHENSIVE_HAR.read_bytes(),
            filename="comprehensive.har",
        )
        counts.append(
            {
                label: _count(neo4j_client, label, _EID)
                for label in (
                    "RequestObservation",
                    "Endpoint",
                    "Parameter",
                    "ResponseArtifact",
                    "ParseFailure",
                    "Principal",
                    "AuthContext",
                )
            }
        )
    assert counts[0] == counts[1]  # second ingest adds nothing
