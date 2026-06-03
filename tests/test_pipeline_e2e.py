"""End-to-end pipeline integration test (Neo4j + Redis + MinIO via testcontainers).

Exercises L1 -> L2 -> L3 for the slice-1 HAR contents and asserts on the graph:
one Host, N Endpoints (one per distinct concrete path), N RequestObservations,
the per-engagement anonymous AuthContext + Principal singletons, ParseFailure
handling, L1 + L3 idempotency, cross-engagement isolation, and trace_id
propagation through structured logs.

Skips cleanly if any of the three containers cannot start (reported, not
deleted).
"""

from __future__ import annotations

import json as _json
from collections.abc import Iterator
from datetime import UTC, datetime

import jwt as _jwt
import pytest

from doo.ids import EngagementId
from doo.infra.blobs import BlobClient
from doo.infra.neo4j_driver import Neo4jClient
from doo.infra.streams import StreamClient
from doo.ingestion.intake import IntakeDeps, ingest_har
from doo.ingestion.l2_worker import L2WorkerDeps, run_l2_worker
from doo.ontology.commit import CommitOrchestrator, RedisSetNX
from doo.ontology.graph_state import Neo4jGraphState
from doo.ontology.l3_worker import L3WorkerDeps, run_l3_worker
from doo.ontology.schema import apply_schema
from doo.setup import EngagementConfig, load_engagement
from tests.fixtures import ANON_HAR, BODIES_HAR, MIXED_HAR, RESPONSE_ARTIFACTS_HAR
from tests.test_loader import _base_config_dict

# The JWT + AWS key embedded in the response_artifacts fixture; their raw bytes
# must live only in the MinIO response body, never in a Neo4j node property.
_RA_SESSION_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVC19."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5Nabc123"
)
_RA_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

_SIGNING_KEY = "irrelevant-signing-key-at-least-32-bytes-long!"
_PIPELINE_TOKEN = _jwt.encode(
    {"sub": "uuid-aaa", "exp": 4102444800}, _SIGNING_KEY, algorithm="HS256"
)


def _bearer_har(token: str) -> bytes:
    """A single-entry HAR carrying `Authorization: Bearer <token>`."""

    doc = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "startedDateTime": "2026-05-01T10:00:00.000Z",
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/me",
                        "headers": [
                            {"name": "Authorization", "value": f"Bearer {token}"}
                        ],
                        "cookies": [],
                        "queryString": [],
                    },
                    "response": {"status": 200, "bodySize": 10},
                }
            ],
        }
    }
    return _json.dumps(doc).encode("utf-8")


@pytest.fixture
def neo4j_client(neo4j_container) -> Iterator[Neo4jClient]:
    client = Neo4jClient.connect(
        neo4j_container.get_connection_url(),
        neo4j_container.username,
        neo4j_container.password,
    )
    # Edition-aware schema bootstrap (skips existence constraints on Community).
    with client.driver.session() as session:
        apply_schema(session, edition=client.server_edition())
    try:
        yield client
    finally:
        client.close()


@pytest.fixture
def redis_client(redis_url):  # type: ignore[no-untyped-def]
    import redis

    client = redis.Redis.from_url(redis_url, decode_responses=True)
    try:
        yield client
    finally:
        client.flushall()
        client.close()


@pytest.fixture
def blob_client(minio_config) -> BlobClient:
    return BlobClient.from_config(
        endpoint_url=minio_config["endpoint_url"],
        access_key=minio_config["access_key"],
        secret_key=minio_config["secret_key"],
        bucket="doo-blobs",
    )


def _seed_engagement(neo4j: Neo4jClient, engagement_id: str) -> None:
    """Create a minimal Engagement + Scope so intake's existence gate passes."""

    now = datetime.now(UTC)
    state = Neo4jGraphState(neo4j)
    from doo.setup.loader import PlannedMutation

    cross = {
        "source": "manual",
        "source_id": None,
        "confidence": 1.0,
        "confidence_method": "manual",
        "first_seen": now,
        "last_seen": now,
        "ingested_at": now,
        "status": "active",
    }
    state.apply_mutations(
        (
            PlannedMutation(
                kind="scope_create",
                properties={"content_hash": f"scope-{engagement_id}", "rules": {}, **cross},
            ),
            PlannedMutation(
                kind="engagement_create",
                properties={
                    "id": engagement_id,
                    "name": engagement_id,
                    "description": None,
                    "time_window": None,
                    "kill_switch": {"backend": "redis"},
                    **cross,
                },
            ),
            PlannedMutation(
                kind="engagement_under_scope",
                properties={
                    "engagement_id": engagement_id,
                    "scope_content_hash": f"scope-{engagement_id}",
                },
            ),
        )
    )


def _run_pipeline(
    *,
    neo4j: Neo4jClient,
    redis_client,
    blob_client: BlobClient,
    engagement_id: str,
    har_bytes: bytes,
    filename: str,
) -> None:
    """Drive L1 intake -> L2 worker -> L3 worker for one HAR upload."""

    streams = StreamClient(redis_client)
    intake = IntakeDeps(
        engagements=Neo4jGraphState(neo4j), blobs=blob_client, streams=streams
    )
    ingest_har(
        intake,
        engagement_id=EngagementId(engagement_id),
        filename=filename,
        data=har_bytes,
    )
    run_l2_worker(L2WorkerDeps(blobs=blob_client, streams=streams), max_messages=1)
    orchestrator = CommitOrchestrator(
        neo4j=neo4j,
        idempotency=RedisSetNX(redis_client),
        streams=streams,
        expected_engagement_id=EngagementId(engagement_id),
    )
    # Drain however many L2 events the HAR produced.
    run_l3_worker(
        L3WorkerDeps(orchestrator=orchestrator, streams=streams),
        max_messages=50,
        block_ms=500,
    )
    # Deferred endpoint inference (ADR-0022): re-template the dirty cohorts once,
    # the way `doo worker run` does at end of drain.
    orchestrator.flush()


def _count(neo4j: Neo4jClient, label: str, engagement_id: str) -> int:
    rows = neo4j.execute_read(
        f"MATCH (n:{label} {{engagement_id: $eid}}) RETURN count(n) AS c",
        eid=engagement_id,
    )
    return int(rows[0]["c"])


def test_anon_har_full_pipeline(neo4j_client, redis_client, blob_client) -> None:
    eid = "eng-e2e-anon"
    _seed_engagement(neo4j_client, eid)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=ANON_HAR.read_bytes(),
        filename="anon_burp.har",
    )

    # 4 entries -> 4 RequestObservations; /products and /products/ collapse, so
    # 3 distinct Endpoints; one Host; anonymous singletons (exactly one each).
    assert _count(neo4j_client, "RequestObservation", eid) == 4
    assert _count(neo4j_client, "Endpoint", eid) == 3
    assert _count(neo4j_client, "Host", eid) == 1
    assert _count(neo4j_client, "AuthContext", eid) == 1
    assert _count(neo4j_client, "Principal", eid) == 1

    # Every Endpoint carries engagement_id.
    rows = neo4j_client.execute_read(
        "MATCH (e:Endpoint {engagement_id: $eid}) RETURN count(e) AS c", eid=eid
    )
    assert rows[0]["c"] == 3

    # Structural edges exist: RequestObservation -HIT-> Endpoint.
    hit = neo4j_client.execute_read(
        "MATCH (:RequestObservation {engagement_id: $eid})-[:HIT]->(:Endpoint) "
        "RETURN count(*) AS c",
        eid=eid,
    )
    assert hit[0]["c"] == 4


def test_reupload_same_har_is_idempotent(neo4j_client, redis_client, blob_client) -> None:
    eid = "eng-e2e-idem"
    _seed_engagement(neo4j_client, eid)
    for _ in range(2):
        _run_pipeline(
            neo4j=neo4j_client,
            redis_client=redis_client,
            blob_client=blob_client,
            engagement_id=eid,
            har_bytes=ANON_HAR.read_bytes(),
            filename="anon_burp.har",
        )
    # Re-upload collapses: same node counts as a single ingest.
    assert _count(neo4j_client, "RequestObservation", eid) == 4
    assert _count(neo4j_client, "Endpoint", eid) == 3
    assert _count(neo4j_client, "AuthContext", eid) == 1
    assert _count(neo4j_client, "Principal", eid) == 1


def test_malformed_entry_produces_parse_failure_with_backref(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-e2e-mixed"
    _seed_engagement(neo4j_client, eid)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=MIXED_HAR.read_bytes(),
        filename="mixed.har",
    )
    # 2 good entries + 1 ParseFailure.
    assert _count(neo4j_client, "RequestObservation", eid) == 2
    assert _count(neo4j_client, "ParseFailure", eid) == 1
    rows = neo4j_client.execute_read(
        "MATCH (f:ParseFailure {engagement_id: $eid}) "
        "RETURN f.envelope_event_id AS ev, f.error_kind AS kind, f.error_message AS msg",
        eid=eid,
    )
    assert rows[0]["ev"]  # back-ref to the L1 envelope present
    assert rows[0]["kind"] == "missing_required_field"
    assert rows[0]["msg"]


def test_cross_engagement_isolation(neo4j_client, redis_client, blob_client) -> None:
    for eid in ("eng-e2e-x1", "eng-e2e-x2"):
        _seed_engagement(neo4j_client, eid)
        _run_pipeline(
            neo4j=neo4j_client,
            redis_client=redis_client,
            blob_client=blob_client,
            engagement_id=eid,
            har_bytes=ANON_HAR.read_bytes(),
            filename="anon_burp.har",
        )
    # Two disjoint subgraphs; counts independent.
    assert _count(neo4j_client, "Endpoint", "eng-e2e-x1") == 3
    assert _count(neo4j_client, "Endpoint", "eng-e2e-x2") == 3
    assert _count(neo4j_client, "Host", "eng-e2e-x1") == 1
    assert _count(neo4j_client, "Host", "eng-e2e-x2") == 1
    # No Host node is shared across engagements (engagement-scoped identity).
    shared = neo4j_client.execute_read(
        "MATCH (a:Host {engagement_id: 'eng-e2e-x1'}), (b:Host {engagement_id: 'eng-e2e-x2'}) "
        "WHERE a.id = b.id RETURN count(*) AS c"
    )
    assert shared[0]["c"] == 0


def test_bearer_har_reconciles_to_declared_principal_no_raw_token(
    neo4j_client, redis_client, blob_client
) -> None:
    """T4 end-to-end: a bearer HAR whose JWT sub matches a declared Principal's
    `known_signals.jwt_sub` attaches to that declared Principal (no phantom twin),
    and the raw token appears in no Neo4j node property (acceptance criterion)."""

    eid = "eng-e2e-bearer"
    d = _base_config_dict()
    d["engagement"]["id"] = eid
    d["scope"]["host_patterns"] = ["^api\\.example\\.com$"]
    d["principals"] = [
        {
            "label": "test-user-a",
            "auth_contexts": [{"kind": "bearer", "token": "${TOK_A}"}],
            "known_signals": {"jwt_sub": "uuid-aaa"},
        }
    ]
    config = EngagementConfig.model_validate(d)
    load_engagement(config, Neo4jGraphState(neo4j_client), env={"TOK_A": _PIPELINE_TOKEN})

    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=_bearer_har(_PIPELINE_TOKEN),
        filename="bearer.har",
    )

    # No phantom twin: exactly one non-anonymous Principal (the declared one).
    rows = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, tier: 'declared', label: 'test-user-a'}) "
        "RETURN count(p) AS c",
        eid=eid,
    )
    assert rows[0]["c"] == 1
    disc = neo4j_client.execute_read(
        "MATCH (p:Principal {engagement_id: $eid, tier: 'discovered'}) "
        "WHERE p.is_anonymous = false RETURN count(p) AS c",
        eid=eid,
    )
    assert disc[0]["c"] == 0

    # Secrets discipline: the raw token (and its signature) live in no node prop.
    nodes = neo4j_client.execute_read(
        "MATCH (n {engagement_id: $eid}) RETURN properties(n) AS props", eid=eid
    )
    import json as _j

    blob = _j.dumps([n["props"] for n in nodes], default=str)
    assert _PIPELINE_TOKEN not in blob
    assert _PIPELINE_TOKEN.split(".")[2] not in blob


def test_bodies_har_full_pipeline_blobs_params_and_secrets(
    neo4j_client, redis_client, blob_client
) -> None:
    """T5 end-to-end: bodies land in MinIO, RO nodes carry serialised BlobRefs,
    body bytes round-trip out of MinIO by `BlobRef.key` with a matching sha256,
    body params aggregate into `location="body"` Parameter nodes (incl. a JSON
    pointer), and the raw refresh token lives only in MinIO — never in a graph
    node property (ADR-0015)."""

    import base64
    import hashlib
    import json as _j

    eid = "eng-e2e-bodies"
    _seed_engagement(neo4j_client, eid)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=BODIES_HAR.read_bytes(),
        filename="bodies.har",
    )

    # 6 entries -> 6 RequestObservations on one Host.
    assert _count(neo4j_client, "RequestObservation", eid) == 6
    assert _count(neo4j_client, "Host", eid) == 1

    # --- POST /api/users carries a request_body_ref; bytes round-trip by key. ---
    rows = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid, concrete_path: '/api/users'}) "
        "RETURN r.request_body_ref AS rb",
        eid=eid,
    )
    assert rows and rows[0]["rb"]
    ref = _j.loads(rows[0]["rb"])
    assert ref["content_type"] == "application/json"
    assert ref["key"] == f"engagement/{eid}/source/har/bodies/{ref['sha256']}.bin"
    # Round-trip the body out of MinIO via BlobRef.key; sha256 matches.
    body = blob_client.get(ref["key"])
    assert hashlib.sha256(body).hexdigest() == ref["sha256"]
    # The body is the real JSON request body, and it still holds the raw token.
    assert b"alice.profile@example.com" in body
    assert b"eyJhbGciOiJIUzI1Ni1." in body

    # --- base64 response body decoded before upload; stored bytes are raw. ---
    rows = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid, concrete_path: '/api/avatar'}) "
        "RETURN r.response_body_ref AS rb",
        eid=eid,
    )
    resp_ref = _j.loads(rows[0]["rb"])
    stored = blob_client.get(resp_ref["key"])
    assert stored == base64.b64decode("iVBORw0KGgoAAAByYXdiaW5hcnktYnl0ZXM=")
    assert hashlib.sha256(stored).hexdigest() == resp_ref["sha256"]

    # --- no-body entry: both refs null, no placeholder object. ---
    rows = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid, concrete_path: '/api/health'}) "
        "RETURN r.request_body_ref AS rq, r.response_body_ref AS rs",
        eid=eid,
    )
    assert rows[0]["rq"] is None and rows[0]["rs"] is None

    # --- body params aggregate into Parameter nodes with location="body". ---
    # JSON-pointer-named leaf: /user/email leaf has name "email".
    body_params = neo4j_client.execute_read(
        "MATCH (e:Endpoint {engagement_id: $eid})-[:HAS_PARAMETER]->"
        "(p:Parameter {engagement_id: $eid, location: 'body'}) "
        "RETURN collect(DISTINCT p.name) AS names",
        eid=eid,
    )
    names = set(body_params[0]["names"])
    # Form pairs from /api/login + /api/search, multipart caption, JSON leaves.
    assert {"username", "remember", "q", "page", "caption"} <= names
    assert "email" in names  # from the JSON body's /user/email + /user/profile/email
    assert "refresh_token" in names  # the param exists even though its value is suppressed

    # Every body Parameter hangs off an Endpoint via HAS_PARAMETER.
    edge = neo4j_client.execute_read(
        "MATCH (:Endpoint {engagement_id: $eid})-[:HAS_PARAMETER]->"
        "(p:Parameter {engagement_id: $eid, location: 'body'}) RETURN count(p) AS c",
        eid=eid,
    )
    assert edge[0]["c"] >= 1

    # --- ADR-0015: the raw refresh token appears in NO graph node property. ---
    nodes = neo4j_client.execute_read(
        "MATCH (n {engagement_id: $eid}) RETURN properties(n) AS props", eid=eid
    )
    blob = _j.dumps([n["props"] for n in nodes], default=str)
    assert "eyJhbGciOiJIUzI1Ni1." not in blob  # raw token never in the graph
    assert "hunter2" not in blob  # the form password value is suppressed too


def test_response_artifacts_full_pipeline_exact_n_and_yielded_edges(
    neo4j_client, redis_client, blob_client
) -> None:
    """T6 end-to-end: the response-artifact fixture lands exactly N ResponseArtifact
    nodes, each YIELDED from its parent RO with a matching engagement_id; the
    acceptance-criterion hostname/JWT/Server artifacts have the expected shape."""

    eid = "eng-e2e-ra"
    _seed_engagement(neo4j_client, eid)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=RESPONSE_ARTIFACTS_HAR.read_bytes(),
        filename="response_artifacts.har",
    )

    # 5 entries -> 5 RequestObservations; the fixture yields exactly 7 artifacts:
    # hostname + error_message (500), JWT secret_shaped, Server fingerprint,
    # url + hostname (internal URL), AWS secret_shaped.
    assert _count(neo4j_client, "RequestObservation", eid) == 5
    assert _count(neo4j_client, "ResponseArtifact", eid) == 7

    # Every ResponseArtifact is YIELDED from a RequestObservation; the edge and
    # both endpoints share the engagement_id (ADR-0017).
    yielded = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid})-[y:YIELDED]->"
        "(a:ResponseArtifact {engagement_id: $eid}) "
        "WHERE y.engagement_id = $eid AND r.engagement_id = a.engagement_id "
        "RETURN count(a) AS c",
        eid=eid,
    )
    assert yielded[0]["c"] == 7

    # Acceptance: the internal hostname artifact.
    host = neo4j_client.execute_read(
        "MATCH (a:ResponseArtifact {engagement_id: $eid, artifact_kind: 'hostname', "
        "value: 'internal-billing.corp.example'}) "
        "RETURN a.extractor AS ex, a.location_section AS sec",
        eid=eid,
    )
    assert host and host[0]["ex"] == "regex:internal_hostname_v1"
    assert host[0]["sec"] == "body"

    # Acceptance: the JWT secret-shape carries hash+preview, value is null.
    jwt_art = neo4j_client.execute_read(
        "MATCH (a:ResponseArtifact {engagement_id: $eid, artifact_kind: 'secret_shaped'}) "
        "WHERE a.extractor = 'regex:jwt_v1' "
        "RETURN a.value AS v, a.value_hash AS h, a.value_length AS len, a.value_preview AS prev",
        eid=eid,
    )
    import hashlib as _hl

    assert jwt_art and jwt_art[0]["v"] is None
    assert jwt_art[0]["h"] == _hl.sha256(_RA_SESSION_JWT.encode()).hexdigest()
    assert jwt_art[0]["len"] == len(_RA_SESSION_JWT.encode())
    assert jwt_art[0]["prev"] == _RA_SESSION_JWT[:8]

    # Acceptance: the Server fingerprint (header section).
    fp = neo4j_client.execute_read(
        "MATCH (a:ResponseArtifact {engagement_id: $eid, artifact_kind: 'fingerprint'}) "
        "RETURN a.location_section AS sec, a.location_header_name AS hn, a.value AS v",
        eid=eid,
    )
    assert fp and fp[0]["sec"] == "header"
    assert fp[0]["hn"] == "Server"
    assert fp[0]["v"] == "nginx/1.21.6"

    # ADR-0015: neither the raw JWT nor the AWS key appears in ANY node property.
    import json as _j

    nodes = neo4j_client.execute_read(
        "MATCH (n {engagement_id: $eid}) RETURN properties(n) AS props", eid=eid
    )
    blob = _j.dumps([n["props"] for n in nodes], default=str)
    assert _RA_SESSION_JWT not in blob
    assert _RA_AWS_KEY not in blob

    # ...but the raw bytes are retrievable from MinIO via the RO's response_body_ref.
    refs = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid, concrete_path: '/session'}) "
        "RETURN r.response_body_ref AS rb",
        eid=eid,
    )
    assert refs and refs[0]["rb"]
    ref = _j.loads(refs[0]["rb"])
    body = blob_client.get(ref["key"])
    assert _RA_SESSION_JWT.encode() in body


def test_response_artifacts_reingest_idempotent_no_duplicates(
    neo4j_client, redis_client, blob_client
) -> None:
    """T6 idempotency: re-ingesting the same response does NOT double-create
    ResponseArtifacts, despite the random UUID7 artifact_id. The deterministic,
    secret-free source_id collapses the re-delivery at the ADR-0016 SETNX."""

    eid = "eng-e2e-ra-idem"
    _seed_engagement(neo4j_client, eid)
    for _ in range(2):
        _run_pipeline(
            neo4j=neo4j_client,
            redis_client=redis_client,
            blob_client=blob_client,
            engagement_id=eid,
            har_bytes=RESPONSE_ARTIFACTS_HAR.read_bytes(),
            filename="response_artifacts.har",
        )
    # Second ingest collapses: still exactly 7 ResponseArtifacts, 5 ROs.
    assert _count(neo4j_client, "ResponseArtifact", eid) == 7
    assert _count(neo4j_client, "RequestObservation", eid) == 5


def test_unknown_engagement_4xx_nothing_lands(neo4j_client, redis_client, blob_client) -> None:
    from doo.ingestion.intake import UnknownEngagementError

    streams = StreamClient(redis_client)
    intake = IntakeDeps(
        engagements=Neo4jGraphState(neo4j_client), blobs=blob_client, streams=streams
    )
    with pytest.raises(UnknownEngagementError):
        ingest_har(
            intake,
            engagement_id=EngagementId("does-not-exist"),
            filename="x.har",
            data=ANON_HAR.read_bytes(),
        )
    # Nothing on the ingest stream.
    assert redis_client.xlen("ingest") == 0
