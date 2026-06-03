"""End-to-end integration test for ADR-0023 `ObservedValue` promotion.

Drives the real L1 -> L2 -> L3 pipeline (Neo4j + Redis + MinIO testcontainers,
mirroring `test_templating_e2e.py`) and asserts on the graph: a fixture HAR yields
exactly the expected `ObservedValue`s + `YIELDED_VALUE` edges, **zero**
`ResponseArtifact`s, secrets hash-only, the 277k collapse (100 distinct UUIDs ->
no nodes), `value_hash` dedup across responses, fingerprint/error inline, and
idempotent re-ingest.

Skips cleanly if any container cannot start. Reuses the pipeline driver + count
helper from `test_pipeline_e2e`.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator

import pytest

from doo.infra.blobs import BlobClient
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.schema import apply_schema
from tests.test_pipeline_e2e import _count, _run_pipeline, _seed_engagement

_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJ1c2VyIn0.AbCdEf0123456789AbCdEf0123456789AbCd"
)


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


def _entry(url: str, *, minute: int, second: int, status: int, ctype: str, body: str) -> dict:
    return {
        "startedDateTime": f"2026-05-03T09:{minute:02d}:{second:02d}.000Z",
        "request": {
            "method": "GET",
            "url": url,
            "queryString": [],
            "headersSize": -1,
            "bodySize": 0,
        },
        "response": {
            "status": status,
            "bodySize": len(body),
            "headers": [{"name": "Server", "value": "nginx/1.21.6"}]
            if status == 200
            else [{"name": "Content-Type", "value": "text/html"}],
            "content": {"mimeType": ctype, "text": body},
        },
    }


# A UUID that leaks in a *list* response (output, endpoint A = /widgets) and is
# later sent as a request query parameter (input, endpoint B = /widget-detail) ->
# the leak-to-input pivot (#16): ONE ObservedValue, a YIELDED_VALUE from the
# producer and a SENT_VALUE {parameter_name} from the consumer.
LEAKED_UUID = "11111111-2222-3333-4444-555555555555"


def _input_entry(
    url: str, *, minute: int, second: int, query: list[dict[str, str]]
) -> dict:
    """A 200 GET entry whose request carries query parameters (the input side)."""

    return {
        "startedDateTime": f"2026-05-03T09:{minute:02d}:{second:02d}.000Z",
        "request": {
            "method": "GET",
            "url": url,
            "queryString": query,
            "headersSize": -1,
            "bodySize": 0,
        },
        "response": {
            "status": 200,
            "bodySize": 2,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"mimeType": "application/json", "text": "{}"},
        },
    }


def _fixture_har() -> bytes:
    """A HAR exercising every promotion case ADR-0023 names for #14/#15/#16.

    - /report (500 HTML): an internal hostname + a 5xx error excerpt.
    - /session (200 JSON): a JWT (secret), and a Server fingerprint header.
    - /a and /b (200 JSON): the SAME internal hostname in two responses (dedup).
    - /list (200 JSON): 100 distinct UUID ids (the 277k collapse: no promotion).
    - /x and /y (200 JSON): the SAME non-allowlisted `account_id` in two responses
      (multiplicity >=2 -> promotes, #15).
    - /solo (200 JSON): a non-allowlisted `account_id` seen in ONE response
      (multiplicity 1 -> stays inline, no promotion).
    - /widgets (200 JSON): a list whose item ids include LEAKED_UUID (output).
    - /widget-detail?widget_id=LEAKED_UUID (200): the same UUID sent as a request
      query parameter (input) -> leak-to-input pivot across distinct endpoints (#16).
    """

    # A recurring tenant/account identifier (non-allowlisted `identifier` kind) that
    # appears in two distinct responses -> promotes on multiplicity, not shape.
    recurring_account = "acct-recurring-7f3a"
    # A non-allowlisted identifier seen in exactly one response -> no promotion.
    solo_account = "acct-solo-91bd"
    list_items = json.dumps(
        {"items": [{"id": f"{i:08d}-0000-0000-0000-000000000000"} for i in range(100)]}
    )
    # A short list whose item ids include the UUID we later send as an input.
    widgets = json.dumps(
        {"items": [{"id": LEAKED_UUID}, {"id": "99999999-8888-7777-6666-555555555555"}]}
    )
    entries = [
        _entry(
            "https://api.example.com/report",
            minute=0, second=0, status=500, ctype="text/html",
            body="<html><body>Error: cannot reach internal-billing.corp.example</body></html>",
        ),
        _entry(
            "https://api.example.com/session",
            minute=0, second=1, status=200, ctype="application/json",
            body=json.dumps({"access_token": _JWT}),
        ),
        _entry(
            "https://api.example.com/a",
            minute=0, second=2, status=200, ctype="application/json",
            body=json.dumps({"backend": "shared.internal.example"}),
        ),
        _entry(
            "https://api.example.com/b",
            minute=0, second=3, status=200, ctype="application/json",
            body=json.dumps({"upstream": "shared.internal.example"}),
        ),
        _entry(
            "https://api.example.com/list",
            minute=0, second=4, status=200, ctype="application/json",
            body=list_items,
        ),
        _entry(
            "https://api.example.com/x",
            minute=0, second=5, status=200, ctype="application/json",
            body=json.dumps({"account_id": recurring_account}),
        ),
        _entry(
            "https://api.example.com/y",
            minute=0, second=6, status=200, ctype="application/json",
            body=json.dumps({"account_id": recurring_account}),
        ),
        _entry(
            "https://api.example.com/solo",
            minute=0, second=7, status=200, ctype="application/json",
            body=json.dumps({"account_id": solo_account}),
        ),
        _entry(
            "https://api.example.com/widgets",
            minute=0, second=8, status=200, ctype="application/json",
            body=widgets,
        ),
        _input_entry(
            f"https://api.example.com/widget-detail?widget_id={LEAKED_UUID}",
            minute=0, second=9,
            query=[{"name": "widget_id", "value": LEAKED_UUID}],
        ),
    ]
    return json.dumps({"log": {"version": "1.2", "entries": entries}}).encode()


def test_observed_value_promotion_end_to_end(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-ov-e2e"
    _seed_engagement(neo4j_client, eid)
    _run_pipeline(
        neo4j=neo4j_client,
        redis_client=redis_client,
        blob_client=blob_client,
        engagement_id=eid,
        har_bytes=_fixture_har(),
        filename="observed_values.har",
    )

    # Zero ResponseArtifacts (retired). 10 RequestObservations.
    assert _count(neo4j_client, "ResponseArtifact", eid) == 0
    assert _count(neo4j_client, "RequestObservation", eid) == 10

    # Five ObservedValues promote: internal-billing.corp.example,
    # shared.internal.example (deduped across /a and /b), the JWT secret, the
    # recurring account_id (multiplicity >=2 across /x and /y, #15), and the
    # LEAKED_UUID (leak-to-input across /widgets output + /widget-detail input,
    # #16). The 100 list UUIDs do NOT promote (the 277k collapse), the solo
    # account_id seen in one response does NOT promote (multiplicity 1), and the
    # second /widgets UUID seen only once as an output does NOT promote.
    assert _count(neo4j_client, "ObservedValue", eid) == 5
    kinds = neo4j_client.execute_read(
        "MATCH (v:ObservedValue {engagement_id: $eid}) RETURN v.kind AS k, count(*) AS c "
        "ORDER BY k",
        eid=eid,
    )
    assert {r["k"]: r["c"] for r in kinds} == {
        "internal_hostname": 2,
        "identifier": 2,
        "secret": 1,
    }

    # Leak-to-input pivot (#16): LEAKED_UUID promotes to ONE ObservedValue with a
    # YIELDED_VALUE edge from the producing /widgets response and a SENT_VALUE edge
    # carrying parameter_name=widget_id from the consuming /widget-detail request —
    # across DISTINCT endpoints.
    pivot = neo4j_client.execute_read(
        "MATCH (v:ObservedValue {engagement_id: $eid, value: $uuid}) "
        "OPTIONAL MATCH (prod:RequestObservation)-[:YIELDED_VALUE]->(v) "
        "OPTIONAL MATCH (cons:RequestObservation)-[s:SENT_VALUE]->(v) "
        "RETURN count(DISTINCT v) AS vc, "
        "       collect(DISTINCT prod.concrete_path) AS produced, "
        "       collect(DISTINCT cons.concrete_path) AS consumed, "
        "       collect(DISTINCT s.parameter_name) AS params",
        eid=eid,
        uuid=LEAKED_UUID,
    )
    assert pivot[0]["vc"] == 1
    assert pivot[0]["produced"] == ["/widgets"]
    assert pivot[0]["consumed"] == ["/widget-detail"]
    assert pivot[0]["params"] == ["widget_id"]

    # Multiplicity (#15): the recurring account_id promotes to ONE ObservedValue
    # with a YIELDED_VALUE edge from each of /x and /y.
    recurring = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid})-[y:YIELDED_VALUE]->"
        "(v:ObservedValue {engagement_id: $eid, value: 'acct-recurring-7f3a'}) "
        "RETURN count(DISTINCT v) AS vc, count(y) AS edges",
        eid=eid,
    )
    assert recurring[0]["vc"] == 1
    assert recurring[0]["edges"] == 2

    # The solo account_id seen in a single observation does NOT promote.
    solo = neo4j_client.execute_read(
        "MATCH (v:ObservedValue {engagement_id: $eid, value: 'acct-solo-91bd'}) "
        "RETURN count(v) AS c",
        eid=eid,
    )
    assert solo[0]["c"] == 0

    # No ObservedValue for any list UUID id.
    list_ids = neo4j_client.execute_read(
        "MATCH (v:ObservedValue {engagement_id: $eid}) "
        "WHERE v.value CONTAINS '-0000-0000-0000-' RETURN count(v) AS c",
        eid=eid,
    )
    assert list_ids[0]["c"] == 0

    # value_hash dedup: shared.internal.example -> one ObservedValue, TWO
    # YIELDED_VALUE edges (one from /a, one from /b).
    shared = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid})-[y:YIELDED_VALUE]->"
        "(v:ObservedValue {engagement_id: $eid, value: 'shared.internal.example'}) "
        "RETURN count(DISTINCT v) AS vc, count(y) AS edges",
        eid=eid,
    )
    assert shared[0]["vc"] == 1
    assert shared[0]["edges"] == 2

    # The JWT promotes hash-only (ADR-0015): value null, hash + length + preview set.
    jwt = neo4j_client.execute_read(
        "MATCH (v:ObservedValue {engagement_id: $eid, kind: 'secret'}) "
        "RETURN v.value AS v, v.value_hash AS h, v.value_preview AS prev",
        eid=eid,
    )
    assert jwt and jwt[0]["v"] is None
    assert jwt[0]["h"] == hashlib.sha256(_JWT.encode()).hexdigest()
    assert jwt[0]["prev"] == _JWT[:8]

    # Every YIELDED_VALUE edge carries location + extractor and a matching engagement.
    edges = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid})-[y:YIELDED_VALUE]->"
        "(v:ObservedValue {engagement_id: $eid}) "
        "WHERE y.location IS NULL OR y.extractor IS NULL OR y.engagement_id <> $eid "
        "RETURN count(y) AS bad",
        eid=eid,
    )
    assert edges[0]["bad"] == 0

    # Fingerprint + error excerpt are inline RO properties, not nodes.
    fp = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid, concrete_path: '/session'}) "
        "RETURN r.server_fingerprint AS sf",
        eid=eid,
    )
    assert fp and fp[0]["sf"] == "nginx/1.21.6"
    err = neo4j_client.execute_read(
        "MATCH (r:RequestObservation {engagement_id: $eid, concrete_path: '/report'}) "
        "RETURN r.error_excerpt AS ee",
        eid=eid,
    )
    assert err and err[0]["ee"] and "internal-billing.corp.example" in err[0]["ee"]

    # The raw JWT lives in NO node property (only the MinIO blob).
    nodes = neo4j_client.execute_read(
        "MATCH (n {engagement_id: $eid}) RETURN properties(n) AS props", eid=eid
    )
    blob = json.dumps([n["props"] for n in nodes], default=str)
    assert _JWT not in blob


def test_observed_value_reingest_is_idempotent(
    neo4j_client, redis_client, blob_client
) -> None:
    eid = "eng-ov-idem"
    _seed_engagement(neo4j_client, eid)
    for _ in range(2):
        _run_pipeline(
            neo4j=neo4j_client,
            redis_client=redis_client,
            blob_client=blob_client,
            engagement_id=eid,
            har_bytes=_fixture_har(),
            filename="observed_values.har",
        )
    # Re-ingest adds no new ObservedValues or edges, and does not double-count the
    # multiplicity signal (the recurring account_id is still ONE node, 2 edges) nor
    # the leak-to-input pivot (LEAKED_UUID is still ONE node, 1 YIELDED + 1 SENT).
    assert _count(neo4j_client, "ObservedValue", eid) == 5
    yielded = neo4j_client.execute_read(
        "MATCH (:RequestObservation {engagement_id: $eid})-[y:YIELDED_VALUE]->"
        "(:ObservedValue {engagement_id: $eid}) RETURN count(y) AS c",
        eid=eid,
    )
    # billing(1) + shared(2) + jwt(1) + recurring(2) + leaked-uuid(2: json-walk id
    # field + uuid regex, two distinct locations on the /widgets response).
    assert yielded[0]["c"] == 8
    sent = neo4j_client.execute_read(
        "MATCH (:RequestObservation {engagement_id: $eid})-[s:SENT_VALUE]->"
        "(:ObservedValue {engagement_id: $eid}) RETURN count(s) AS c",
        eid=eid,
    )
    assert sent[0]["c"] == 1  # the single widget_id input occurrence (#16)
