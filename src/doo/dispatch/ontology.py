"""Agent-send graph writes: `RequestObservation(source="agent")` + `EXECUTED_AS`.

An agent send is committed via the **same** `RequestObservation` shape as a
parsed observation (ADR-0006: agent traffic and passive traffic are one
observation set), with `source = "agent"` and full ADR-0005 cross-cutting
provenance. The `EXECUTED_AS` edge from the `TestCase` carries
`dispatch_status` + `request_role` + `run_id` (ADR-0013/0042/0043) so coverage
and audit can group sends by the run that authorised them.

Kept separate from `ontology/resolve.py` (the L2-ingest commit path) because the
agent send already knows its `AuthContext` and `Host` directly (no cue
resolution), and carries no parser-specific fields (`envelope_event_id`,
`value_candidates`). The node property names match `commit_request_observation`
so existing queries (`r.method`, `r.concrete_path`, `r.response_status`) read it
identically.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Protocol

from doo.canonical.identity import host_id
from doo.canonical.value_objects import BlobRef
from doo.dispatch.executor.send import HttpResponse
from doo.dispatch.models import ConcreteRequest, RequestRole
from doo.events.execution import DispatchStatus
from doo.ids import (
    AuthContextId,
    DispatchRunId,
    EngagementId,
    ObservationId,
    TestCaseKeyHash,
)
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger

log = get_logger(__name__)

AGENT_SOURCE = "agent"


class BodyStore(Protocol):
    """Minimal duck-type for the body-blob writer (ADR-0015).

    `infra.blobs.BlobClient.put_body` satisfies this. Tests inject an in-memory
    stub. The agent-send writer stores only the **response** body (the request
    body, if any, is the constructor's deterministic output and reconstructable).
    """

    def put_body(
        self, engagement_id: EngagementId, *, raw: bytes, content_type: str
    ) -> BlobRef: ...


class NoopBodyStore:
    """Body store that drops bodies (e2e / no-MinIO runs).

    The graph still records `response_status` + `response_size_bytes`; only the
    raw bytes are dropped. Used when `--no-bodies` or no blob client is
    configured.
    """

    def put_body(
        self, engagement_id: EngagementId, *, raw: bytes, content_type: str
    ) -> BlobRef | None:
        return None


def new_agent_observation_id() -> ObservationId:
    """A fresh agent-send observation id (per-send, not content-addressed).

    Agent sends are not idempotent the way parsed observations are: two `primary`
    sends in two runs are two distinct edges (ADR-0013: `EXECUTED_AS` is the
    per-execution record). So the id is a fresh uuid, not a content hash.
    """

    return ObservationId(f"agent-{uuid.uuid4().hex}")


def commit_agent_send(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    run_id: DispatchRunId,
    key_hash: TestCaseKeyHash,
    request: ConcreteRequest,
    response: HttpResponse | None,
    dispatch_status: DispatchStatus,
    role: RequestRole,
    auth_context_id: AuthContextId,
    bodies: BodyStore,
    now: datetime | None = None,
) -> ObservationId:
    """Commit one agent send: `RequestObservation(source="agent")` + `EXECUTED_AS`.

    The observation node carries the same property names as the L2-ingest path
    (`method`, `concrete_path`, `response_status`, …) so coverage queries read it
    identically. The `EXECUTED_AS` edge is the per-execution record (ADR-0013);
    it carries `dispatch_status` + `request_role` + `run_id` and the ADR-0005
    cross-cutting fields. `OBSERVED_UNDER` → the (known) `AuthContext` and
    `ON_HOST` → the (known) `Host` are wired directly — no cue resolution.

    A `dispatcher_blocked` send (no bytes left the process) writes **no**
    observation: there is nothing observed. The caller records that as a
    `RunOutcome` only.
    """

    run_at = now or datetime.now(UTC)
    obs_id = new_agent_observation_id()
    h_id = host_id(engagement_id, request.host)

    body_ref_json: str | None = None
    body_sha256: str | None = None
    response_status = response.status if response is not None else None
    response_size = len(response.body) if response is not None else 0
    duration_ms = response.duration_ms if response is not None else None
    if response is not None and response.body:
        ct = next(
            (v for k, v in response.headers if k.lower() == "content-type"),
            "application/octet-stream",
        )
        ref = bodies.put_body(engagement_id, raw=response.body, content_type=ct)
        if ref is not None:
            body_ref_json = ref.model_dump_json()
            body_sha256 = ref.sha256

    # Persist query/headers/cookies as `["name=value", …]` flat arrays (Neo4j has
    # no nested-map property type — same JSON-string discipline as
    # `graph_state.py`). Secret-shaped values (the spliced auth) are NOT written:
    # only the non-auth headers, plus the auth header NAME (so audit sees which
    # carrier was used) with the value redacted (ADR-0015).
    query = [f"{k}={v}" for k, v in request.query]
    headers = [
        f"{k}=<redacted>" if k.lower() in {"authorization", "x-api-key", "cookie"} else f"{k}={v}"
        for k, v in request.headers
    ]
    cookies = [f"{k}=<redacted>" for k, _ in request.cookies]

    client.execute_write(
        """
        MERGE (h:Host {engagement_id: $eid, id: $host_id})
        ON CREATE SET h.scheme = $scheme, h.canonical_hostname = $hostname,
                      h.port = $port, h.is_ip_literal = $is_ip,
                      h.source = 'agent', h.confidence = 1.0,
                      h.confidence_method = 'heuristic', h.status = 'active',
                      h.first_seen = $now, h.last_seen = $now, h.ingested_at = $now
        ON MATCH SET h.last_seen = $now
        WITH h
        MERGE (r:RequestObservation {engagement_id: $eid, observation_id: $obs_id})
        ON CREATE SET r.id = $obs_id, r.method = $method,
                      r.concrete_path = $path, r.query_string = $query_string,
                      r.query = $query_kv, r.headers = $headers, r.cookies = $cookies,
                      r.response_status = $response_status,
                      r.response_size_bytes = $response_size,
                      r.response_body_ref = $body_ref,
                      r.response_body_sha256 = $body_sha256,
                      r.duration_ms = $duration_ms,
                      r.source = $source, r.source_id = $run_id,
                      r.confidence = 1.0, r.confidence_method = 'heuristic',
                      r.first_seen = $now, r.last_seen = $now,
                      r.ingested_at = $now, r.status = 'active'
        MERGE (r)-[:ON_HOST]->(h)
        WITH r
        MATCH (ac:AuthContext {engagement_id: $eid, id: $auth_context_id})
        MERGE (r)-[:OBSERVED_UNDER]->(ac)
        WITH r
        MATCH (t:TestCase {engagement_id: $eid, key_hash: $key_hash})
        MERGE (t)-[x:EXECUTED_AS {run_id: $run_id, request_role: $role}]->(r)
        ON CREATE SET x.dispatch_status = $dispatch_status,
                      x.engagement_id = $eid,
                      x.at = $now,
                      x.source = $source, x.source_id = $run_id,
                      x.confidence = 1.0, x.confidence_method = 'heuristic',
                      x.first_seen = $now, x.last_seen = $now,
                      x.ingested_at = $now, x.status = 'active'
        RETURN r.id AS id
        """,
        eid=engagement_id,
        host_id=h_id,
        scheme=request.host.scheme,
        hostname=request.host.canonical_hostname,
        port=request.host.port,
        is_ip=request.host.is_ip_literal,
        obs_id=obs_id,
        method=request.method,
        path=request.path,
        query_string="&".join(query) if query else None,
        # `query` collides with neo4j `tx.run(query, …)`; bound as `query_kv`.
        query_kv=query,
        headers=headers,
        cookies=cookies,
        response_status=response_status,
        response_size=response_size,
        body_ref=body_ref_json,
        body_sha256=body_sha256,
        duration_ms=duration_ms,
        source=AGENT_SOURCE,
        run_id=run_id,
        auth_context_id=str(auth_context_id),
        key_hash=key_hash,
        role=role,
        dispatch_status=dispatch_status,
        now=run_at,
    )
    log.info(
        "dispatch.executed_as.commit",
        engagement_id=engagement_id,
        run_id=run_id,
        key_hash=key_hash,
        role=role,
        dispatch_status=dispatch_status,
        observation_id=obs_id,
    )
    return obs_id
