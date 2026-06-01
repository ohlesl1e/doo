"""trace_id propagates unchanged across L1 -> L2 -> L3 (ADR-0018).

Drives the pipeline with in-memory fakes (no docker) and captures structlog
events to assert the same `trace_id` rides every layer's log lines. The
intake-side `trace_id` is the one that must appear in L2 and L3 log records.
"""

from __future__ import annotations

import json
from typing import Any

import structlog
from structlog.contextvars import merge_contextvars

from doo.events.envelope import IngestionEnvelope
from doo.events.l2 import L2Event
from doo.ids import BlobKey, EngagementId
from doo.ingestion.intake import IntakeDeps, ingest_har
from doo.ingestion.l2_worker import L2WorkerDeps, process_envelope
from doo.ontology.commit import CommitOrchestrator
from tests.fixtures import ANON_HAR

ENG = "eng-trace"


class _Engagements:
    def engagement_exists(self, engagement_id: EngagementId) -> bool:
        return engagement_id == ENG


class _Blobs:
    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    def put_har(self, engagement_id, blob_sha256, data):  # type: ignore[no-untyped-def]
        key = BlobKey(f"engagement/{engagement_id}/source/har/{blob_sha256}.har")
        self.store[str(key)] = data
        return key

    def get(self, key: BlobKey) -> bytes:
        return self.store[str(key)]


class _Streams:
    def __init__(self) -> None:
        self.by_stream: dict[str, list[dict[str, object]]] = {}

    def publish(self, stream: str, payload: dict[str, object]) -> str:
        self.by_stream.setdefault(stream, []).append(payload)
        return f"0-{len(self.by_stream[stream])}"


class _Neo4j:
    def execute_write(self, cypher: str, **params: object) -> list[dict[str, object]]:
        return []


class _Idem:
    def claim(self, key: str) -> bool:
        return True


def _install_capturing_logger() -> list[dict[str, Any]]:
    """Configure structlog to capture event dicts *with merged contextvars*.

    `structlog.testing.capture_logs` bypasses the processor chain, so it never
    sees the contextvars-bound `trace_id`. We install a chain that runs
    `merge_contextvars` (which surfaces the bound correlation ids) and then
    appends the resulting event dict to a list.
    """

    captured: list[dict[str, Any]] = []

    def _sink(_logger: object, _name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
        captured.append(dict(event_dict))
        raise structlog.DropEvent

    structlog.configure(
        processors=[merge_contextvars, _sink],
        wrapper_class=structlog.make_filtering_bound_logger(0),
        context_class=dict,
        logger_factory=structlog.ReturnLoggerFactory(),
        cache_logger_on_first_use=False,
    )
    return captured


def test_trace_id_rides_l1_l2_l3_log_lines() -> None:
    import doo.ingestion.intake as intake_mod
    import doo.ingestion.l2_worker as l2_mod
    import doo.ontology.commit as commit_mod
    from doo.observability.logging import get_logger

    blobs = _Blobs()
    streams = _Streams()

    logs = _install_capturing_logger()
    # Re-bind the module-level loggers so they pick up the capturing config even
    # if an earlier test cached them against a different processor chain
    # (structlog caches bound loggers on first use per module).
    intake_mod.log = get_logger("doo.ingestion.intake")
    l2_mod.log = get_logger("doo.ingestion.l2_worker")
    commit_mod.log = get_logger("doo.ontology.commit")
    try:
        # --- L1 intake ---
        intake = IntakeDeps(engagements=_Engagements(), blobs=blobs, streams=streams)
        result = ingest_har(
            intake,
            engagement_id=EngagementId(ENG),
            filename="anon_burp.har",
            data=ANON_HAR.read_bytes(),
        )
        trace_id = result.trace_id

        # --- L2 worker ---
        envelope = IngestionEnvelope.model_validate_json(
            json.dumps(streams.by_stream["ingest"][0])
        )
        process_envelope(L2WorkerDeps(blobs=blobs, streams=streams), envelope)  # type: ignore[arg-type]

        # --- L3 commit ---
        orch = CommitOrchestrator(
            neo4j=_Neo4j(),  # type: ignore[arg-type]
            idempotency=_Idem(),
            streams=streams,  # type: ignore[arg-type]
            expected_engagement_id=EngagementId(ENG),
        )
        from pydantic import TypeAdapter

        for payload in streams.by_stream["l2-events"]:
            event = TypeAdapter(L2Event).validate_json(json.dumps(payload))
            orch.commit(event)
    finally:
        structlog.reset_defaults()
        from doo.observability.logging import clear_correlation

        clear_correlation()

    # Find log events from each layer and assert the same trace_id.
    l1 = [e for e in logs if e.get("event") == "intake.har.accepted"]
    l2 = [e for e in logs if e.get("event") == "l2.envelope_processed"]
    l3 = [e for e in logs if e.get("event") == "commit.applied"]

    assert l1 and l2 and l3, (len(l1), len(l2), len(l3))
    assert all(e["trace_id"] == trace_id for e in l1)
    assert all(e["trace_id"] == trace_id for e in l2)
    assert all(e["trace_id"] == trace_id for e in l3)

    # And the envelope on the wire carried that same trace_id (the chain root).
    assert streams.by_stream["ingest"][0]["trace_id"] == trace_id
