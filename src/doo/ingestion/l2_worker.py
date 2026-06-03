"""L2 extraction worker (slice-1 T2).

Consumes the `ingest` stream, fetches the referenced blob from object storage,
dispatches to the parser registry by `(source, blob_format)`, and pushes the
resulting `L2Event`s onto `l2-events`. Parser exceptions are wrapped as
`ParseFailure` events with the envelope back-ref — the worker never crashes on
bad input (CONTEXT.md ParseFailure; ARCHITECTURE.md L2 contract).

`trace_id` propagates unchanged from the envelope into every emitted L2 event
(ADR-0018). The worker is a thin loop; `process_envelope` is the unit-testable
core (no stream, no loop).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from doo.events.envelope import IngestionEnvelope
from doo.events.l2 import L2Event, ParseFailure
from doo.extraction.registry import UnknownParserError, get_parser
from doo.ids import BlobKey, ObservationId, SourceId
from doo.infra.blobs import BlobClient
from doo.infra.streams import INGEST_STREAM, L2_EVENTS_STREAM, StreamClient
from doo.observability.ids import new_span_id
from doo.observability.logging import bind_correlation, get_logger

log = get_logger(__name__)

L2_CONSUMER_GROUP = "l2-extraction"


class BlobFetcher:
    """Duck-type adapter so `process_envelope` can take any blob source."""

    def get(self, key: BlobKey) -> bytes:  # pragma: no cover - protocol-ish
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class L2WorkerDeps:
    """Injected collaborators for the L2 worker."""

    blobs: BlobClient
    streams: StreamClient


def process_envelope(deps: L2WorkerDeps, envelope: IngestionEnvelope) -> list[L2Event]:
    """Fetch the blob, parse it, publish L2 events; return them (for tests).

    Never raises on bad blob content — a parse problem becomes a `ParseFailure`
    event. Infrastructure errors (blob fetch failure) DO raise, since those mean
    the message should be retried, not turned into a domain ParseFailure.
    """

    bind_correlation(
        trace_id=envelope.trace_id,
        span_id=new_span_id(),
        engagement_id=envelope.engagement_id,
    )
    blob = deps.blobs.get(BlobKey(envelope.blob_ref))

    try:
        parser = get_parser(envelope.source, envelope.blob_format)
    except UnknownParserError as exc:
        log.warning(
            "l2.no_parser", source=envelope.source, blob_format=envelope.blob_format
        )
        events: list[L2Event] = [_whole_blob_failure(envelope, str(exc))]
        _publish(deps.streams, events)
        return events

    events = []
    try:
        # The BlobClient doubles as the T5 body uploader: bodies stream into
        # object storage during parse, the graph sees only the BlobRef.
        for event in parser(blob, envelope, deps.blobs):
            events.append(event)
    except Exception as exc:  # noqa: BLE001 - parser robustness backstop
        # The parser is supposed to emit ParseFailures internally, but if it
        # raises anyway we still must not crash the worker.
        log.warning("l2.parser_raised", error=repr(exc))
        events.append(_whole_blob_failure(envelope, f"parser raised: {exc}"))

    _publish(deps.streams, events)
    log.info(
        "l2.envelope_processed",
        event_count=len(events),
        parse_failures=sum(1 for e in events if isinstance(e, ParseFailure)),
    )
    return events


def _publish(streams: StreamClient, events: Iterable[L2Event]) -> None:
    for event in events:
        streams.publish(L2_EVENTS_STREAM, event.model_dump(mode="json"))


def _whole_blob_failure(envelope: IngestionEnvelope, message: str) -> ParseFailure:
    now = datetime.now(UTC)
    source_id = SourceId("blob|<unparsed>")
    return ParseFailure(
        event_id=new_span_id() + new_span_id(),  # type: ignore[arg-type]
        trace_id=envelope.trace_id,
        span_id=new_span_id(),
        engagement_id=envelope.engagement_id,
        envelope_event_id=envelope.event_id,
        source=envelope.source,
        source_id=source_id,
        ingested_at=now,
        observed_at=now,
        confidence=1.0,
        observation_id=ObservationId(
            f"{envelope.engagement_id}:{envelope.source}:parse_failure:{source_id}"
        ),
        error_kind="malformed_blob",
        error_message=message,
        location_hint="log",
    )


def run_l2_worker(
    deps: L2WorkerDeps,
    *,
    consumer_name: str = "l2-1",
    max_messages: int | None = None,
    block_ms: int = 1000,
    on_events: Callable[[list[L2Event]], None] | None = None,
) -> int:
    """Consume `ingest` and process envelopes until `max_messages` (or forever).

    Returns the number of messages processed. `max_messages` bounds the loop for
    tests / one-shot CLI drains; `None` runs indefinitely. `on_events`, when
    given, is called with each envelope's emitted `L2Event`s (so callers can,
    e.g., surface `ParseFailure`s) — invoked before the message is acked.
    """

    deps.streams.ensure_group(INGEST_STREAM, L2_CONSUMER_GROUP)
    processed = 0
    while max_messages is None or processed < max_messages:
        got_any = False
        for message_id, payload in deps.streams.read_group(
            INGEST_STREAM, L2_CONSUMER_GROUP, consumer_name, block_ms=block_ms
        ):
            got_any = True
            # Validate from JSON so str-encoded UUID / datetime fields coerce
            # under the envelope's strict config (dict-mode strict would reject).
            envelope = IngestionEnvelope.model_validate_json(json.dumps(payload))
            events = process_envelope(deps, envelope)
            if on_events is not None:
                on_events(events)
            deps.streams.ack(INGEST_STREAM, L2_CONSUMER_GROUP, message_id)
            processed += 1
        # `max_messages` is checked at the batch boundary (the `while` head), never
        # mid-batch: breaking inside the loop would leave the rest of an already-
        # delivered read batch unacked, stranding it in the consumer PEL.
        if not got_any and max_messages is not None:
            # No more messages within the block window; stop draining.
            break
    return processed
