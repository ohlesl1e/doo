"""L3 commit worker (slice-1 T2).

Consumes `l2-events`, validates each into an `L2Event`, and runs the
`CommitOrchestrator` (semantic-key idempotency + engagement-scoping gate + Neo4j
writes + `l3-events` emission). A thin loop around the orchestrator;
`process_l2_event` is the unit-testable core.

The worker runs the schema bootstrap once at startup (edition-aware; see
`apply_schema`). `trace_id` propagates from the L2 event into the L3 events the
orchestrator emits.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from doo.events.l2 import L2Event
from doo.infra.streams import L2_EVENTS_STREAM, StreamClient
from doo.observability.logging import get_logger
from doo.ontology.commit import CommitOrchestrator, CommitResult

log = get_logger(__name__)

L3_CONSUMER_GROUP = "l3-commit"


@dataclass(frozen=True, slots=True)
class L3WorkerDeps:
    """Injected collaborators for the L3 worker."""

    orchestrator: CommitOrchestrator
    streams: StreamClient


def process_l2_event(deps: L3WorkerDeps, event: L2Event) -> CommitResult:
    """Commit one L2 event via the orchestrator."""

    return deps.orchestrator.commit(event)


def run_l3_worker(
    deps: L3WorkerDeps,
    *,
    consumer_name: str = "l3-1",
    max_messages: int | None = None,
    block_ms: int = 1000,
    on_event: Callable[[], None] | None = None,
) -> int:
    """Consume `l2-events` and commit until `max_messages` (or forever).

    Returns the number of messages processed. `on_event`, when given, is invoked
    once per committed event (after the ack) — the per-event progress hook the
    `doo worker run` progress bar advances on (mirrors `run_l2_worker`'s
    `on_events`). It must not raise.
    """

    deps.streams.ensure_group(L2_EVENTS_STREAM, L3_CONSUMER_GROUP)
    processed = 0
    while max_messages is None or processed < max_messages:
        got_any = False
        for message_id, payload in deps.streams.read_group(
            L2_EVENTS_STREAM, L3_CONSUMER_GROUP, consumer_name, block_ms=block_ms
        ):
            got_any = True
            event: L2Event = _validate_l2_event(payload)
            process_l2_event(deps, event)
            deps.streams.ack(L2_EVENTS_STREAM, L3_CONSUMER_GROUP, message_id)
            processed += 1
            if on_event is not None:
                on_event()
        # `max_messages` is checked at the batch boundary (the `while` head), never
        # mid-batch: breaking inside the loop would leave the rest of an already-
        # delivered read batch unacked, stranding it in the consumer PEL.
        if not got_any and max_messages is not None:
            break
    return processed


def _validate_l2_event(payload: dict[str, object]) -> L2Event:
    """Validate a raw stream payload into the discriminated `L2Event` union.

    Validates via JSON so str-encoded datetime fields coerce under the strict
    model config (dict-mode strict validation would reject them).
    """

    import json

    from pydantic import TypeAdapter

    return TypeAdapter(L2Event).validate_json(json.dumps(payload))
