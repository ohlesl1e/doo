"""Regression: a worker must not strand a partially-consumed read batch.

When `max_messages` is reached mid-batch, the rest of the already-delivered
Redis batch must still be acked — otherwise those messages sit unacked in the
consumer PEL forever and are silently lost (this bit a 2,000-entry HAR: 36 of
2,000 observations went missing). The bound is checked at the batch boundary,
never inside the loop.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from doo.events.l2 import ParseFailure
from doo.ids import EngagementId, L2EventId, ObservationId, SourceId
from doo.ontology.l3_worker import L3WorkerDeps, run_l3_worker


def _parse_failure_payload(i: int) -> dict[str, object]:
    pf = ParseFailure(
        event_id=L2EventId(f"{i:032x}"),
        trace_id="a" * 32,  # type: ignore[arg-type]
        span_id="b" * 16,  # type: ignore[arg-type]
        engagement_id=EngagementId("eng-x"),
        envelope_event_id=uuid4(),
        source="har",
        source_id=SourceId(f"{i}|t"),
        ingested_at=datetime.now(UTC),
        observed_at=datetime.now(UTC),
        confidence=1.0,
        observation_id=ObservationId(f"eng-x:har:pf:{i}"),
        error_kind="decode_error",
        error_message="bad",
        location_hint="log",
    )
    return pf.model_dump(mode="json")


class _FakeStream:
    """Returns one batch of 5 messages, then nothing; records acks."""

    def __init__(self, batch: list[tuple[str, dict[str, object]]]) -> None:
        self._batches = [batch]
        self.acked: list[str] = []

    def ensure_group(self, stream: str, group: str) -> None:
        pass

    def read_group(self, stream: str, group: str, consumer: str, *, block_ms: int):  # type: ignore[no-untyped-def]
        return self._batches.pop(0) if self._batches else []


    def ack(self, stream: str, group: str, message_id: str) -> None:
        self.acked.append(message_id)


class _FakeOrchestrator:
    def __init__(self) -> None:
        self.committed = 0

    def commit(self, event: object) -> None:
        self.committed += 1


def test_run_l3_worker_acks_the_whole_batch_past_max_messages() -> None:
    batch = [(f"0-{i}", _parse_failure_payload(i)) for i in range(5)]
    stream = _FakeStream(batch)
    deps = L3WorkerDeps(
        orchestrator=_FakeOrchestrator(),  # type: ignore[arg-type]
        streams=stream,  # type: ignore[arg-type]
    )

    processed = run_l3_worker(deps, max_messages=2, block_ms=0)

    # The whole delivered batch of 5 is acked + committed, even though
    # max_messages was 2 — nothing left stranded in the PEL.
    assert len(stream.acked) == 5
    assert processed == 5


def test_run_l3_worker_invokes_on_event_per_committed_event() -> None:
    batch = [(f"0-{i}", _parse_failure_payload(i)) for i in range(5)]
    stream = _FakeStream(batch)
    deps = L3WorkerDeps(
        orchestrator=_FakeOrchestrator(),  # type: ignore[arg-type]
        streams=stream,  # type: ignore[arg-type]
    )
    ticks: list[int] = []

    processed = run_l3_worker(
        deps, max_messages=2, block_ms=0, on_event=lambda: ticks.append(1)
    )

    # The progress hook fires exactly once per committed event (the worker
    # progress bar advances on it).
    assert processed == 5
    assert len(ticks) == 5
