"""Dispatch ledger — append-only sibling of the review ledger (ADR-0042/0040).

A dispatch run is an observability record (OTel span, structured log on
`trace_id`) plus a row here — `{engagement_id, run_id, actor, armed_at,
selection, budget, mode}` — and a per-`TestCase` `RunOutcome` per attempt. NOT a
graph node, for the same ADR-0040 reason: tester identity stays out of the
target model.

Same JSON-array shape as `JsonFileReviewLedger` (`planner/review.py`); the path
defaults to `~/.doo/dispatch_ledger.json`, overridable via
`DOO_DISPATCH_LEDGER_PATH`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from doo.dispatch.models import DispatchLedgerEvent, DispatchRun, RunOutcome
from doo.ids import DispatchRunId, EngagementId, TestCaseKeyHash
from doo.observability.logging import get_logger

log = get_logger(__name__)

# Sentinel `run_id` for engagement-scoped (not run-scoped) `override` events.
OVERRIDE_RUN_ID = DispatchRunId("_override")


class DispatchLedger(Protocol):
    """Append-only dispatch ledger keyed by `(engagement_id, run_id)`."""

    def append(self, event: DispatchLedgerEvent) -> None: ...

    def events_for(
        self, engagement_id: EngagementId, run_id: DispatchRunId
    ) -> list[DispatchLedgerEvent]: ...

    def all_for_engagement(
        self, engagement_id: EngagementId
    ) -> list[DispatchLedgerEvent]: ...


@dataclass(frozen=True, slots=True)
class JsonFileDispatchLedger:
    """JSON-file-backed append-only dispatch ledger (mirrors `JsonFileReviewLedger`)."""

    ledger_path: Path

    def _read_raw(self) -> list[dict[str, object]]:
        if not self.ledger_path.exists():
            return []
        try:
            data: list[dict[str, object]] = json.loads(self.ledger_path.read_text())
            return data
        except json.JSONDecodeError:
            log.warning(
                "dispatch_ledger.unreadable",
                path=str(self.ledger_path),
                action="treat_as_empty",
            )
            return []

    def append(self, event: DispatchLedgerEvent) -> None:
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        raw = self._read_raw()
        raw.append(event.model_dump(mode="json"))
        self.ledger_path.write_text(json.dumps(raw, indent=2))

    def events_for(
        self, engagement_id: EngagementId, run_id: DispatchRunId
    ) -> list[DispatchLedgerEvent]:
        return [
            DispatchLedgerEvent.model_validate(e)
            for e in self._read_raw()
            if e.get("engagement_id") == engagement_id and e.get("run_id") == run_id
        ]

    def all_for_engagement(
        self, engagement_id: EngagementId
    ) -> list[DispatchLedgerEvent]:
        return [
            DispatchLedgerEvent.model_validate(e)
            for e in self._read_raw()
            if e.get("engagement_id") == engagement_id
        ]


@dataclass
class InMemoryDispatchLedger:
    """In-memory `DispatchLedger` for tests and single-process runs."""

    events: list[DispatchLedgerEvent] = field(default_factory=list)

    def append(self, event: DispatchLedgerEvent) -> None:
        self.events.append(event)

    def events_for(
        self, engagement_id: EngagementId, run_id: DispatchRunId
    ) -> list[DispatchLedgerEvent]:
        return [
            e
            for e in self.events
            if e.engagement_id == engagement_id and e.run_id == run_id
        ]

    def all_for_engagement(
        self, engagement_id: EngagementId
    ) -> list[DispatchLedgerEvent]:
        return [e for e in self.events if e.engagement_id == engagement_id]


def record_armed(ledger: DispatchLedger, run: DispatchRun) -> None:
    """Append the `armed` ledger row for one dispatch run (ADR-0042)."""

    ledger.append(
        DispatchLedgerEvent(
            kind="armed",
            engagement_id=run.engagement_id,
            run_id=run.run_id,
            timestamp=run.armed_at,
            actor=run.actor,
            selection=run.selection,
            budget=run.budget,
            arming=run.arming,
            interpreter=run.interpreter,
            environment=run.environment,
        )
    )


def record_outcome(ledger: DispatchLedger, outcome: RunOutcome) -> None:
    """Append one per-`TestCase` `RunOutcome` row (ADR-0043)."""

    ledger.append(
        DispatchLedgerEvent(
            kind="outcome",
            engagement_id=outcome.engagement_id,
            run_id=outcome.run_id,
            timestamp=outcome.at,
            outcome=outcome,
        )
    )


def record_override(
    ledger: DispatchLedger,
    *,
    engagement_id: EngagementId,
    key_hash: TestCaseKeyHash,
    action: Literal["set_hint", "ignore_hazard"],
    hazard_kind: str,
    hint: str | None = None,
    now: datetime | None = None,
) -> None:
    """Append a `doo dispatch review` hazard override the next run reads (S5/#90)."""

    ledger.append(
        DispatchLedgerEvent(
            kind="override",
            engagement_id=engagement_id,
            run_id=OVERRIDE_RUN_ID,
            timestamp=now or datetime.now(UTC),
            key_hash=key_hash,
            override_action=action,
            hazard_kind=hazard_kind,
            hint=hint,
        )
    )


def resolve_overrides(
    ledger: DispatchLedger, engagement_id: EngagementId
) -> dict[tuple[str, str], DispatchLedgerEvent]:
    """Latest-wins `(key_hash, hazard_kind) → override` map for the engagement.

    Read once at run start; the run driver consults it before resolving each
    hazard (a `set_hint` supplies the `source_hint`; an `ignore_hazard` drops the
    hazard so the `primary` sends anyway).
    """

    out: dict[tuple[str, str], DispatchLedgerEvent] = {}
    for e in ledger.all_for_engagement(engagement_id):
        if e.kind == "override" and e.key_hash is not None and e.hazard_kind is not None:
            out[(str(e.key_hash), e.hazard_kind)] = e
    return out
