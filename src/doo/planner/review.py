"""Review lifecycle + append-only audit ledger (ADR-0040).

Human review moves a committed `TestCase` `proposed -> approved | rejected`. The
*decision* is a provenanced **append-only ledger event** keyed by
`(engagement_id, key_hash)` — `{actor, timestamp, decision, reason, disposition,
prior_status -> new_status}` plus an evidence snapshot for the re-surface predicate.
Tester identity lives only on the ledger (and as denormalised node fields), never
as a graph node (ADR-0012). The `TestCase` node carries the *denormalised current*
state: `review_status` + `reviewed_by` / `reviewed_at` / `review_reason`.

`approved` is **"cleared for dispatch consideration", not authorisation** (ADR-0040):
slice-4 dispatch needs a fresh, mode-gated gate. Rejected nodes are **kept**
(`review_status = rejected`) so the planner does not re-surface them and the audit
trail survives. The ledger is the audit/observability substrate, not Neo4j — here a
JSON-file store mirroring the engagement ledger (`setup.loader.JsonFileLedger`).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from doo.ids import EngagementId, TestCaseKeyHash
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
from doo.ontology.queries import for_engagement
from doo.planner.models import (
    Disposition,
    ReviewDecision,
    ReviewLedgerEvent,
    ReviewStatus,
)

log = get_logger(__name__)


class ReviewLedger(Protocol):
    """Append-only review-decision ledger keyed by `(engagement_id, key_hash)`."""

    def append(self, event: ReviewLedgerEvent) -> None: ...

    def events_for(
        self, engagement_id: EngagementId, key_hash: TestCaseKeyHash
    ) -> list[ReviewLedgerEvent]: ...

    def latest_for(
        self, engagement_id: EngagementId, key_hash: TestCaseKeyHash
    ) -> ReviewLedgerEvent | None: ...


@dataclass(frozen=True, slots=True)
class JsonFileReviewLedger:
    """JSON-file-backed append-only review ledger (mirrors `JsonFileLedger`).

    One JSON array of serialised `ReviewLedgerEvent`s, append-only and ordered by
    write. Keyed reads filter by `(engagement_id, key_hash)`. The path is
    overridable (tests / scripted runs); the default is `~/.doo/review_ledger.json`.
    """

    ledger_path: Path

    def _read_raw(self) -> list[dict[str, object]]:
        if not self.ledger_path.exists():
            return []
        try:
            data: list[dict[str, object]] = json.loads(self.ledger_path.read_text())
            return data
        except json.JSONDecodeError:
            log.warning(
                "review_ledger.unreadable",
                path=str(self.ledger_path),
                action="treat_as_empty",
            )
            return []

    def append(self, event: ReviewLedgerEvent) -> None:
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        raw = self._read_raw()
        raw.append(event.model_dump(mode="json"))
        self.ledger_path.write_text(json.dumps(raw, indent=2))

    def events_for(
        self, engagement_id: EngagementId, key_hash: TestCaseKeyHash
    ) -> list[ReviewLedgerEvent]:
        return [
            ReviewLedgerEvent.model_validate(e)
            for e in self._read_raw()
            if e.get("engagement_id") == engagement_id
            and e.get("key_hash") == key_hash
        ]

    def latest_for(
        self, engagement_id: EngagementId, key_hash: TestCaseKeyHash
    ) -> ReviewLedgerEvent | None:
        events = self.events_for(engagement_id, key_hash)
        return events[-1] if events else None


class InMemoryReviewLedger:
    """In-memory `ReviewLedger` for tests and single-process runs."""

    def __init__(self) -> None:
        self._events: list[ReviewLedgerEvent] = []

    def append(self, event: ReviewLedgerEvent) -> None:
        self._events.append(event)

    def events_for(
        self, engagement_id: EngagementId, key_hash: TestCaseKeyHash
    ) -> list[ReviewLedgerEvent]:
        return [
            e
            for e in self._events
            if e.engagement_id == engagement_id and e.key_hash == key_hash
        ]

    def latest_for(
        self, engagement_id: EngagementId, key_hash: TestCaseKeyHash
    ) -> ReviewLedgerEvent | None:
        events = self.events_for(engagement_id, key_hash)
        return events[-1] if events else None


class ReviewError(Exception):
    """An illegal review transition or an unknown / inactive target `TestCase`."""


_DECISION_TO_STATUS: dict[ReviewDecision, ReviewStatus] = {
    "approve": "approved",
    "reject": "rejected",
}


@dataclass(frozen=True, slots=True)
class TargetEvidence:
    """The current evidence snapshot of a `TestCase`'s target (ADR-0040).

    `effective_confidence` is the decayed target inference confidence at decision
    time; `derived_from_count` is the count of `DERIVED_FROM` edges feeding the
    target/boundary. Snapshotted onto a reject ledger event so the re-surface
    predicate can later detect a material change.
    """

    effective_confidence: float
    derived_from_count: int


def _fetch_review_state(
    client: Neo4jClient, engagement_id: EngagementId, key_hash: TestCaseKeyHash
) -> str | None:
    frag = for_engagement(engagement_id, var="t")
    rows = client.execute_read(
        f"""
        MATCH (t:TestCase {{key_hash: $key_hash}})
        {frag.and_("t.status = 'active'")}
        RETURN t.review_status AS review_status
        """,
        key_hash=key_hash,
        **frag.parameters,
    )
    if not rows:
        return None
    return str(rows[0]["review_status"])


@dataclass(frozen=True, slots=True)
class ReviewResult:
    """Outcome of one review decision: the recorded ledger event + new status."""

    event: ReviewLedgerEvent
    prior_status: ReviewStatus
    new_status: ReviewStatus


def review_testcase(
    client: Neo4jClient,
    ledger: ReviewLedger,
    *,
    engagement_id: EngagementId,
    key_hash: TestCaseKeyHash,
    decision: ReviewDecision,
    actor: str,
    reason: str | None = None,
    disposition: Disposition | None = None,
    evidence: TargetEvidence,
    now: datetime | None = None,
) -> ReviewResult:
    """Apply one review decision: append a ledger event + denormalise onto the node.

    Enforces the lifecycle (ADR-0040): the node must exist and be active; only a
    `proposed` test can be approved or rejected (a re-decide of an already-reviewed
    test is an explicit transition the CLI exposes, but the spine treats the
    proposed-state as the gate). A `reject` requires a `disposition` (default
    `defer` is applied by the caller/CLI, never silently here). The decision is
    recorded as an append-only ledger event keyed by `(engagement_id, key_hash)`;
    the node gets only the denormalised current `review_status` + `reviewed_by` /
    `reviewed_at` / `review_reason`.

    `approved` means "cleared for dispatch *consideration*", not authorisation — no
    dispatch happens in slice 3 (ADR-0040).
    """

    run_at = now or datetime.now(UTC)
    prior = _fetch_review_state(client, engagement_id, key_hash)
    if prior is None:
        raise ReviewError(
            f"no active TestCase {key_hash!r} in engagement {engagement_id!r}"
        )
    prior_status: ReviewStatus = prior  # type: ignore[assignment]

    if decision == "reject" and disposition is None:
        raise ReviewError("a reject decision requires a disposition (permanent|defer)")
    if decision == "approve" and disposition is not None:
        raise ReviewError("an approve decision carries no disposition")

    new_status = _DECISION_TO_STATUS[decision]

    event = ReviewLedgerEvent(
        engagement_id=engagement_id,
        key_hash=key_hash,
        actor=actor,
        timestamp=run_at,
        decision=decision,
        reason=reason,
        disposition=disposition,
        prior_status=prior_status,
        new_status=new_status,
        evidence_confidence=evidence.effective_confidence,
        evidence_derived_from_count=evidence.derived_from_count,
    )

    # Denormalise the current decision onto the node (ADR-0040). The full history
    # (incl. approve-then-rescind) is the ledger's; the node holds latest only.
    frag = for_engagement(engagement_id, var="t")
    client.execute_write(
        f"""
        MATCH (t:TestCase {{key_hash: $key_hash}})
        {frag.and_("t.status = 'active'")}
        SET t.review_status = $new_status,
            t.reviewed_by = $actor,
            t.reviewed_at = $now,
            t.review_reason = $reason,
            t.review_disposition = $disposition,
            t.last_seen = $now
        """,
        key_hash=key_hash,
        new_status=new_status,
        actor=actor,
        now=run_at,
        reason=reason,
        disposition=disposition,
        **frag.parameters,
    )

    ledger.append(event)
    log.info(
        "planner.review.recorded",
        engagement_id=engagement_id,
        key_hash=key_hash,
        actor=actor,
        decision=decision,
        disposition=disposition,
        prior_status=prior_status,
        new_status=new_status,
    )
    return ReviewResult(
        event=event, prior_status=prior_status, new_status=new_status
    )


def fetch_target_evidence(
    client: Neo4jClient,
    engagement_id: EngagementId,
    key_hash: TestCaseKeyHash,
    *,
    now: datetime | None = None,
) -> TargetEvidence:
    """Snapshot the target's effective confidence + `DERIVED_FROM` count (ADR-0040).

    Reads the `TestCase`'s XOR target (Endpoint for the S1 spine), decays its stored
    confidence (ADR-0005), and counts the `DERIVED_FROM` evidence edges feeding it.
    Used to stamp a reject event and to evaluate the re-surface predicate later.
    """

    from doo.coverage.decay import effective_confidence
    from doo.coverage.queries import _to_aware

    run_at = now or datetime.now(UTC)
    frag = for_engagement(engagement_id, var="t")
    rows = client.execute_read(
        f"""
        MATCH (t:TestCase {{key_hash: $key_hash}})
        {frag.and_("t.status = 'active'")}
        OPTIONAL MATCH (t)-[:TARGETS_ENDPOINT]->(e:Endpoint)
        OPTIONAL MATCH (t)-[:TARGETS_PARAMETER]->(p:Parameter)
        OPTIONAL MATCH (t)-[:TARGETS_BOUNDARY]->(b:TrustBoundary)
        WITH coalesce(e, p, b) AS target
        RETURN target.confidence AS confidence,
               target.last_seen AS last_seen,
               COUNT {{ (target)-[:DERIVED_FROM]->() }} AS derived_from_count
        """,
        key_hash=key_hash,
        **frag.parameters,
    )
    if not rows or rows[0]["confidence"] is None:
        # No resolvable target confidence (e.g. an endpoint with no stored
        # confidence) — treat as full confidence, zero evidence edges.
        return TargetEvidence(effective_confidence=1.0, derived_from_count=0)
    row = rows[0]
    stored = float(row["confidence"])
    last_seen = _to_aware(row["last_seen"], fallback=run_at)
    eff = effective_confidence(stored, last_seen, now=run_at)
    derived = int(row["derived_from_count"]) if row["derived_from_count"] is not None else 0
    return TargetEvidence(effective_confidence=eff, derived_from_count=derived)
