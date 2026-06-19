"""Verdict writer + `Finding` commit + finding ledger (ADR-0045).

Deterministic code records the `InterpreterVerdict` on the **TestCase** (the
fourth orthogonal axis: `interpreter_verdict` / `interpreted_at` /
`interpreter_justification`, denormalised like `review_status`). On
`verdict = vulnerable`, commits a `Finding` at `finding_status = proposed` with
`source = "llm-interpreter"`, `confidence_method = "llm-self-reported"`,
`REFERENCES → TestCase`, `AFFECTS → target`, `DERIVED_FROM → evidence
observations`.

`Finding` identity is content-addressed but **soft** (ADR-0045): `finding_key =
sha256(engagement_id, vuln_category, primary_affected_id)` for commit-time dedup
(two TestCases proving the same IDOR add `REFERENCES` edges to one Finding); a
human-driven merge/split uses `status = retracted` + `MERGED_INTO`. The hash is a
dedup convenience, not an identity prison.

The finding ledger is a sibling of the review and dispatch ledgers (ADR-0040
shape: `{actor, timestamp, decision, reason}`, tester identity out of the graph).
Only `confirmed` Findings feed reporting; `disclosure_status` is reserved at
`unreported` (transitions ship with the reporting tracer).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from doo import __version__
from doo.dispatch.executor.evidence import DispatchTestCase
from doo.dispatch.interpreter.models import InterpreterVerdict
from doo.ids import (
    DispatchRunId,
    EngagementId,
    FindingId,
    ObservationId,
    TestCaseKeyHash,
)
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
from doo.ontology.queries import for_engagement

log = get_logger(__name__)

LLM_INTERPRETER_SOURCE = "llm-interpreter"

FindingStatus = Literal["proposed", "confirmed", "rejected"]
FindingDecision = Literal["confirm", "reject"]


# ---------------------------------------------------------------------------
# 4th-axis verdict writer (ADR-0045).
# ---------------------------------------------------------------------------


def record_verdict(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    key_hash: TestCaseKeyHash,
    verdict: InterpreterVerdict,
    run_id: DispatchRunId,
    transcript_key: str | None,
    now: datetime | None = None,
) -> None:
    """Denormalise the verdict onto the `TestCase` node (the 4th orthogonal axis).

    `interpreter_verdict` / `interpreted_at` / `interpreter_justification` /
    `interpreter_run_id` / `interpreter_transcript_key`. The full verdict (incl.
    `evidence_refs`) lives in the dispatch ledger keyed by `(run_id, key_hash)`
    (ADR-0045 consequence); the node holds the latest only, like `review_status`.
    """

    run_at = now or datetime.now(UTC)
    frag = for_engagement(engagement_id, var="t")
    client.execute_write(
        f"""
        MATCH (t:TestCase {{key_hash: $key_hash}})
        {frag.and_("t.status = 'active'")}
        SET t.interpreter_verdict = $verdict,
            t.interpreted_at = $now,
            t.interpreter_justification = $justification,
            t.interpreter_run_id = $run_id,
            t.interpreter_transcript_key = $transcript_key,
            t.last_seen = $now
        """,
        key_hash=key_hash,
        verdict=verdict.verdict,
        justification=verdict.justification,
        run_id=run_id,
        transcript_key=transcript_key,
        now=run_at,
        **frag.parameters,
    )
    log.info(
        "interpreter.verdict.recorded",
        engagement_id=engagement_id,
        key_hash=key_hash,
        verdict=verdict.verdict,
        run_id=run_id,
    )


# ---------------------------------------------------------------------------
# Finding identity + commit (ADR-0045).
# ---------------------------------------------------------------------------


def compute_finding_key(
    *,
    engagement_id: EngagementId,
    vuln_category: str,
    primary_affected_id: str,
) -> FindingId:
    """Soft content-addressed `finding_key` (ADR-0045): commit-time dedup, not
    an identity prison. Two TestCases proving the same `(category, affected)` →
    one Finding."""

    canonical = "|".join([engagement_id, vuln_category, primary_affected_id])
    return FindingId(hashlib.sha256(canonical.encode("utf-8")).hexdigest())


@dataclass(frozen=True, slots=True)
class FindingCommitOutcome:
    """Outcome of committing a `vulnerable` verdict as a `Finding`."""

    finding_key: FindingId
    created: bool
    finding_status: str


def _primary_affected(testcase: DispatchTestCase) -> tuple[str, str]:
    """The (label, node_id) of the TestCase's XOR target — the `AFFECTS` endpoint."""

    if testcase.target_endpoint_id is not None:
        return "Endpoint", testcase.target_endpoint_id
    if testcase.target_trust_boundary_id is not None:
        return "TrustBoundary", testcase.target_trust_boundary_id
    assert testcase.target_parameter_id is not None
    return "Parameter", testcase.target_parameter_id


def commit_finding(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    testcase: DispatchTestCase,
    verdict: InterpreterVerdict,
    run_id: DispatchRunId,
    transcript_key: str | None,
    now: datetime | None = None,
) -> FindingCommitOutcome:
    """Commit a `Finding@proposed` for a `vulnerable` verdict (ADR-0045).

    `MERGE` on `(engagement_id, finding_key)` makes a second TestCase proving the
    same `(category, affected)` add a `REFERENCES` edge rather than minting a new
    node. `finding_status = proposed`, `disclosure_status = unreported` (reserved),
    standard `status = active` (the merge-lineage axis). On a re-commit
    (`created = False`), `last_seen` bumps and the new `REFERENCES` /
    `DERIVED_FROM` edges are added; `finding_status` is **never** reset (a
    confirmed Finding stays confirmed).
    """

    assert verdict.verdict == "vulnerable"
    assert verdict.vuln_category is not None and verdict.proposed_severity is not None

    run_at = now or datetime.now(UTC)
    affects_label, affects_id = _primary_affected(testcase)
    finding_key = compute_finding_key(
        engagement_id=engagement_id,
        vuln_category=verdict.vuln_category,
        primary_affected_id=affects_id,
    )

    rows = client.execute_write(
        f"""
        MERGE (f:Finding {{engagement_id: $eid, finding_key: $fk}})
        ON CREATE SET
            f.id = $fk,
            f.category = $category,
            f.severity = $severity,
            f.title = $title,
            f.finding_status = 'proposed',
            f.disclosure_status = 'unreported',
            f.primary_affected_id = $affects_id,
            f.primary_affected_label = $affects_label,
            f.source = $source,
            f.source_id = $run_id,
            f.confidence = $confidence,
            f.confidence_method = 'llm-self-reported',
            f.first_seen = $now, f.last_seen = $now, f.ingested_at = $now,
            f.inferred_at = $now, f.code_version = $code_version,
            f.status = 'active',
            f.transcript_key = $transcript_key,
            f._created = true
        ON MATCH SET
            f.last_seen = $now,
            f._created = false
        WITH f, f._created AS created, f.finding_status AS finding_status
        REMOVE f._created
        WITH f, created, finding_status
        MATCH (t:TestCase {{engagement_id: $eid, key_hash: $key_hash}})
        MERGE (f)-[:REFERENCES]->(t)
        WITH f, created, finding_status
        MATCH (a:{affects_label} {{engagement_id: $eid, id: $affects_id}})
        MERGE (f)-[:AFFECTS]->(a)
        WITH f, created, finding_status
        UNWIND $evidence_ids AS oid
        MATCH (r:RequestObservation {{engagement_id: $eid, observation_id: oid}})
        MERGE (f)-[:DERIVED_FROM]->(r)
        RETURN created, finding_status
        """,
        eid=engagement_id,
        fk=finding_key,
        category=verdict.vuln_category,
        severity=verdict.proposed_severity,
        title=f"{verdict.vuln_category}: {testcase.test_class} on {affects_label} {affects_id[:12]}",
        affects_id=affects_id,
        affects_label=affects_label,
        source=LLM_INTERPRETER_SOURCE,
        run_id=run_id,
        confidence=0.5,  # llm-self-reported is NOT disclosure-grade (ADR-0045).
        key_hash=testcase.key_hash,
        evidence_ids=[str(o) for o in verdict.evidence_refs],
        transcript_key=transcript_key,
        now=run_at,
        code_version=__version__,
    )
    # When `evidence_refs` is empty UNWIND yields zero rows; fall back to a
    # second read so the outcome is still reported.
    if rows:
        created = bool(rows[0]["created"])
        status = str(rows[0]["finding_status"])
    else:
        r = client.execute_read(
            "MATCH (f:Finding {engagement_id: $eid, finding_key: $fk}) "
            "RETURN f.finding_status AS s, (f.first_seen = f.last_seen) AS c",
            eid=engagement_id,
            fk=finding_key,
        )
        created = bool(r[0]["c"]) if r else True
        status = str(r[0]["s"]) if r else "proposed"

    log.info(
        "finding.commit",
        engagement_id=engagement_id,
        finding_key=finding_key,
        created=created,
        finding_status=status,
        category=verdict.vuln_category,
        affects=f"{affects_label}:{affects_id}",
    )
    return FindingCommitOutcome(
        finding_key=finding_key, created=created, finding_status=status
    )


def merge_finding_into(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    loser_key: FindingId,
    winner_key: FindingId,
    now: datetime | None = None,
) -> None:
    """Human-driven merge: `status = retracted` on the loser + `MERGED_INTO` (ADR-0045).

    The Principal/Tenant pattern (ADR-0010): the loser is retracted, not deleted;
    a `MERGED_INTO` edge preserves lineage. Split is the converse (commit a second
    Finding with a distinct `primary_affected_id`).
    """

    run_at = now or datetime.now(UTC)
    client.execute_write(
        """
        MATCH (l:Finding {engagement_id: $eid, finding_key: $loser})
        MATCH (w:Finding {engagement_id: $eid, finding_key: $winner})
        SET l.status = 'retracted', l.last_seen = $now
        MERGE (l)-[:MERGED_INTO]->(w)
        """,
        eid=engagement_id,
        loser=loser_key,
        winner=winner_key,
        now=run_at,
    )


# ---------------------------------------------------------------------------
# Finding ledger (sibling of review/dispatch ledgers, ADR-0040 shape).
# ---------------------------------------------------------------------------


class FindingLedgerEvent(BaseModel):
    """One provenanced finding-review decision (`confirm` / `reject`)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    engagement_id: EngagementId
    finding_key: FindingId
    actor: str = Field(min_length=1)
    timestamp: datetime
    decision: FindingDecision
    reason: str | None = None
    prior_status: FindingStatus
    new_status: FindingStatus


class FindingLedger(Protocol):
    def append(self, event: FindingLedgerEvent) -> None: ...
    def events_for(
        self, engagement_id: EngagementId, finding_key: FindingId
    ) -> list[FindingLedgerEvent]: ...


@dataclass(frozen=True, slots=True)
class JsonFileFindingLedger:
    """JSON-file-backed append-only finding ledger (mirrors the review ledger)."""

    ledger_path: Path

    def _read_raw(self) -> list[dict[str, object]]:
        if not self.ledger_path.exists():
            return []
        try:
            data: list[dict[str, object]] = json.loads(self.ledger_path.read_text())
            return data
        except json.JSONDecodeError:
            return []

    def append(self, event: FindingLedgerEvent) -> None:
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        raw = self._read_raw()
        raw.append(event.model_dump(mode="json"))
        self.ledger_path.write_text(json.dumps(raw, indent=2))

    def events_for(
        self, engagement_id: EngagementId, finding_key: FindingId
    ) -> list[FindingLedgerEvent]:
        return [
            FindingLedgerEvent.model_validate(e)
            for e in self._read_raw()
            if e.get("engagement_id") == engagement_id
            and e.get("finding_key") == finding_key
        ]


@dataclass
class InMemoryFindingLedger:
    events: list[FindingLedgerEvent] = field(default_factory=list)

    def append(self, event: FindingLedgerEvent) -> None:
        self.events.append(event)

    def events_for(
        self, engagement_id: EngagementId, finding_key: FindingId
    ) -> list[FindingLedgerEvent]:
        return [
            e
            for e in self.events
            if e.engagement_id == engagement_id and e.finding_key == finding_key
        ]


_DECISION_TO_STATUS: dict[FindingDecision, FindingStatus] = {
    "confirm": "confirmed",
    "reject": "rejected",
}


def review_finding(
    client: Neo4jClient,
    ledger: FindingLedger,
    *,
    engagement_id: EngagementId,
    finding_key: FindingId,
    decision: FindingDecision,
    actor: str,
    reason: str | None = None,
    now: datetime | None = None,
) -> FindingLedgerEvent:
    """Apply one finding-review decision: ledger event + denormalise onto the node.

    Same ADR-0040 discipline as `review_testcase`: append-only ledger keyed by
    `(engagement_id, finding_key)`; the node holds the denormalised current
    `finding_status` only. Only `confirmed` Findings feed reporting (ADR-0045).
    """

    run_at = now or datetime.now(UTC)
    frag = for_engagement(engagement_id, var="f")
    rows = client.execute_read(
        f"""
        MATCH (f:Finding {{finding_key: $fk}})
        {frag.and_("f.status = 'active'")}
        RETURN f.finding_status AS finding_status
        """,
        fk=finding_key,
        **frag.parameters,
    )
    if not rows:
        raise ValueError(
            f"no active Finding {finding_key!r} in engagement {engagement_id!r}"
        )
    prior: FindingStatus = str(rows[0]["finding_status"])  # type: ignore[assignment]
    new = _DECISION_TO_STATUS[decision]

    client.execute_write(
        f"""
        MATCH (f:Finding {{finding_key: $fk}})
        {frag.and_("f.status = 'active'")}
        SET f.finding_status = $new,
            f.reviewed_by = $actor,
            f.reviewed_at = $now,
            f.review_reason = $reason,
            f.last_seen = $now
        """,
        fk=finding_key,
        new=new,
        actor=actor,
        now=run_at,
        reason=reason,
        **frag.parameters,
    )
    event = FindingLedgerEvent(
        engagement_id=engagement_id,
        finding_key=finding_key,
        actor=actor,
        timestamp=run_at,
        decision=decision,
        reason=reason,
        prior_status=prior,
        new_status=new,
    )
    ledger.append(event)
    log.info(
        "finding.review.recorded",
        engagement_id=engagement_id,
        finding_key=finding_key,
        actor=actor,
        decision=decision,
        prior_status=prior,
        new_status=new,
    )
    return event


@dataclass(frozen=True, slots=True)
class ProposedFindingView:
    """A `proposed` `Finding` projected for `doo finding review`."""

    finding_key: FindingId
    category: str
    severity: str
    title: str
    affects: str
    referenced_testcases: tuple[TestCaseKeyHash, ...]
    transcript_key: str | None
    finding_status: str


def list_proposed_findings(
    client: Neo4jClient, engagement_id: EngagementId
) -> list[ProposedFindingView]:
    """List `proposed` Findings for review (with the transcript link, ADR-0045)."""

    frag = for_engagement(engagement_id, var="f")
    rows = client.execute_read(
        f"""
        MATCH (f:Finding)
        {frag.and_("f.status = 'active' AND f.finding_status = 'proposed'")}
        OPTIONAL MATCH (f)-[:REFERENCES]->(t:TestCase)
        WITH f, collect(t.key_hash) AS tcs
        RETURN f.finding_key AS fk, f.category AS cat, f.severity AS sev,
               f.title AS title, f.primary_affected_label AS aflabel,
               f.primary_affected_id AS afid, f.transcript_key AS tk,
               f.finding_status AS status, f.first_seen AS first_seen,
               tcs
        ORDER BY sev DESC, first_seen ASC
        """,
        **frag.parameters,
    )
    return [
        ProposedFindingView(
            finding_key=FindingId(str(r["fk"])),
            category=str(r["cat"]),
            severity=str(r["sev"]),
            title=str(r["title"]),
            affects=f"{r['aflabel']}:{str(r['afid'])[:12]}",
            referenced_testcases=tuple(
                TestCaseKeyHash(str(t)) for t in (r["tcs"] or []) if t
            ),
            transcript_key=r.get("tk"),
            finding_status=str(r["status"]),
        )
        for r in rows
    ]


def resolve_finding_key(
    client: Neo4jClient, engagement_id: EngagementId, prefix: str
) -> FindingId | None:
    """Resolve a `finding_key` (or 12-char prefix) regardless of `finding_status`.

    `list_proposed_findings` is the right *listing* (the review queue is
    `proposed`-only), but `--confirm` / `--reject` must reach a Finding the
    tester previously rejected and is now overriding — the ledger records
    `prior_status → new_status` so the audit trail is intact (ADR-0045).
    Returns `None` when no active Finding matches; ambiguity (>1 match) raises.
    """

    frag = for_engagement(engagement_id, var="f")
    rows = client.execute_read(
        f"""
        MATCH (f:Finding)
        {frag.and_("f.status = 'active' AND f.finding_key STARTS WITH $pre")}
        RETURN f.finding_key AS fk
        """,
        pre=prefix,
        **frag.parameters,
    )
    if not rows:
        return None
    if len(rows) > 1:
        keys = ", ".join(str(r["fk"])[:12] for r in rows)
        raise ValueError(
            f"finding-key prefix {prefix!r} is ambiguous ({len(rows)} matches: {keys}); "
            "use a longer prefix"
        )
    return FindingId(str(rows[0]["fk"]))


# ---------------------------------------------------------------------------
# Transcript persistence (ADR-0037 applied to the Interpreter, ADR-0045).
# ---------------------------------------------------------------------------


def persist_transcript(
    bodies: object,
    *,
    engagement_id: EngagementId,
    run_id: DispatchRunId,
    key_hash: TestCaseKeyHash,
    transcript: tuple[dict[str, object], ...],
    verdict: InterpreterVerdict,
) -> str | None:
    """Persist the full confirm-loop transcript to object storage (ADR-0045).

    Keyed by `(run_id, key_hash)` so any Finding traces back to the exact bytes
    and reasoning that produced it. Reuses `BlobClient.put_body` (the body store
    seam) with `content_type = application/json`; a `NoopBodyStore` returns None
    (the verdict + justification still land on the TestCase node).
    """

    from doo.dispatch.interpreter.loop import INTERPRETER_PROMPT_VERSION

    body = {
        "engagement_id": engagement_id,
        "run_id": run_id,
        "key_hash": key_hash,
        "prompt_version": INTERPRETER_PROMPT_VERSION,
        "transcript": list(transcript),
        "verdict": verdict.model_dump(mode="json"),
    }
    raw = json.dumps(body, sort_keys=True, default=str).encode("utf-8")
    ref = bodies.put_body(  # type: ignore[attr-defined]
        engagement_id, raw=raw, content_type="application/json"
    )
    if ref is None:
        return None
    return str(ref.key)


__all__ = [
    "FindingCommitOutcome",
    "FindingDecision",
    "FindingLedger",
    "FindingLedgerEvent",
    "FindingStatus",
    "InMemoryFindingLedger",
    "JsonFileFindingLedger",
    "ObservationId",
    "ProposedFindingView",
    "commit_finding",
    "compute_finding_key",
    "list_proposed_findings",
    "merge_finding_into",
    "persist_transcript",
    "resolve_finding_key",
    "record_verdict",
    "review_finding",
]
