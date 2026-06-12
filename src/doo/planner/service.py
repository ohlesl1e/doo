"""Planner orchestration: `propose` and `review_queue` (ADRs 0036/0037/0040).

`propose` runs the enabled deterministic generators, turns each candidate into a
proposal, validates it, and commits the survivors as content-addressed `TestCase`s
at `review_status = proposed`. Discarded proposals are logged, never committed
(ADR-0040). For the S1 tracer this is pure deterministic C1 — no LLM.

`review_queue` assembles the deterministically-prioritised review surface: the
`proposed` `TestCase`s plus any previously-`defer`-rejected ones the re-surface
predicate now re-admits (flagged with what changed), ordered by the prioritiser and
truncated top-N. Nothing dispatches.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from doo.coverage.decay import effective_confidence
from doo.coverage.queries import _to_aware
from doo.ids import EngagementId, TestCaseKeyHash
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
from doo.ontology.queries import for_engagement
from doo.planner.commit import commit_testcase
from doo.planner.generators import (
    LLMProgressCallback,
    LLMSkipped,
    PlannerConfig,
    enabled_generators,
    enabled_llm_generators,
)
from doo.planner.llm import DraftRejected as LLMDraftRejected
from doo.planner.llm import LLMCaller
from doo.planner.llm_audit import LLMAuditSink
from doo.planner.models import GeneratorId, PlannerProposal, ProposedTestCaseView
from doo.planner.prioritize import prioritize, priority_score
from doo.planner.review import ReviewLedger
from doo.planner.validator import DiscardedProposal, should_resurface, validate

log = get_logger(__name__)

# Gap/boundary criticality by provenance source (ADR-0036: tenant > capability >
# C2b > C2 > C1). C1 is the lowest tier; the C2 LLM generator commits `llm-planner`
# and outranks it. Later tracers extend this map.
_CRITICALITY_BY_SOURCE: dict[str, float] = {
    "deterministic-c1": 1.0,
    "llm-planner": 2.0,
}

# Map a committed node's `source` back to the generator id (for the view). Both the
# C2 and C2b LLM-proposing generators commit `source = "llm-planner"` (ADR-0036: the
# proposing *mode*, not the generator, is the provenance distinction), so the source
# alone cannot tell C2 from C2b on the node — `llm-planner` maps to the C2 family
# representative `c2` for the view's generator label.
_GENERATOR_BY_SOURCE: dict[str, GeneratorId] = {
    "deterministic-c1": "c1",
    "llm-planner": "c2",
}
_DEFAULT_GENERATOR: GeneratorId = "c1"


@dataclass(frozen=True, slots=True)
class ProposeResult:
    """Outcome of a `propose` run: committed (new + idempotent) and discarded counts.

    `discarded` collects deterministic Validator discards. The LLM path adds two
    pre-validator outcomes (ADR-0037): `llm_rejected` — drafts whose handles did not
    resolve (the hallucination guard) — and `llm_skipped` — gaps with no proposable
    pack or an unparseable response (reasons). Neither commits.
    """

    candidates: int = 0
    committed: int = 0
    created: int = 0
    idempotent: int = 0
    discarded: tuple[DiscardedProposal, ...] = field(default_factory=tuple)
    committed_key_hashes: tuple[TestCaseKeyHash, ...] = field(default_factory=tuple)
    llm_rejected: tuple[LLMDraftRejected, ...] = field(default_factory=tuple)
    llm_skipped: tuple[LLMSkipped, ...] = field(default_factory=tuple)


def propose(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    config: PlannerConfig | None = None,
    llm_caller: LLMCaller | None = None,
    llm_audit_sink: LLMAuditSink | None = None,
    on_llm_progress: LLMProgressCallback | None = None,
    now: datetime | None = None,
) -> ProposeResult:
    """Run the enabled generators, validate, and commit proposed `TestCase`s.

    Deterministic generators (C1) select candidates, propose per candidate, the
    Validator resolves / checks each proposal, and survivors commit idempotently at
    `review_status = proposed`. LLM-proposing generators (C2) additionally need a
    `llm_caller` (the model seam) and a `llm_audit_sink` (ADR-0037 replayability):
    each proposal's verbatim call is persisted and the storage key stamped onto the
    committed node before validation. A C2 generator requested without a caller is
    skipped (the default stays LLM-free); with a caller but no sink it is a wiring
    error (the audit is not optional for an LLM contribution).

    Discards / rejections / skips are collected for the run audit, never committed
    (ADR-0040). Re-running on an unchanged graph re-commits the same content as a
    no-op (ADR-0007).
    """

    cfg = config or PlannerConfig()
    run_at = now or datetime.now(UTC)
    generators = enabled_generators(cfg)
    llm_generators = enabled_llm_generators(cfg, caller=llm_caller)
    if llm_generators and llm_audit_sink is None:
        raise ValueError(
            "an LLM-proposing generator is enabled but no llm_audit_sink was "
            "supplied; the proposing call must be persisted for replay (ADR-0037)"
        )

    candidates_n = committed = created = idempotent = 0
    discarded: list[DiscardedProposal] = []
    committed_hashes: list[TestCaseKeyHash] = []
    llm_rejected: list[LLMDraftRejected] = []
    llm_skipped: list[LLMSkipped] = []

    def _commit(proposal: PlannerProposal) -> None:
        nonlocal committed, created, idempotent
        outcome = validate(client, proposal)
        if isinstance(outcome, DiscardedProposal):
            discarded.append(outcome)
            return
        commit = commit_testcase(client, outcome, now=run_at)
        committed += 1
        committed_hashes.append(commit.key_hash)
        if commit.created:
            created += 1
        else:
            idempotent += 1

    for generator in generators:
        candidates = generator.generate(client, engagement_id, now=run_at)
        candidates_n += len(candidates)
        for candidate in candidates:
            _commit(generator.propose(candidate))

    for llm_generator in llm_generators:
        run = llm_generator.run(
            client, engagement_id, now=run_at, on_progress=on_llm_progress
        )
        candidates_n += run.candidates
        assert llm_audit_sink is not None  # guarded above when llm_generators present
        for item in run.proposed:
            audit_key = llm_audit_sink.record(engagement_id, item.call)
            _commit(item.proposal.model_copy(update={"llm_audit_key": audit_key}))
        for rej in run.rejected:
            # Persist even a rejected call so a hallucination is replayable (ADR-0037).
            llm_audit_sink.record(engagement_id, rej.call)
            llm_rejected.append(rej.rejection)
        llm_skipped.extend(run.skipped)

    log.info(
        "planner.propose.complete",
        engagement_id=engagement_id,
        candidates=candidates_n,
        committed=committed,
        created=created,
        idempotent=idempotent,
        discarded=len(discarded),
        llm_rejected=len(llm_rejected),
        llm_skipped=len(llm_skipped),
    )
    return ProposeResult(
        candidates=candidates_n,
        committed=committed,
        created=created,
        idempotent=idempotent,
        discarded=tuple(discarded),
        committed_key_hashes=tuple(committed_hashes),
        llm_rejected=tuple(llm_rejected),
        llm_skipped=tuple(llm_skipped),
    )


def _row_to_view(
    row: dict[str, Any],
    *,
    engagement_id: EngagementId,
    run_at: datetime,
    resurfaced: bool = False,
    resurfaced_reason: str | None = None,
    review_status_override: str | None = None,
) -> ProposedTestCaseView:
    """Project one TestCase-with-target Cypher row into a prioritised view."""

    source = str(row["source"])
    criticality = _CRITICALITY_BY_SOURCE.get(source, 1.0)
    generator: GeneratorId = _GENERATOR_BY_SOURCE.get(source, _DEFAULT_GENERATOR)

    stored = float(row["target_confidence"]) if row["target_confidence"] is not None else 1.0
    last_seen = _to_aware(row["target_last_seen"], fallback=run_at)
    eff = effective_confidence(stored, last_seen, now=run_at)

    expected_yield = float(row["expected_yield"])
    score = priority_score(
        expected_yield=expected_yield,
        criticality=criticality,
        effective_target_confidence=eff,
    )

    host_label = None
    if row["host"] is not None:
        host_label = str(row["host"])
        if row["port"] is not None:
            host_label = f"{host_label}:{row['port']}"

    return ProposedTestCaseView(
        engagement_id=engagement_id,
        key_hash=TestCaseKeyHash(str(row["key_hash"])),
        test_class=str(row["test_class"]),  # type: ignore[arg-type]
        generator=generator,
        source=source,
        target_endpoint_id=row["target_endpoint_id"],
        target_parameter_id=row["target_parameter_id"],
        target_trust_boundary_id=row["target_trust_boundary_id"],
        method=str(row["method"]) if row["method"] is not None else None,
        host=host_label,
        path_template=(
            str(row["path_template"]) if row["path_template"] is not None else None
        ),
        payload_class=str(row["payload_class"]),  # type: ignore[arg-type]
        expected_yield=expected_yield,
        confidence=float(row["confidence"]),
        effective_target_confidence=eff,
        criticality=criticality,
        justification=str(row["justification"]),
        expected_outcome=str(row["expected_outcome"]),
        priority_score=score,
        replay_hazards=tuple(row["replay_hazards"]) if row["replay_hazards"] else (),
        review_status=review_status_override or str(row["review_status"]),  # type: ignore[arg-type]
        resurfaced=resurfaced,
        resurfaced_reason=resurfaced_reason,
    )


# One shared RETURN projecting a TestCase + its (optional) Endpoint target with the
# host identity needed for scope/labels. Parameter/boundary targets carry null
# method/host (the S1 spine only commits endpoint targets).
_TESTCASE_PROJECTION = """
    OPTIONAL MATCH (t)-[:TARGETS_ENDPOINT]->(e:Endpoint)-[:ON_HOST]->(h:Host)
    RETURN t.key_hash AS key_hash,
           t.test_class AS test_class,
           t.source AS source,
           t.target_endpoint_id AS target_endpoint_id,
           t.target_parameter_id AS target_parameter_id,
           t.target_trust_boundary_id AS target_trust_boundary_id,
           t.payload_class AS payload_class,
           t.review_status AS review_status,
           t.expected_yield AS expected_yield,
           t.confidence AS confidence,
           t.justification AS justification,
           t.expected_outcome AS expected_outcome,
           t.replay_hazards AS replay_hazards,
           t.review_disposition AS review_disposition,
           e.method AS method,
           e.path_template AS path_template,
           e.confidence AS target_confidence,
           e.last_seen AS target_last_seen,
           h.canonical_hostname AS host,
           h.port AS port
"""


def review_queue(
    client: Neo4jClient,
    ledger: ReviewLedger,
    *,
    engagement_id: EngagementId,
    top_n: int | None = None,
    include_resurfaced: bool = True,
    now: datetime | None = None,
) -> list[ProposedTestCaseView]:
    """Build the deterministically-prioritised review queue (ADR-0036/0040).

    Returns the `proposed` `TestCase`s (the awaiting-review set) plus, when
    `include_resurfaced`, any previously-`defer`-rejected ones the re-surface
    predicate now re-admits (effective confidence rose materially, or new
    `DERIVED_FROM` evidence appeared since rejection) — each flagged with what
    changed (ADR-0040). The combined set is ordered by the prioritiser and
    truncated top-N. A read only; no graph mutation, nothing dispatched.
    """

    run_at = now or datetime.now(UTC)
    frag = for_engagement(engagement_id, var="t")

    proposed_rows = client.execute_read(
        f"""
        MATCH (t:TestCase)
        {frag.and_("t.status = 'active' AND t.review_status = 'proposed'")}
        {_TESTCASE_PROJECTION}
        """,
        **frag.parameters,
    )
    views = [
        _row_to_view(row, engagement_id=engagement_id, run_at=run_at)
        for row in proposed_rows
    ]

    if include_resurfaced:
        rejected_rows = client.execute_read(
            f"""
            MATCH (t:TestCase)
            {frag.and_("t.status = 'active' AND t.review_status = 'rejected'")}
            {_TESTCASE_PROJECTION}
            """,
            **frag.parameters,
        )
        for row in rejected_rows:
            key_hash = TestCaseKeyHash(str(row["key_hash"]))
            latest = ledger.latest_for(engagement_id, key_hash)
            if latest is None or latest.decision != "reject":
                continue
            disposition = latest.disposition or "defer"
            stored = (
                float(row["target_confidence"])
                if row["target_confidence"] is not None
                else 1.0
            )
            last_seen = _to_aware(row["target_last_seen"], fallback=run_at)
            current_conf = effective_confidence(stored, last_seen, now=run_at)
            # Current DERIVED_FROM count for the target (re-surface input).
            current_derived = _target_derived_from_count(
                client, engagement_id=engagement_id, key_hash=key_hash
            )
            verdict = should_resurface(
                disposition=disposition,
                snapshot_confidence=latest.evidence_confidence,
                snapshot_derived_from_count=latest.evidence_derived_from_count,
                current_confidence=current_conf,
                current_derived_from_count=current_derived,
            )
            if verdict.resurface:
                views.append(
                    _row_to_view(
                        row,
                        engagement_id=engagement_id,
                        run_at=run_at,
                        resurfaced=True,
                        resurfaced_reason=verdict.reason,
                    )
                )

    ordered = prioritize(views, top_n=top_n)
    log.info(
        "planner.review_queue.built",
        engagement_id=engagement_id,
        proposed=len(proposed_rows),
        shown=len(ordered),
        top_n=top_n,
    )
    return ordered


def _target_derived_from_count(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    key_hash: TestCaseKeyHash,
) -> int:
    frag = for_engagement(engagement_id, var="t")
    rows = client.execute_read(
        f"""
        MATCH (t:TestCase {{key_hash: $key_hash}})
        {frag.and_("t.status = 'active'")}
        OPTIONAL MATCH (t)-[:TARGETS_ENDPOINT]->(e:Endpoint)
        OPTIONAL MATCH (t)-[:TARGETS_PARAMETER]->(p:Parameter)
        OPTIONAL MATCH (t)-[:TARGETS_BOUNDARY]->(b:TrustBoundary)
        WITH coalesce(e, p, b) AS target
        RETURN COUNT {{ (target)-[:DERIVED_FROM]->() }} AS derived_from_count
        """,
        key_hash=key_hash,
        **frag.parameters,
    )
    if not rows or rows[0]["derived_from_count"] is None:
        return 0
    return int(rows[0]["derived_from_count"])
