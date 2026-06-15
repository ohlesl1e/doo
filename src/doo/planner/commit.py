"""Content-addressed `TestCase` identity + idempotent commit (ADR-0007/0040).

A committed proposal is a **real `TestCase`** (ADR-0037: no `TestProposal` type) —
content-addressed by the ADR-0007 `key_hash` and Engagement-scoped. "Proposed" is
just a `TestCase` with no `EXECUTED_AS` edge and `review_status = proposed`
(ADR-0040). `confidence` is validity (validator-set, high); `expected_yield` is the
separate priority hunch (ADR-0037).

Commit is idempotent by construction (ADR-0007): the `(engagement_id, key_hash)`
uniqueness constraint (`ontology/schema.py`) makes a re-commit of the same content
a no-op `MERGE`. The same logical test proposed twice converges to one node; an
already-reviewed node is never silently reset to `proposed`.

The target edge (`TARGETS_ENDPOINT` / `TARGETS_PARAMETER` / `TARGETS_BOUNDARY`) is
wired to match the three-way XOR (ADR-0007). Deterministic only — no LLM here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from doo import __version__
from doo.events.slice4 import PayloadClass, TestClass
from doo.ids import (
    AuthContextId,
    EngagementId,
    ParameterId,
    Sha256Hex,
    TestCaseKeyHash,
    TrustBoundaryId,
)
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
from doo.ontology.queries import for_engagement

log = get_logger(__name__)

# `confidence` on a validator-passed TestCase is validity, set deterministically
# high (ADR-0037). Kept just below 1.0 so it reads as "machine-validated, not
# ground truth".
VALIDATED_CONFIDENCE = 0.99

# Provenance source tag per generator/mode (ADR-0036). Deterministic generators
# commit `deterministic-<gen>`; LLM-proposing ones commit `llm-planner`.
_SOURCE_BY_GENERATOR = {"c1": "deterministic-c1"}

# The single provenance tag every LLM-proposing generator commits (ADR-0036): the
# proposing *mode*, not the generator id, is what distinguishes an LLM contribution
# from a deterministic one (CLAUDE.md: `source: "llm-<task>"`).
LLM_PLANNER_SOURCE = "llm-planner"
# The Interpreter's follow-up proposals commit a distinct source (ADR-0045/S8) so
# provenance separates them from the Planner's, though they share this path.
LLM_INTERPRETER_SOURCE = "llm-interpreter"


@dataclass(frozen=True, slots=True)
class ValidatedTestCase:
    """A validator-resolved, ready-to-commit `TestCase` (ADR-0007).

    Carries the resolved identity (`key_hash`, the XOR target, resolved
    `payload_hash`) plus the review/priority/provenance fields the node stores.
    """

    engagement_id: EngagementId
    key_hash: TestCaseKeyHash
    test_class: TestClass
    target_endpoint_id: str | None
    target_parameter_id: ParameterId | None
    target_trust_boundary_id: TrustBoundaryId | None
    payload_class: PayloadClass
    payload_hash: Sha256Hex
    auth_context_id: AuthContextId
    source: str
    # The deterministic generator that selected this target (ADR-0036). Persisted
    # for the slice-4 selection predicate (`--select generator=c2`). NOT part of
    # `key_hash` (ADR-0007: same content via different generators is one test).
    generator: str
    expected_yield: float
    expected_yield_method: str
    justification: str
    expected_outcome: str
    # Authz-replay execution intent (ADR-0041): the param names held verbatim from
    # the evidence observation while auth is swapped. Persisted so the slice-4
    # constructor (ADR-0043) can apply it deterministically. Like `replay_hazards`,
    # a derivable execution-fidelity annotation — NOT part of `key_hash`.
    hold: tuple[str, ...] = ()
    # Replay-fidelity annotation (ADR-0041): the deterministically-detected
    # replay-breaker roles in the evidencing observation. Set by code, never the LLM,
    # and **not** part of `key_hash` (a derivable execution-fidelity annotation, like
    # `hold`). Persisted as a node property for the review surface.
    replay_hazards: tuple[str, ...] = ()
    # Resolvable-hazard `source_hint`s (`"<kind>=<url>"`, ADR-0041): where the
    # slice-4 resolver fetches a fresh token (csrf). Code-set, not in `key_hash`.
    hazard_source_hints: tuple[str, ...] = ()
    # Object-storage key of the proposing LLM call (ADR-0037), or None for a
    # deterministic proposal. Committed onto the node as replay provenance.
    llm_audit_key: str | None = None


@dataclass(frozen=True, slots=True)
class CommitOutcome:
    """Outcome of committing a `ValidatedTestCase`.

    `created` is True on a fresh insert, False on an idempotent re-commit (the
    node already existed — ADR-0007 content-address no-op). `review_status` is the
    node's current review state after the commit (a re-commit never resets it).
    """

    key_hash: TestCaseKeyHash
    created: bool
    review_status: str


def _target_label(vtc: ValidatedTestCase) -> tuple[str, str]:
    """The (edge_type, target_id) for the XOR-resolved target (ADR-0007)."""

    if vtc.target_endpoint_id is not None:
        return "TARGETS_ENDPOINT", vtc.target_endpoint_id
    if vtc.target_parameter_id is not None:
        return "TARGETS_PARAMETER", str(vtc.target_parameter_id)
    assert vtc.target_trust_boundary_id is not None  # XOR guaranteed upstream
    return "TARGETS_BOUNDARY", str(vtc.target_trust_boundary_id)


def commit_testcase(
    client: Neo4jClient,
    vtc: ValidatedTestCase,
    *,
    now: datetime | None = None,
    code_version: str | None = None,
) -> CommitOutcome:
    """Idempotently commit a validated `TestCase` at `review_status = proposed`.

    `MERGE` on `(engagement_id, key_hash)` makes re-commit a no-op (ADR-0007). On a
    fresh insert the node is stamped with the full cross-cutting provenance
    (ADR-0005), `review_status = proposed`, validity `confidence`, the separate
    `expected_yield`, and the target edge matching the XOR. A re-commit only bumps
    `last_seen` and **never** resets `review_status` (a re-proposed test that a
    human already approved/rejected keeps its decision).
    """

    run_at = now or datetime.now(UTC)
    edge_type, target_id = _target_label(vtc)

    target_endpoint_id = vtc.target_endpoint_id
    target_parameter_id = (
        str(vtc.target_parameter_id) if vtc.target_parameter_id is not None else None
    )
    target_trust_boundary_id = (
        str(vtc.target_trust_boundary_id)
        if vtc.target_trust_boundary_id is not None
        else None
    )

    # The target edge endpoint label is fixed per XOR branch; build the matching
    # MATCH so the edge wires to the right node type.
    target_label = {
        "TARGETS_ENDPOINT": "Endpoint",
        "TARGETS_PARAMETER": "Parameter",
        "TARGETS_BOUNDARY": "TrustBoundary",
    }[edge_type]

    rows = client.execute_write(
        f"""
        MERGE (t:TestCase {{engagement_id: $eid, key_hash: $key_hash}})
        ON CREATE SET
            t.test_class = $test_class,
            t.target_endpoint_id = $target_endpoint_id,
            t.target_parameter_id = $target_parameter_id,
            t.target_trust_boundary_id = $target_trust_boundary_id,
            t.payload_class = $payload_class,
            t.payload_hash = $payload_hash,
            t.auth_context_id = $auth_context_id,
            t.review_status = 'proposed',
            t.expected_yield = $expected_yield,
            t.expected_yield_method = $expected_yield_method,
            t.justification = $justification,
            t.expected_outcome = $expected_outcome,
            t.hold = $hold,
            t.replay_hazards = $replay_hazards,
            t.hazard_source_hints = $hazard_source_hints,
            t.generator = $generator,
            t.source = $source,
            t.source_id = $source_id,
            t.llm_audit_key = $llm_audit_key,
            t.confidence = $confidence,
            t.confidence_method = 'heuristic',
            t.first_seen = $now,
            t.last_seen = $now,
            t.ingested_at = $now,
            t.inferred_at = $now,
            t.code_version = $code_version,
            t.status = 'active',
            t._created = true
        ON MATCH SET
            t.last_seen = $now,
            t._created = false
        WITH t, t._created AS created, t.review_status AS review_status
        REMOVE t._created
        WITH t, created, review_status
        MATCH (target:{target_label} {{engagement_id: $eid, id: $target_id}})
        MERGE (t)-[:{edge_type}]->(target)
        RETURN created AS created, review_status AS review_status
        """,
        eid=vtc.engagement_id,
        key_hash=vtc.key_hash,
        test_class=vtc.test_class,
        target_endpoint_id=target_endpoint_id,
        target_parameter_id=target_parameter_id,
        target_trust_boundary_id=target_trust_boundary_id,
        payload_class=vtc.payload_class,
        payload_hash=vtc.payload_hash,
        auth_context_id=str(vtc.auth_context_id),
        expected_yield=vtc.expected_yield,
        expected_yield_method=vtc.expected_yield_method,
        justification=vtc.justification,
        expected_outcome=vtc.expected_outcome,
        hold=list(vtc.hold),
        replay_hazards=list(vtc.replay_hazards),
        hazard_source_hints=list(vtc.hazard_source_hints),
        generator=vtc.generator,
        source=vtc.source,
        source_id=None,
        llm_audit_key=vtc.llm_audit_key,
        confidence=VALIDATED_CONFIDENCE,
        now=run_at,
        code_version=code_version or __version__,
        target_id=target_id,
    )
    # The target MATCH is guaranteed to succeed: the validator resolved the target
    # against the same graph before producing the ValidatedTestCase.
    row = rows[0]
    created = bool(row["created"])
    review_status = str(row["review_status"])
    log.info(
        "planner.testcase.commit",
        engagement_id=vtc.engagement_id,
        key_hash=vtc.key_hash,
        created=created,
        review_status=review_status,
    )
    return CommitOutcome(
        key_hash=vtc.key_hash, created=created, review_status=review_status
    )


def source_for_generator(generator: str) -> str:
    """The provenance `source` tag for a deterministic generator (ADR-0036)."""

    return _SOURCE_BY_GENERATOR.get(generator, f"deterministic-{generator}")


def source_for(generator: str, mode: str) -> str:
    """The provenance `source` tag for a proposal, keyed on its proposing *mode*.

    An LLM-proposing proposal (`mode == "llm"`) commits `llm-planner` regardless of
    which generator produced it (ADR-0036 / CLAUDE.md); a deterministic one commits
    `deterministic-<generator>`.
    """

    if mode == "llm":
        return LLM_INTERPRETER_SOURCE if generator == "interpreter" else LLM_PLANNER_SOURCE
    return source_for_generator(generator)


@dataclass(frozen=True, slots=True)
class TestCaseNode:
    """A read projection of a committed `TestCase` node (review/dedup reads)."""

    key_hash: TestCaseKeyHash
    test_class: TestClass
    target_endpoint_id: str | None
    target_parameter_id: str | None
    target_trust_boundary_id: str | None
    payload_class: PayloadClass
    source: str
    review_status: str
    expected_yield: float
    confidence: float
    justification: str
    expected_outcome: str


def fetch_testcase(
    client: Neo4jClient, engagement_id: EngagementId, key_hash: TestCaseKeyHash
) -> TestCaseNode | None:
    """Fetch one `TestCase` by content address (dedup / re-surface read), or None."""

    frag = for_engagement(engagement_id, var="t")
    rows = client.execute_read(
        f"""
        MATCH (t:TestCase {{key_hash: $key_hash}})
        {frag.and_("t.status = 'active'")}
        RETURN t.key_hash AS key_hash,
               t.test_class AS test_class,
               t.target_endpoint_id AS target_endpoint_id,
               t.target_parameter_id AS target_parameter_id,
               t.target_trust_boundary_id AS target_trust_boundary_id,
               t.payload_class AS payload_class,
               t.source AS source,
               t.review_status AS review_status,
               t.expected_yield AS expected_yield,
               t.confidence AS confidence,
               t.justification AS justification,
               t.expected_outcome AS expected_outcome
        """,
        key_hash=key_hash,
        **frag.parameters,
    )
    if not rows:
        return None
    r = rows[0]
    return TestCaseNode(
        key_hash=TestCaseKeyHash(str(r["key_hash"])),
        test_class=str(r["test_class"]),  # type: ignore[arg-type]
        target_endpoint_id=r["target_endpoint_id"],
        target_parameter_id=r["target_parameter_id"],
        target_trust_boundary_id=r["target_trust_boundary_id"],
        payload_class=str(r["payload_class"]),  # type: ignore[arg-type]
        source=str(r["source"]),
        review_status=str(r["review_status"]),
        expected_yield=float(r["expected_yield"]),
        confidence=float(r["confidence"]),
        justification=str(r["justification"]),
        expected_outcome=str(r["expected_outcome"]),
    )
