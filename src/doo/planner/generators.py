"""Candidate generators + registry (ADR-0036).

Target selection is a **pluggable set of deterministic candidate generators**, not
hardcoded to the coverage C-queries. Each generator reads a deterministic signal
(the shared coverage library, ADR-0034) and emits one `Candidate` per selected
target, each carrying a named reason. A generator is either *deterministic-
proposing* (C1: dead endpoint -> `forced_browsing`, no LLM) or *LLM-proposing*
(later tracers); the S1 tracer ships only the deterministic C1 generator.

`PlannerConfig.candidate_generators` enables/disables generators by id — every
setting fully deterministic (ADR-0036). The registry resolves the enabled set.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from doo import __version__
from doo.canonical.identity import (
    auth_context_id,
    compute_anonymous_auth_hash,
)
from doo.coverage.queries import _load_principals, run_c1, run_c2, run_c2b
from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
from doo.planner.assemble import (
    assemble_c2_pack,
    assemble_c2b_pack,
    fetch_reaching_observation_hazards,
)
from doo.planner.llm import (
    DraftRejected,
    LLMCaller,
    LLMCallResult,
    LLMProposalError,
    resolve_draft,
)
from doo.planner.models import (
    GENERATOR_IDS,
    Candidate,
    GeneratorId,
    PayloadSpec,
    PlannerProposal,
    ProposalMode,
)

log = get_logger(__name__)

# Gap/boundary criticality tiers (ADR-0036). C1 is the lowest. Higher tiers
# (C2 < C2b < capability < tenant) land with their generators in later tracers.
_C1_CRITICALITY = 1.0
# C2 (presence-differential authz) outranks C1's mechanical dead-endpoint probe
# (ADR-0036: tenant > capability > C2b > C2 > C1). Surfaced here so the prioritiser
# and the review view agree on the tier (see service `_CRITICALITY_BY_SOURCE`).
_C2_CRITICALITY = 2.0
# C2b (content-differential authz, the BOLA/IDOR hotspot) outranks C2 (ADR-0036:
# tenant > capability > C2b > C2 > C1). Both commit `source = "llm-planner"`, so the
# review view's criticality is keyed on source today (a single `llm-planner` tier);
# this constant records the intended C2b tier for when source-keying is refined.
_C2B_CRITICALITY = 3.0


@runtime_checkable
class CandidateGenerator(Protocol):
    """A deterministic target selector (ADR-0036).

    `generate(client, engagement_id, *, now)` reads the graph at a settle point and
    returns the selected `Candidate`s (target + reason). `propose(candidate)` turns
    one selected candidate into a `PlannerProposal`. A *deterministic-proposing*
    generator (`mode == "deterministic"`) builds the proposal itself with no LLM; an
    *LLM-proposing* generator assembles a context pack and calls the model (later
    tracers). The S1 spine only exercises the deterministic path.
    """

    @property
    def generator_id(self) -> GeneratorId: ...

    @property
    def mode(self) -> ProposalMode: ...

    def generate(
        self,
        client: Neo4jClient,
        engagement_id: EngagementId,
        *,
        now: datetime | None = None,
    ) -> list[Candidate]: ...

    def propose(self, candidate: Candidate) -> PlannerProposal: ...


class C1Generator:
    """Deterministic-proposing generator for in-scope dead endpoints (ADR-0036).

    Selection reuses the shared coverage library's `run_c1` (ADR-0034) — the *same*
    dead-endpoint definition the `doo coverage c1` CLI sees, so the planner and
    coverage never disagree. Each dead endpoint becomes one `Candidate` and then,
    with **no LLM call**, one `forced_browsing` `PlannerProposal`: a benign GET
    against the never-hit endpoint, sent as the anonymous AuthContext (a probe as
    nobody), `payload_class = no-payload`, `payload_spec = none`.
    """

    generator_id: GeneratorId = "c1"
    mode: ProposalMode = "deterministic"

    def generate(
        self,
        client: Neo4jClient,
        engagement_id: EngagementId,
        *,
        now: datetime | None = None,
    ) -> list[Candidate]:
        run_at = now or datetime.now(UTC)
        rows = run_c1(client, engagement_id, now=run_at)
        candidates = [
            Candidate(
                engagement_id=engagement_id,
                generator="c1",
                reason=(
                    f"C1 dead endpoint: in-scope {row.method} {row.host}"
                    f"{row.path_template} has no HIT edge of any kind"
                ),
                criticality=_C1_CRITICALITY,
                target_confidence=row.effective_confidence,
                target_endpoint_id=row.endpoint_id,
            )
            for row in rows
        ]
        log.info(
            "planner.generator.c1.complete",
            engagement_id=engagement_id,
            candidates=len(candidates),
        )
        return candidates

    def propose(self, candidate: Candidate) -> PlannerProposal:
        if candidate.generator != "c1":
            raise ValueError(
                f"C1Generator cannot propose a {candidate.generator!r} candidate"
            )
        if candidate.target_endpoint_id is None:
            raise ValueError("C1 candidate must target an endpoint")
        anon_auth = auth_context_id(
            candidate.engagement_id, compute_anonymous_auth_hash()
        )
        return PlannerProposal(
            engagement_id=candidate.engagement_id,
            generator="c1",
            mode="deterministic",
            test_class="forced_browsing",
            payload_class="no-payload",
            payload_spec=PayloadSpec(kind="none"),
            auth_context_id=anon_auth,
            target_endpoint_id=candidate.target_endpoint_id,
            # Validity is high (validator confirms it); priority is a heuristic
            # hunch derived from the gap's decayed confidence (ADR-0037). A dead
            # endpoint is a low-yield mechanical probe, so the hunch is modest.
            expected_yield=round(0.5 * candidate.target_confidence, 6),
            confidence_method="heuristic",
            justification=candidate.reason,
            expected_outcome=(
                "A non-401/403 response (2xx/3xx/5xx) confirms the endpoint exists "
                "and is reachable unauthenticated — discovered surface now exercised."
            ),
        )


# ---------------------------------------------------------------------------
# LLM-proposing generators (ADR-0037). A different shape from the deterministic
# `CandidateGenerator`: gap selection, pack assembly, the (single) LLM call, and
# handle resolution are one encapsulated pipeline so the LLM seam stays contained
# and the service never touches a model. The service validates + commits whatever
# proposals come back, and persists every call (committed or not).
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LLMProposed:
    """One resolved LLM proposal plus the verbatim call that produced it (audit)."""

    proposal: PlannerProposal
    call: LLMCallResult


@dataclass(frozen=True, slots=True)
class LLMRejected:
    """A draft whose handles did not resolve (hallucination guard) + its call."""

    rejection: DraftRejected
    call: LLMCallResult


@dataclass(frozen=True, slots=True)
class LLMSkipped:
    """A gap that produced no proposal *before* a resolvable draft existed.

    Either the pack was unproposable (no attacker AuthContext) or the model's
    response was unparseable. No `LLMCallResult` to commit; recorded for the run
    audit so a skipped gap is visible, never silently dropped.
    """

    reason: str


@dataclass(frozen=True, slots=True)
class LLMRunResult:
    """The outcome of one LLM generator pass over its candidate gaps."""

    candidates: int
    proposed: tuple[LLMProposed, ...]
    rejected: tuple[LLMRejected, ...]
    skipped: tuple[LLMSkipped, ...]


@runtime_checkable
class LLMProposingGenerator(Protocol):
    """An LLM-proposing generator (ADR-0037): gaps -> packs -> proposals.

    Distinct from the deterministic `CandidateGenerator` because the candidate ->
    proposal step is a model call over an assembled context pack, with rejection /
    skip outcomes a deterministic `propose(candidate)` does not have. `run` does the
    whole pass; the service validates and commits the survivors.
    """

    @property
    def generator_id(self) -> GeneratorId: ...

    @property
    def mode(self) -> ProposalMode: ...

    def run(
        self,
        client: Neo4jClient,
        engagement_id: EngagementId,
        *,
        now: datetime | None = None,
    ) -> LLMRunResult: ...


class C2Generator:
    """LLM-proposing generator for presence-differential authz gaps (ADR-0037).

    Selection reuses the shared coverage library's `run_c2` (ADR-0033/0034) — the
    same gaps `doo coverage c2` surfaces, so planner and coverage never disagree.
    Each gap is deterministically assembled into a bounded, id-free `ContextPack`
    (`assemble.py`); the LLM proposes ONE authz replay by selecting handles and
    classifying (`llm.py`); the deterministic resolver maps the handles back to
    concrete ids and rejects any hallucinated handle. A gap with no resolvable
    attacker AuthContext is skipped before any model call.
    """

    generator_id: GeneratorId = "c2"
    mode: ProposalMode = "llm"

    def __init__(self, caller: LLMCaller) -> None:
        self._caller = caller

    def run(
        self,
        client: Neo4jClient,
        engagement_id: EngagementId,
        *,
        now: datetime | None = None,
    ) -> LLMRunResult:
        run_at = now or datetime.now(UTC)
        gaps = run_c2(client, engagement_id, now=run_at)
        principal_ids = {
            pv.label: pv.principal_id
            for pv in _load_principals(client, engagement_id)
        }

        proposed: list[LLMProposed] = []
        rejected: list[LLMRejected] = []
        skipped: list[LLMSkipped] = []

        for gap in gaps:
            pack = assemble_c2_pack(
                client,
                gap=gap,
                principal_ids=principal_ids,
                code_version=__version__,
                now=run_at,
            )
            if pack is None:
                skipped.append(
                    LLMSkipped(
                        reason=(
                            f"unproposable C2 gap {gap.method} {gap.host}"
                            f"{gap.path_template}: no resolvable attacker AuthContext"
                        )
                    )
                )
                continue
            try:
                call = self._caller.propose(pack)
            except LLMProposalError as exc:
                skipped.append(
                    LLMSkipped(
                        reason=(
                            f"LLM proposal unparseable for endpoint "
                            f"{gap.endpoint_id}: {exc}"
                        )
                    )
                )
                continue
            outcome = resolve_draft(pack, call.draft)
            if isinstance(outcome, DraftRejected):
                rejected.append(LLMRejected(rejection=outcome, call=call))
                continue
            # ADR-0041: deterministically annotate replay-breakers from a reaching
            # 2xx observation (code-set, never the LLM). A frozen proposal -> copy.
            hazards = fetch_reaching_observation_hazards(
                client, engagement_id, endpoint_id=gap.endpoint_id
            )
            proposal = outcome.model_copy(update={"replay_hazards": hazards})
            proposed.append(LLMProposed(proposal=proposal, call=call))

        log.info(
            "planner.generator.c2.complete",
            engagement_id=engagement_id,
            candidates=len(gaps),
            proposed=len(proposed),
            rejected=len(rejected),
            skipped=len(skipped),
        )
        return LLMRunResult(
            candidates=len(gaps),
            proposed=tuple(proposed),
            rejected=tuple(rejected),
            skipped=tuple(skipped),
        )


class C2bGenerator:
    """LLM-proposing generator for content-differential authz gaps (ADR-0037/0033).

    Selection reuses the shared coverage library's `run_c2b` (ADR-0033/0034) — the
    same gaps `doo coverage c2b` surfaces, so planner and coverage never disagree. A
    C2b gap is an endpoint ≥2 principals ALL reached with a 2xx but whose response
    bodies differ (the role-differentiated-200 BOLA/IDOR hotspot). Each gap is
    deterministically assembled into a bounded, id-free `ContextPack`
    (`assemble_c2b_pack`) carrying **every** reaching principal as a candidate
    attacker (any of them could read another's differentiated resource); the LLM
    proposes ONE authz replay by selecting handles and classifying (`llm.py`); the
    deterministic resolver maps the handles back to concrete ids and rejects any
    hallucinated handle. After resolution, the deterministic replay-hazard detector
    (ADR-0041) annotates the proposal from a reaching observation's request fields —
    code-set, never the LLM. A gap with fewer than two resolvable AuthContexts is
    skipped before any model call.
    """

    generator_id: GeneratorId = "c2b"
    mode: ProposalMode = "llm"

    def __init__(self, caller: LLMCaller) -> None:
        self._caller = caller

    def run(
        self,
        client: Neo4jClient,
        engagement_id: EngagementId,
        *,
        now: datetime | None = None,
    ) -> LLMRunResult:
        run_at = now or datetime.now(UTC)
        gaps = run_c2b(client, engagement_id, now=run_at)

        proposed: list[LLMProposed] = []
        rejected: list[LLMRejected] = []
        skipped: list[LLMSkipped] = []

        for gap in gaps:
            pack = assemble_c2b_pack(
                client,
                gap=gap,
                code_version=__version__,
                now=run_at,
            )
            if pack is None:
                skipped.append(
                    LLMSkipped(
                        reason=(
                            f"unproposable C2b gap {gap.method} {gap.host}"
                            f"{gap.path_template}: fewer than two resolvable AuthContexts"
                        )
                    )
                )
                continue
            try:
                call = self._caller.propose(pack)
            except LLMProposalError as exc:
                skipped.append(
                    LLMSkipped(
                        reason=(
                            f"LLM proposal unparseable for endpoint "
                            f"{gap.endpoint_id}: {exc}"
                        )
                    )
                )
                continue
            outcome = resolve_draft(pack, call.draft)
            if isinstance(outcome, DraftRejected):
                rejected.append(LLMRejected(rejection=outcome, call=call))
                continue
            # ADR-0041: deterministically annotate replay-breakers (code-set, never
            # the LLM) from a reaching 2xx observation. A frozen proposal -> copy.
            hazards = fetch_reaching_observation_hazards(
                client, engagement_id, endpoint_id=gap.endpoint_id
            )
            proposal = outcome.model_copy(update={"replay_hazards": hazards})
            proposed.append(LLMProposed(proposal=proposal, call=call))

        log.info(
            "planner.generator.c2b.complete",
            engagement_id=engagement_id,
            candidates=len(gaps),
            proposed=len(proposed),
            rejected=len(rejected),
            skipped=len(skipped),
        )
        return LLMRunResult(
            candidates=len(gaps),
            proposed=tuple(proposed),
            rejected=tuple(rejected),
            skipped=tuple(skipped),
        )


class PlannerConfig(BaseModel):
    """Deterministic planner configuration (ADR-0036).

    `candidate_generators` is the enable/disable allowlist by generator id; an
    empty tuple means *all* registered generators run. `llm_ranking` is the
    optional axis-2 re-rank, default off (the S1 spine never uses it). Every
    setting is fully deterministic.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_generators: tuple[GeneratorId, ...] = GENERATOR_IDS
    llm_ranking: bool = False


# The registry of deterministic-proposing generators, keyed by id. New
# deterministic generators register here; LLM-proposing ones are constructed per
# run (they hold a model caller) and live in `_LLM_GENERATOR_IDS`.
_REGISTRY: dict[GeneratorId, CandidateGenerator] = {
    "c1": C1Generator(),
}

# LLM-proposing generator ids (ADR-0037). Known to config validation, but built by
# the service (not the singleton registry) because each holds a runtime `LLMCaller`.
_LLM_GENERATOR_IDS: tuple[GeneratorId, ...] = ("c2", "c2b")

# Every generator id config may legitimately name (deterministic ∪ LLM).
_KNOWN_GENERATOR_IDS: frozenset[GeneratorId] = frozenset(_REGISTRY) | frozenset(
    _LLM_GENERATOR_IDS
)


def _requested_ids(config: PlannerConfig) -> tuple[GeneratorId, ...]:
    """The requested generator ids, validated against the known set (loud on typo)."""

    requested = config.candidate_generators or GENERATOR_IDS
    unknown = [gid for gid in requested if gid not in _KNOWN_GENERATOR_IDS]
    if unknown:
        raise ValueError(
            f"unknown candidate generator(s) in config: {unknown!r}; "
            f"known: {sorted(_KNOWN_GENERATOR_IDS)}"
        )
    return requested


def requested_llm_generator_ids(config: PlannerConfig) -> tuple[GeneratorId, ...]:
    """The LLM-proposing generator ids this config requests (for CLI dep wiring).

    Empty when the run is purely deterministic — the CLI uses this to decide whether
    to build a model caller + audit sink at all.
    """

    return tuple(gid for gid in _requested_ids(config) if gid in _LLM_GENERATOR_IDS)


def enabled_generators(config: PlannerConfig) -> list[CandidateGenerator]:
    """Resolve the enabled *deterministic* generators from config (ADR-0036).

    An empty `candidate_generators` enables every generator (the default);
    otherwise only the named ids run, in registry order so the candidate set is
    deterministic. LLM-proposing ids (`c2`) are valid but resolved separately by
    `enabled_llm_generators` (they need a model caller); unknown ids raise.
    """

    wanted = set(_requested_ids(config))
    return [gen for gid, gen in _REGISTRY.items() if gid in wanted]


def enabled_llm_generators(
    config: PlannerConfig, *, caller: LLMCaller | None
) -> list[LLMProposingGenerator]:
    """Resolve the enabled LLM-proposing generators, constructed with `caller`.

    Returns empty when no LLM generator is requested. When one *is* requested but no
    `caller` is wired (the default deterministic path), the generator is skipped with
    a warning rather than an error — so a default `propose` stays LLM-free until the
    caller (and audit sink) are supplied.
    """

    wanted = set(_requested_ids(config)) & set(_LLM_GENERATOR_IDS)
    if not wanted:
        return []
    if caller is None:
        log.warning(
            "planner.llm_generators.skipped_no_caller",
            requested=sorted(wanted),
            reason="LLM generator requested but no caller configured",
        )
        return []
    builders: dict[GeneratorId, LLMProposingGenerator] = {
        "c2": C2Generator(caller),
        "c2b": C2bGenerator(caller),
    }
    return [builders[gid] for gid in _LLM_GENERATOR_IDS if gid in wanted]
