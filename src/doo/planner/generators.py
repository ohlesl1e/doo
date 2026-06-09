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

from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from doo.canonical.identity import (
    auth_context_id,
    compute_anonymous_auth_hash,
)
from doo.coverage.queries import run_c1
from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
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


# The full registry of available generators, keyed by id. New generators (C2/C2b/
# C3/C4/sink_params) register here in later tracers without touching the spine.
_REGISTRY: dict[GeneratorId, CandidateGenerator] = {
    "c1": C1Generator(),
}


def enabled_generators(config: PlannerConfig) -> list[CandidateGenerator]:
    """Resolve the enabled generators from config (ADR-0036).

    An empty `candidate_generators` enables every registered generator (the
    default); otherwise only the named ids run, in registry order so the candidate
    set is deterministic. Unknown ids raise — a config typo is loud, not silent.
    """

    requested = config.candidate_generators or GENERATOR_IDS
    unknown = [gid for gid in requested if gid not in _REGISTRY]
    if unknown:
        raise ValueError(
            f"unknown candidate generator(s) in config: {unknown!r}; "
            f"known: {sorted(_REGISTRY)}"
        )
    wanted = set(requested)
    return [gen for gid, gen in _REGISTRY.items() if gid in wanted]
