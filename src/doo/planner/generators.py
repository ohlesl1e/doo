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

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from doo import __version__
from doo.canonical.identity import (
    auth_context_id,
    compute_anonymous_auth_hash,
)
from doo.coverage.queries import _load_principals, run_c1, run_c2, run_c2b, run_c3
from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger
from doo.ontology.queries import for_engagement
from doo.planner.assemble import (
    assemble_boundary_pack,
    assemble_c2_pack,
    assemble_c2b_pack,
    assemble_c3_pack,
    assemble_sink_pack,
    fetch_reaching_observation_hazards,
    fetch_reaching_observation_source_hints,
)
from doo.planner.llm import (
    DraftRejected,
    LLMCaller,
    LLMCallError,
    LLMCallResult,
    LLMProposalError,
    resolve_c3_draft,
    resolve_draft,
    resolve_sink_draft,
)
from doo.planner.models import (
    GENERATOR_IDS,
    Candidate,
    ContextPack,
    GeneratorId,
    LLMProposalDraft,
    PayloadSpec,
    PlannerProposal,
    ProposalMode,
)
from doo.planner.sink_params import sink_role_for_parameter

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
# C3 (leak-to-input) sits beside the authz tiers — a concrete value the app handed
# out and an endpoint consumes. Recorded for when the review view keys on source.
_C3_CRITICALITY = 2.0


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
            # ADR-0049: anonymous attacker → the rotation-stable sentinel pair.
            attacker_principal="anonymous",
            attacker_slot="anonymous",
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


SkipCode = Literal[
    "unproposable_pack", "unparseable_response", "call_timeout", "call_error"
]


@dataclass(frozen=True, slots=True)
class LLMSkipped:
    """A gap that produced no proposal *before* a resolvable draft existed.

    `code` is the cause: `unproposable_pack` (deterministic — the assembler
    returned None, no LLM call made), `unparseable_response` (a response arrived
    but had no usable `propose_test` tool call), `call_timeout` (the call hit
    `timeout_s`), or `call_error` (any other provider failure — auth, rate-limit,
    transport, 5xx). No `LLMCallResult` to commit; recorded for the run audit so a
    skipped gap is visible and the CLI summary can group by cause — N×
    `call_timeout` reads "fix your gateway", N× `unproposable_pack` reads "the
    engagement lacks a second principal".
    """

    code: SkipCode
    reason: str


@dataclass(frozen=True, slots=True)
class LLMRunResult:
    """The outcome of one LLM generator pass over its candidate gaps."""

    candidates: int
    proposed: tuple[LLMProposed, ...]
    rejected: tuple[LLMRejected, ...]
    skipped: tuple[LLMSkipped, ...]


# Per-gap progress callback: `(generator_id, i, total, outcome)`. The CLI passes
# one that drives a progress bar; when `None`, the driver falls back to a
# structured `planner.generator.llm.progress` log line so non-interactive callers
# (and OTel, ADR-0018) still observe per-gap progress.
LLMProgressCallback = Callable[[GeneratorId, int, int, str], None]


def _run_llm_generator[T](
    caller: LLMCaller,
    engagement_id: EngagementId,
    generator_id: GeneratorId,
    candidates: Sequence[T],
    *,
    assemble: Callable[[T], ContextPack | None],
    describe: Callable[[T], str],
    resolve: Callable[[ContextPack, LLMProposalDraft], PlannerProposal | DraftRejected],
    finalize: Callable[[PlannerProposal, T], PlannerProposal] | None = None,
    on_progress: LLMProgressCallback | None = None,
) -> LLMRunResult:
    """The shared LLM-proposing generator loop (ADR-0036/0037).

    Every LLM generator (C2, C2b, C3, capability/tenant boundary, sink) runs the
    same per-candidate skeleton: assemble a bounded `ContextPack`, make one
    proposing call, resolve the returned handles, optionally post-process, and
    aggregate into an `LLMRunResult`. This driver owns that skeleton — and so
    owns, in one place, the things that must behave identically across generators:

    - **Per-gap progress** (`planner.generator.llm.progress` with `i`/`total`/
      `outcome`) so a long-but-healthy run is distinguishable from a hung one.
    - **Skip-code mapping.** `assemble → None` ⇒ `unproposable_pack`; an
      `LLMCallError` ⇒ its `code` (`call_timeout` / `call_error`); an
      `LLMProposalError` ⇒ `unparseable_response`. One bad gap never crashes
      the run.
    - The unified **`.complete`** event (`planner.generator.llm.complete`,
      `generator=<id>`).

    What varies is passed in: `assemble` builds the pack (closing over `client` /
    `now` / any per-generator context), `describe` returns a short label for the
    candidate (used in skip reasons), `resolve` maps a draft's handles back to a
    concrete `PlannerProposal` (or `DraftRejected`), and `finalize` is an optional
    post-resolve transform (C2/C2b stamp deterministic replay-hazards there).
    """

    proposed: list[LLMProposed] = []
    rejected: list[LLMRejected] = []
    skipped: list[LLMSkipped] = []
    total = len(candidates)

    # Surface the candidate count up-front (i=0) so a progress bar can size
    # itself before the first — possibly slow — LLM call returns.
    if on_progress is not None:
        on_progress(generator_id, 0, total, "start")

    def _progress(i: int, outcome: str) -> None:
        if on_progress is not None:
            on_progress(generator_id, i, total, outcome)
            return
        log.info(
            "planner.generator.llm.progress",
            generator=generator_id,
            engagement_id=engagement_id,
            i=i,
            total=total,
            outcome=outcome,
        )

    def _skip(i: int, code: SkipCode, label: str, detail: str) -> None:
        skipped.append(
            LLMSkipped(code=code, reason=f"{generator_id} {label}: {detail}")
        )
        _progress(i, "skipped")

    for i, candidate in enumerate(candidates, 1):
        label = describe(candidate)
        pack = assemble(candidate)
        if pack is None:
            # The specific cause (no attacker auth, <2 contexts, missing parameter)
            # is already in the assembler's structured warning; the skip reason just
            # names the candidate.
            _skip(i, "unproposable_pack", label, "assembler returned no pack")
            continue
        try:
            call = caller.propose(pack)
        except LLMCallError as exc:
            _skip(i, exc.code, label, str(exc))  # type: ignore[arg-type]
            continue
        except LLMProposalError as exc:
            _skip(i, "unparseable_response", label, str(exc))
            continue
        outcome = resolve(pack, call.draft)
        if isinstance(outcome, DraftRejected):
            rejected.append(LLMRejected(rejection=outcome, call=call))
            _progress(i, "rejected")
            continue
        proposal = finalize(outcome, candidate) if finalize is not None else outcome
        proposed.append(LLMProposed(proposal=proposal, call=call))
        _progress(i, "proposed")

    log.info(
        "planner.generator.llm.complete",
        generator=generator_id,
        engagement_id=engagement_id,
        candidates=total,
        proposed=len(proposed),
        rejected=len(rejected),
        skipped=len(skipped),
    )
    return LLMRunResult(
        candidates=total,
        proposed=tuple(proposed),
        rejected=tuple(rejected),
        skipped=tuple(skipped),
    )


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
        on_progress: LLMProgressCallback | None = None,
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
        on_progress: LLMProgressCallback | None = None,
    ) -> LLMRunResult:
        run_at = now or datetime.now(UTC)
        gaps = run_c2(client, engagement_id, now=run_at)
        principal_ids = {
            pv.label: pv.principal_id
            for pv in _load_principals(client, engagement_id)
        }
        return _run_llm_generator(
            self._caller,
            engagement_id,
            "c2",
            gaps,
            on_progress=on_progress,
            assemble=lambda g: assemble_c2_pack(
                client,
                gap=g,
                principal_ids=principal_ids,
                code_version=__version__,
                now=run_at,
            ),
            describe=lambda g: f"{g.method} {g.host}{g.path_template}",
            resolve=lambda pack, draft: resolve_draft(pack, draft, generator="c2"),
            # ADR-0041: deterministically annotate replay-breakers from a reaching
            # 2xx observation (code-set, never the LLM). A frozen proposal -> copy.
            finalize=lambda p, g: p.model_copy(
                update={
                    "replay_hazards": fetch_reaching_observation_hazards(
                        client, engagement_id, endpoint_id=g.endpoint_id
                    ),
                    "hazard_source_hints": fetch_reaching_observation_source_hints(
                        client, engagement_id, endpoint_id=g.endpoint_id
                    ),
                }
            ),
        )


class C2bGenerator:
    """LLM-proposing generator for content-differential authz gaps (ADR-0037/0033).

    Selection reuses the shared coverage library's `run_c2b` (ADR-0033/0034) — the
    same gaps `doo coverage c2b` surfaces, so planner and coverage never disagree. A
    C2b gap is an endpoint ≥2 principals ALL reached with a 2xx but whose response
    bodies differ (the role-differentiated-200 BOLA/IDOR hotspot). Each gap is
    deterministically assembled into a bounded, id-free `ContextPack`
    (`assemble_c2b_pack`) carrying every reaching principal, with the
    **declared-tier** ones marked as candidate attackers (any controlled credential
    could read another's differentiated resource; ADR-0010/0048); the LLM
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
        on_progress: LLMProgressCallback | None = None,
    ) -> LLMRunResult:
        run_at = now or datetime.now(UTC)
        gaps = run_c2b(client, engagement_id, now=run_at)
        return _run_llm_generator(
            self._caller,
            engagement_id,
            "c2b",
            gaps,
            on_progress=on_progress,
            assemble=lambda g: assemble_c2b_pack(
                client, gap=g, code_version=__version__, now=run_at
            ),
            describe=lambda g: f"{g.method} {g.host}{g.path_template}",
            resolve=lambda pack, draft: resolve_draft(pack, draft, generator="c2b"),
            # ADR-0041: deterministically annotate replay-breakers (code-set, never
            # the LLM) from a reaching 2xx observation. A frozen proposal -> copy.
            finalize=lambda p, g: p.model_copy(
                update={
                    "replay_hazards": fetch_reaching_observation_hazards(
                        client, engagement_id, endpoint_id=g.endpoint_id
                    ),
                    "hazard_source_hints": fetch_reaching_observation_source_hints(
                        client, engagement_id, endpoint_id=g.endpoint_id
                    ),
                }
            ),
        )


class C3Generator:
    """LLM-proposing generator for leak-to-input pivots (ADR-0037, issue #53).

    Selection reuses the shared coverage library's `run_c3` — the same pivots
    `doo coverage c3` surfaces. A C3 gap is an `ObservedValue` the app yielded in a
    response and that an in-scope endpoint consumes as a parameter. Each gap is
    assembled into a bounded `ContextPack` (`assemble_c3_pack`) naming the input
    Parameter as the target and one identity to send as; the LLM classifies the test
    and selects handles (`resolve_c3_draft`); the deterministic resolver fixes
    `payload_spec = observed_value(value_hash)` (the value is known at propose time,
    ADR-0037) and the Validator resolves it to a real `payload_hash`. No
    replay-hazard annotation — C3 is a leak-replay, not a session/authz replay. A row
    with no named parameter (or no resolvable Parameter / send-as identity) is skipped
    before any model call.
    """

    generator_id: GeneratorId = "c3"
    mode: ProposalMode = "llm"

    def __init__(self, caller: LLMCaller) -> None:
        self._caller = caller

    def run(
        self,
        client: Neo4jClient,
        engagement_id: EngagementId,
        *,
        now: datetime | None = None,
        on_progress: LLMProgressCallback | None = None,
    ) -> LLMRunResult:
        run_at = now or datetime.now(UTC)
        gaps = run_c3(client, engagement_id, now=run_at)

        return _run_llm_generator(
            self._caller,
            engagement_id,
            "c3",
            gaps,
            on_progress=on_progress,
            assemble=lambda g: assemble_c3_pack(
                client, gap=g, code_version=__version__, now=run_at
            ),
            describe=lambda g: (
                f"{g.target_method} {g.target_host}{g.target_path_template} "
                f"param {g.parameter_name!r}"
            ),
            resolve=resolve_c3_draft,
        )


def _load_boundary_ids(
    client: Neo4jClient, engagement_id: EngagementId, kinds: tuple[str, ...]
) -> list[tuple[str, str]]:
    """Active `TrustBoundary` (id, kind) pairs of the given kinds, ordered by id."""

    frag = for_engagement(engagement_id, var="tb")
    rows = client.execute_read(
        f"""
        MATCH (tb:TrustBoundary)
        {frag.and_("(tb.status IS NULL OR tb.status = 'active') AND tb.kind IN $kinds")}
        RETURN tb.id AS id, tb.kind AS kind
        ORDER BY tb.id
        """,
        kinds=list(kinds),
        **frag.parameters,
    )
    return [(str(r["id"]), str(r["kind"])) for r in rows]


def _run_boundary_generator(
    client: Neo4jClient,
    engagement_id: EngagementId,
    caller: LLMCaller,
    *,
    kinds: tuple[str, ...],
    generator_id: GeneratorId,
    now: datetime | None,
    on_progress: LLMProgressCallback | None = None,
) -> LLMRunResult:
    """Capability/tenant boundary generator pass (ADR-0039) via the shared driver.

    Iterates the engagement's `TrustBoundary` nodes of the given kinds; each becomes
    a bounded boundary pack (`assemble_boundary_pack` — endpoint from `DERIVED_FROM`
    evidence, attacker side marked); the LLM proposes one boundary replay; the shared
    `resolve_draft` maps the handles back, stamping `generator_id`, and produces a
    `TARGETS_BOUNDARY` proposal. A boundary that can't be assembled (ambiguous tier,
    missing tenant auth, no evidence endpoint) is skipped before any model call.
    """

    run_at = now or datetime.now(UTC)
    boundaries = _load_boundary_ids(client, engagement_id, kinds)
    return _run_llm_generator(
        caller,
        engagement_id,
        generator_id,
        boundaries,
        on_progress=on_progress,
        assemble=lambda b: assemble_boundary_pack(
            client,
            engagement_id=engagement_id,
            boundary_id=b[0],
            boundary_kind=b[1],
            code_version=__version__,
            now=run_at,
        ),
        describe=lambda b: f"boundary {b[0]} ({b[1]})",
        resolve=lambda pack, draft: resolve_draft(pack, draft, generator=generator_id),
    )


class C4Generator:
    """LLM-proposing generator for **capability** `TrustBoundary`s (ADR-0039).

    Consumes the capability boundaries S4 inferred (scope/mfa/freshness — the same
    tier deltas C4 surfaces) and proposes a privilege-escalation replay: the
    evidenced request (reached by the stronger token) replayed under the weaker
    token, `TARGETS_BOUNDARY`.
    """

    generator_id: GeneratorId = "c4"
    mode: ProposalMode = "llm"

    def __init__(self, caller: LLMCaller) -> None:
        self._caller = caller

    def run(
        self,
        client: Neo4jClient,
        engagement_id: EngagementId,
        *,
        now: datetime | None = None,
        on_progress: LLMProgressCallback | None = None,
    ) -> LLMRunResult:
        return _run_boundary_generator(
            client, engagement_id, self._caller,
            kinds=("scope", "mfa", "freshness"), generator_id="c4", now=now,
            on_progress=on_progress,
        )


class TenantBoundaryGenerator:
    """LLM-proposing generator for **tenant** `TrustBoundary`s (ADR-0039).

    Consumes tenant boundaries (Tenant pairs sharing an endpoint) and proposes a
    cross-tenant replay: hold tenant-A's resource ref, swap tenant-B's auth,
    `TARGETS_BOUNDARY`.
    """

    generator_id: GeneratorId = "tenant"
    mode: ProposalMode = "llm"

    def __init__(self, caller: LLMCaller) -> None:
        self._caller = caller

    def run(
        self,
        client: Neo4jClient,
        engagement_id: EngagementId,
        *,
        now: datetime | None = None,
        on_progress: LLMProgressCallback | None = None,
    ) -> LLMRunResult:
        return _run_boundary_generator(
            client, engagement_id, self._caller,
            kinds=("tenant",), generator_id="tenant", now=now,
            on_progress=on_progress,
        )


# The engagement-config key the sink probe resolves to (ADR-0037/0012). A single
# canonical callback/marker; the slice-4 dispatcher substitutes the real value.
_SINK_CONFIG_KEY = "sink_callback"


def _load_sink_parameters(
    client: Neo4jClient, engagement_id: EngagementId
) -> list[tuple[str, str]]:
    """Active (parameter_id, sink_role) pairs whose name/shape flags a sink (S6)."""

    frag = for_engagement(engagement_id, var="p")
    rows = client.execute_read(
        f"""
        MATCH (e:Endpoint)-[:HAS_PARAMETER]->(p:Parameter)
        {frag.and_("p.status = 'active' AND e.status = 'active'")}
        RETURN p.id AS id, p.name AS name
        ORDER BY p.id
        """,
        **frag.parameters,
    )
    out: list[tuple[str, str]] = []
    for r in rows:
        role = sink_role_for_parameter(str(r["name"]))
        if role is not None:
            out.append((str(r["id"]), role))
    return out


class SinkGenerator:
    """LLM-proposing generator for sink-shaped parameters (ADR-0036, S6).

    Deterministically detects `url_sink`/`redirect_target`/`file_path` parameters
    (`sink_params.py`) — dangerous surface no coverage query encodes — and proposes
    an SSRF / open-redirect / path-traversal test against each. The payload is the
    single **configured** canonical probe (`payload_spec = configured`), resolved by
    the Validator; the LLM only classifies + selects the sink-parameter handle.
    """

    generator_id: GeneratorId = "sink"
    mode: ProposalMode = "llm"

    def __init__(self, caller: LLMCaller) -> None:
        self._caller = caller

    def run(
        self,
        client: Neo4jClient,
        engagement_id: EngagementId,
        *,
        now: datetime | None = None,
        on_progress: LLMProgressCallback | None = None,
    ) -> LLMRunResult:
        run_at = now or datetime.now(UTC)
        sinks = _load_sink_parameters(client, engagement_id)

        return _run_llm_generator(
            self._caller,
            engagement_id,
            "sink",
            sinks,
            on_progress=on_progress,
            assemble=lambda s: assemble_sink_pack(
                client,
                engagement_id=engagement_id,
                parameter_id=s[0],
                sink_role=s[1],
                code_version=__version__,
                now=run_at,
            ),
            describe=lambda s: f"param {s[0]} ({s[1]})",
            resolve=lambda pack, draft: resolve_sink_draft(
                pack, draft, config_key=_SINK_CONFIG_KEY
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


# The registry of deterministic-proposing generators, keyed by id. New
# deterministic generators register here; LLM-proposing ones are constructed per
# run (they hold a model caller) and live in `_LLM_GENERATOR_IDS`.
_REGISTRY: dict[GeneratorId, CandidateGenerator] = {
    "c1": C1Generator(),
}

# LLM-proposing generator ids (ADR-0037). Known to config validation, but built by
# the service (not the singleton registry) because each holds a runtime `LLMCaller`.
_LLM_GENERATOR_IDS: tuple[GeneratorId, ...] = ("c2", "c2b", "c3", "c4", "tenant", "sink")

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
        "c3": C3Generator(caller),
        "c4": C4Generator(caller),
        "tenant": TenantBoundaryGenerator(caller),
        "sink": SinkGenerator(caller),
    }
    return [builders[gid] for gid in _LLM_GENERATOR_IDS if gid in wanted]
