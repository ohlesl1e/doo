"""Dispatch-run driver: arm → select → iterate (construct → dispatch → record).

The S1 spine end-to-end with **no LLM**: per `TestCase` the Executor's
`(test_class, primary)` constructor builds a `ConcreteRequest`, the Dispatcher
gates it (lease → stub OPA → budget → wire), and the result is committed as a
`RequestObservation(source="agent")` + `EXECUTED_AS` edge plus a `RunOutcome`
ledger row.

The Interpreter (S5) plugs into `_execute_one` after the `primary` send; the
hazard-resolver registry (S3) plugs into the constructor lookup; real Rego (S2)
swaps `StubOpaClient`; the liveness probe (S4) plugs into `executor.classify`.
This module owns only the **orchestration** — every deep decision lives in a
unit-tested module it composes.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from doo.dispatch.executor.classify import (
    LivenessResult,
    classify,
    is_auth_negative,
    is_authz_class,
)
from doo.dispatch.executor.constructors import (
    ConstructorMissingError,
    constructor_for,
)
from doo.dispatch.executor.dispatcher import (
    BudgetTracker,
    Dispatcher,
    LeaseReader,
    OpaClient,
)
from doo.dispatch.executor.evidence import (
    DispatchTestCase,
    EvidenceObservation,
    load_evidence,
)
from doo.dispatch.executor.liveness import LivenessPolicy, LivenessProber, ProbeOutcome
from doo.dispatch.executor.send import Sender
from doo.dispatch.finding import commit_finding, persist_transcript, record_verdict
from doo.dispatch.interpreter.loop import (
    ConfirmLoopResult,
    MultiTurnLLMCaller,
    run_confirm_loop,
)
from doo.dispatch.interpreter.models import SendToolResult
from doo.dispatch.interpreter.tools import ToolContext
from doo.dispatch.ledger import DispatchLedger, record_armed, record_outcome
from doo.dispatch.models import (
    DispatchRun,
    DispatchSelection,
    RequestRole,
    RunBudget,
    RunOutcome,
)
from doo.dispatch.ontology import BodyStore, commit_agent_send
from doo.dispatch.reactive import ReactiveEmitter
from doo.dispatch.secrets import AuthMaterial, SecretStore
from doo.dispatch.selection import select_testcases
from doo.events.slice4 import DispatchStatus
from doo.ids import DispatchRunId, EngagementId, ObservationId, TraceId
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.ids import new_trace_id
from doo.observability.logging import bind_correlation, get_logger
from doo.setup.config import ArmingMode, EngagementConfig, InterpreterMode

log = get_logger(__name__)


def new_run_id() -> DispatchRunId:
    """A fresh dispatch-run id (`run-<12hex>`)."""

    return DispatchRunId(f"run-{uuid.uuid4().hex[:12]}")


@dataclass(frozen=True, slots=True)
class RunDependencies:
    """Every IO dependency the run driver needs, injected (testable seam).

    `evidence_loader` defaults to the graph-backed `load_evidence` but is
    injectable so the e2e and unit tests can supply synthetic evidence without
    seeding a full `RequestObservation` subgraph.
    """

    neo4j: Neo4jClient
    lease: LeaseReader
    opa: OpaClient
    sender: Sender
    secrets: SecretStore
    bodies: BodyStore
    ledger: DispatchLedger
    # The Interpreter's multi-turn caller (S3). `None` → no Interpreter (S1/S2
    # behaviour: `primary` only). Tests inject a `FakeMultiTurnCaller`.
    interpreter: MultiTurnLLMCaller | None = None
    # ADR-0044 liveness disambiguation. `liveness` is the engagement's probe
    # config (declared endpoints + body matchers); `None` → authz 4xx stays the
    # least-bad `ok` (S1/S2 behaviour). `reactive` emits the ADR-0014 refresh
    # signal on `auth_invalid`; `None` → no emit (the helper is S6).
    liveness: LivenessPolicy | None = None
    reactive: ReactiveEmitter | None = None
    evidence_loader: object = None  # Callable | None; defaults to graph-backed.


@dataclass(frozen=True, slots=True)
class RunResult:
    """Outcome of one `execute_run` call: the armed run + per-TestCase outcomes."""

    run: DispatchRun
    outcomes: tuple[RunOutcome, ...]
    requests_sent: int
    # ADR-0044: True iff ≥1 authz 4xx fell back to `ok` because no liveness
    # endpoint was resolvable for its AuthContext (the negatives are unverified).
    liveness_unverified: bool = False


@dataclass
class _SendRecord:
    role: RequestRole
    status: DispatchStatus
    observation_id: ObservationId | None


def arm_run(
    *,
    config: EngagementConfig,
    selection: DispatchSelection,
    actor: str,
    arming: ArmingMode | None = None,
    interpreter: InterpreterMode | None = None,
    budget: RunBudget | None = None,
    now: datetime | None = None,
) -> DispatchRun:
    """Construct a `DispatchRun` from config + CLI overrides (ADR-0042).

    `arming` / `interpreter` default to the engagement's `dispatch:` block; a CLI
    override is re-validated against `environment` by `DispatchRun`'s
    model_validator (defence-in-depth: `--arming auto` on a production engagement
    raises here, naming the rule). `budget` defaults to the engagement's; a CLI
    override may only **tighten** it (the smaller of the two wins).
    """

    run_at = now or datetime.now(UTC)
    cfg_budget = RunBudget(
        request_budget=config.dispatch.request_budget,
        wallclock_budget_s=config.dispatch.wallclock_budget_s,
        max_tool_calls=config.dispatch.max_tool_calls,
    )
    eff_budget = (
        cfg_budget
        if budget is None
        else RunBudget(
            request_budget=min(cfg_budget.request_budget, budget.request_budget),
            wallclock_budget_s=min(
                cfg_budget.wallclock_budget_s, budget.wallclock_budget_s
            ),
            max_tool_calls=min(cfg_budget.max_tool_calls, budget.max_tool_calls),
        )
    )
    return DispatchRun(
        engagement_id=config.engagement.id,
        run_id=new_run_id(),
        trace_id=TraceId(new_trace_id()),
        environment=config.environment,
        arming=arming or config.dispatch.arming,
        interpreter=interpreter or config.dispatch.interpreter,
        selection=selection,
        budget=eff_budget,
        actor=actor,
        armed_at=run_at,
    )


def execute_run(
    run: DispatchRun,
    deps: RunDependencies,
    *,
    testcases: list[DispatchTestCase] | None = None,
) -> RunResult:
    """Drain a dispatch run: select → per-TestCase (construct → dispatch → record).

    `testcases` is injectable for tests; when `None`, the graph-backed selection
    runs. The run is recorded in the dispatch ledger (`armed` row first, then a
    `RunOutcome` per TestCase). The Dispatcher's budget tracker is shared across
    every TestCase so the run-wide `request_budget` is a true ceiling.
    """

    bind_correlation(trace_id=run.trace_id, engagement_id=run.engagement_id)
    record_armed(deps.ledger, run)
    log.info(
        "dispatch.run.armed",
        engagement_id=run.engagement_id,
        run_id=run.run_id,
        actor=run.actor,
        environment=run.environment,
        arming=run.arming,
        interpreter=run.interpreter,
        selection=run.selection.describe(),
        request_budget=run.budget.request_budget,
    )

    selected = (
        testcases
        if testcases is not None
        else select_testcases(
            deps.neo4j, engagement_id=run.engagement_id, selection=run.selection
        )
    )
    tracker = BudgetTracker(run.budget)
    dispatcher = Dispatcher(
        run=run, lease=deps.lease, opa=deps.opa, budget=tracker, sender=deps.sender
    )
    # The liveness prober shares the run `Dispatcher` (probes pass the same gate
    # and count against the same budget) and is cached per (AuthContext, window).
    prober = (
        LivenessProber(
            dispatcher=dispatcher,
            neo4j=deps.neo4j,
            policy=deps.liveness,
            engagement_id=run.engagement_id,
        )
        if deps.liveness is not None
        else None
    )

    outcomes: list[RunOutcome] = []
    for tc in selected:
        outcome = _execute_one(
            tc,
            run=run,
            deps=deps,
            dispatcher=dispatcher,
            prober=prober,
            now=datetime.now(UTC),
        )
        record_outcome(deps.ledger, outcome)
        outcomes.append(outcome)
        # Stop draining once the budget is exhausted: subsequent TestCases would
        # all be `dispatcher_blocked(request_budget_exhausted)`, which is noise.
        if tracker.request_budget_exhausted() or tracker.wallclock_exceeded():
            log.info(
                "dispatch.run.budget_exhausted",
                engagement_id=run.engagement_id,
                run_id=run.run_id,
                sent=tracker.sent,
                drained=len(outcomes),
                selected=len(selected),
            )
            break

    log.info(
        "dispatch.run.complete",
        engagement_id=run.engagement_id,
        run_id=run.run_id,
        selected=len(selected),
        drained=len(outcomes),
        requests_sent=tracker.sent,
    )
    liveness_unverified = prober is not None and bool(prober.acs_without_endpoint)
    if liveness_unverified:
        log.warning(
            "dispatch.run.liveness_unverified",
            engagement_id=run.engagement_id,
            run_id=run.run_id,
            auth_contexts=sorted(prober.acs_without_endpoint),  # type: ignore[union-attr]
        )
    return RunResult(
        run=run,
        outcomes=tuple(outcomes),
        requests_sent=tracker.sent,
        liveness_unverified=liveness_unverified,
    )


def _execute_one(
    tc: DispatchTestCase,
    *,
    run: DispatchRun,
    deps: RunDependencies,
    dispatcher: Dispatcher,
    prober: LivenessProber | None,
    now: datetime,
) -> RunOutcome:
    """Execute one `TestCase`'s `primary` send through the full gate (S1: no Interpreter).

    Order: constructor lookup → evidence load → auth-material lookup →
    hazard-gate (S1: any `replay_hazards` → `hazard_unresolved`, ADR-0043) →
    construct → dispatch → commit `EXECUTED_AS`. Each refusal path is a named
    `RunOutcome` reason that surfaces in `doo dispatch review`.
    """

    eid = run.engagement_id
    sends: list[_SendRecord] = []

    # --- constructor lookup (ADR-0043). ---
    try:
        construct = constructor_for(tc.test_class, "primary")
    except ConstructorMissingError as exc:
        return _outcome(tc, run, "constructor_missing", reason=str(exc), now=now)

    # --- evidence load. ---
    loader = deps.evidence_loader or (
        lambda t: load_evidence(deps.neo4j, engagement_id=eid, testcase=t)
    )
    evidence: EvidenceObservation | None = loader(tc)  # type: ignore[operator]
    if evidence is None:
        return _outcome(
            tc,
            run,
            "hazard_unresolved",
            reason="no evidencing RequestObservation resolves for this target",
            now=now,
        )

    # --- auth-material lookup (ADR-0012/0015). ---
    material = deps.secrets.material_for(tc.auth_context_id)
    if material is None:
        return _outcome(
            tc,
            run,
            "hazard_unresolved",
            reason=(
                f"no live token material for auth_context_id "
                f"{tc.auth_context_id!r} (declared principals only; check "
                "${VAR} env refs)"
            ),
            now=now,
        )

    # --- hazard gate (S1, ADR-0043): no resolver registry yet, so any detected
    # `replay_hazards` is unresolvable → refuse + surface. S3 replaces this with
    # the per-`kind` resolver dispatch. ---
    if tc.replay_hazards:
        return _outcome(
            tc,
            run,
            "hazard_unresolved",
            reason=(
                f"replay_hazards {list(tc.replay_hazards)!r} detected and no "
                "resolver registered (S3); refusing primary send"
            ),
            now=now,
        )

    # --- construct (pure). ---
    request = construct(tc, evidence, material)

    # --- dispatch (lease → OPA → budget → wire → classify). ---
    result = dispatcher.dispatch(
        request,
        test_class=tc.test_class,  # type: ignore[arg-type]
        payload_class=tc.payload_class,
        role="primary",
        principal_tier=material.tier,
        target_confidence=evidence.confidence,
        now=now,
    )

    if not result.sent:
        # Gate deny: no observation (nothing observed). RunOutcome only.
        return _outcome(
            tc, run, "dispatcher_blocked", reason=result.reason, now=now
        )

    # --- authz 4xx disambiguation (ADR-0044). For an authz `primary` whose
    # response reads as an auth negative, the bare status from `Dispatcher` is the
    # least-bad `ok`; resolve it via body-match → liveness probe → re-classify.
    # The probe (if sent) is committed as its own `liveness` observation; a dead
    # token fires the ADR-0014 reactive-refresh event. ---
    final_status: DispatchStatus = result.dispatch_status
    probe_outcome: ProbeOutcome | None = None
    if (
        is_authz_class(tc.test_class)
        and result.response is not None
        and is_auth_negative(result.response)
    ):
        final_status, probe_outcome = _disambiguate_authz(
            tc,
            deps=deps,
            prober=prober,
            evidence=evidence,
            material=material,
            response=result.response,
            now=now,
        )

    # --- commit the `primary` `RequestObservation(source="agent")` + `EXECUTED_AS`. ---
    obs_id = commit_agent_send(
        deps.neo4j,
        engagement_id=eid,
        run_id=run.run_id,
        key_hash=tc.key_hash,
        request=request,
        response=result.response,
        dispatch_status=final_status,
        role="primary",
        auth_context_id=tc.auth_context_id,
        bodies=deps.bodies,
        now=now,
    )
    sends.append(
        _SendRecord(role="primary", status=final_status, observation_id=obs_id)
    )

    # --- commit the liveness probe (if a fresh one was sent) + fire reactive. ---
    if (
        probe_outcome is not None
        and probe_outcome.sent
        and probe_outcome.request is not None
        and probe_outcome.dispatch_result is not None
        and probe_outcome.dispatch_result.sent
    ):
        live_obs = commit_agent_send(
            deps.neo4j,
            engagement_id=eid,
            run_id=run.run_id,
            key_hash=tc.key_hash,
            request=probe_outcome.request,
            response=probe_outcome.dispatch_result.response,
            dispatch_status="ok",
            role="liveness",
            auth_context_id=tc.auth_context_id,
            bodies=deps.bodies,
            now=now,
        )
        sends.append(
            _SendRecord(role="liveness", status="ok", observation_id=live_obs)
        )
    if final_status == "auth_invalid" and deps.reactive is not None:
        deps.reactive.emit_auth_invalid(
            engagement_id=eid,
            run_id=run.run_id,
            auth_context_id=tc.auth_context_id,
            principal_label=material.principal_label,
            key_hash=tc.key_hash,
        )

    # --- Interpreter confirm loop (S3, ADR-0042/0045). Runs only on
    # `dispatch_status = ok` (the bytes reached the test path) and when an
    # Interpreter caller is wired. The `primary` result is pre-loaded into the
    # tool context (ADR-0043: pre-send always-useful roles); every additional
    # send the loop makes goes through the SAME `dispatcher` instance, so the
    # run-wide budget + lease + OPA gate apply identically. ---
    if deps.interpreter is not None and final_status == "ok":
        loop = _run_interpreter(
            tc,
            run=run,
            deps=deps,
            dispatcher=dispatcher,
            evidence=evidence,
            attacker_material=material,
            primary_obs_id=obs_id,
            primary_response=result.response,
            now=now,
        )
        sends.extend(
            _SendRecord(role=r, status=s, observation_id=o)
            for (r, s, o) in loop
        )

    return _outcome(
        tc,
        run,
        "executed",
        reason=None,
        sends=tuple((s.role, s.status, s.observation_id) for s in sends),
        now=now,
    )


def _run_interpreter(
    tc: DispatchTestCase,
    *,
    run: DispatchRun,
    deps: RunDependencies,
    dispatcher: Dispatcher,
    evidence: EvidenceObservation,
    attacker_material: object,
    primary_obs_id: ObservationId,
    primary_response: object,
    now: datetime,
) -> list[tuple[RequestRole, DispatchStatus, ObservationId | None]]:
    """Drive the confirm loop for one TestCase; record verdict (+ Finding on vulnerable).

    Returns the additional `(role, status, obs_id)` sends the loop made (for the
    `RunOutcome.sends` record). The full transcript is persisted to blobs keyed
    by `(run_id, key_hash)` (ADR-0045 replayability).
    """

    ctx = ToolContext(
        run=run,
        neo4j=deps.neo4j,
        dispatcher=dispatcher,
        secrets=deps.secrets,
        bodies=deps.bodies,
        testcase=tc,
        evidence=evidence,
        attacker_material=attacker_material,  # type: ignore[arg-type]
    )
    # Pre-load the `primary` result so the Interpreter sees it on turn 1
    # (ADR-0043). The body is cached under `role:primary` for `read_response_body`.
    body_ref = None
    http_status = None
    size = 0
    if primary_response is not None:
        http_status = primary_response.status  # type: ignore[attr-defined]
        body = primary_response.body  # type: ignore[attr-defined]
        size = len(body)
        if body:
            body_ref = "role:primary"
            ctx.bodies_by_ref[body_ref] = body
    ctx.sent_roles["primary"] = SendToolResult(
        role="primary",
        dispatch_status="ok",
        http_status=http_status,
        response_size=size,
        observation_id=primary_obs_id,
        body_ref=body_ref,
    )
    ctx.observation_ids.append(primary_obs_id)

    loop_result: ConfirmLoopResult = run_confirm_loop(
        ctx,
        deps.interpreter,  # type: ignore[arg-type]
        max_tool_calls=run.budget.max_tool_calls,
        expected_outcome="(see TestCase justification)",
    )

    transcript_key = persist_transcript(
        deps.bodies,
        engagement_id=run.engagement_id,
        run_id=run.run_id,
        key_hash=tc.key_hash,
        transcript=loop_result.transcript,
        verdict=loop_result.verdict,
    )

    record_verdict(
        deps.neo4j,
        engagement_id=run.engagement_id,
        key_hash=tc.key_hash,
        verdict=loop_result.verdict,
        run_id=run.run_id,
        transcript_key=transcript_key,
        now=now,
    )

    if loop_result.verdict.verdict == "vulnerable":
        commit_finding(
            deps.neo4j,
            engagement_id=run.engagement_id,
            testcase=tc,
            verdict=loop_result.verdict,
            run_id=run.run_id,
            transcript_key=transcript_key,
            now=now,
        )

    log.info(
        "interpreter.loop.complete",
        engagement_id=run.engagement_id,
        run_id=run.run_id,
        key_hash=tc.key_hash,
        verdict=loop_result.verdict.verdict,
        tool_calls_used=loop_result.tool_calls_used,
        terminated_by=loop_result.terminated_by,
    )

    # The loop's additional sends (excluding the pre-loaded `primary`).
    return [
        (r.role, r.dispatch_status, r.observation_id)  # type: ignore[misc]
        for role, r in ctx.sent_roles.items()
        if role != "primary"
    ]


def _disambiguate_authz(
    tc: DispatchTestCase,
    *,
    deps: RunDependencies,
    prober: LivenessProber | None,
    evidence: EvidenceObservation,
    material: AuthMaterial,
    response: object,
    now: datetime,
) -> tuple[DispatchStatus, ProbeOutcome | None]:
    """Resolve an authz `primary`'s 4xx → `auth_invalid` / `replay_invalid` / `ok` (ADR-0044).

    Body-match overrides (if declared) run first and short-circuit the probe; a
    non-`ok` result there is necessarily a matcher hit (the probe has not run, so
    `liveness_result` is still `unknown`). Otherwise a liveness probe runs and the
    classifier re-decides with the real probe outcome.
    """

    from doo.dispatch.executor.send import HttpResponse

    assert isinstance(response, HttpResponse)
    matchers = deps.liveness.matchers if deps.liveness is not None else None

    if matchers is not None and not matchers.empty:
        by_match = classify(
            response=response,
            test_class=tc.test_class,  # type: ignore[arg-type]
            role="primary",
            replay_hazards=tc.replay_hazards,
            liveness_result="unknown",
            matchers=matchers,
        )
        if by_match != "ok":
            return by_match, None

    liveness_result: LivenessResult = "unknown"
    outcome: ProbeOutcome | None = None
    if prober is not None:
        outcome = prober.probe(
            auth_context_id=tc.auth_context_id,
            material=material,
            evidence=evidence,
            test_class=tc.test_class,  # type: ignore[arg-type]
            now=now,
        )
        liveness_result = outcome.result

    status = classify(
        response=response,
        test_class=tc.test_class,  # type: ignore[arg-type]
        role="primary",
        replay_hazards=tc.replay_hazards,
        liveness_result=liveness_result,
        matchers=matchers,
    )
    return status, outcome


def _outcome(
    tc: DispatchTestCase,
    run: DispatchRun,
    kind: str,
    *,
    reason: str | None,
    now: datetime,
    sends: tuple[tuple[RequestRole, DispatchStatus, ObservationId | None], ...] = (),
) -> RunOutcome:
    return RunOutcome(
        engagement_id=run.engagement_id,
        run_id=run.run_id,
        key_hash=tc.key_hash,
        test_class=tc.test_class,  # type: ignore[arg-type]
        outcome=kind,  # type: ignore[arg-type]
        reason=reason,
        sends=sends,
        at=now,
    )


__all__ = [
    "RunDependencies",
    "RunResult",
    "arm_run",
    "execute_run",
    "new_run_id",
    "EngagementId",
]
