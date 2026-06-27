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
from collections.abc import Callable
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
    _splice_auth,
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
from doo.dispatch.executor.hazards import (
    HazardSplice,
    Unresolved,
    apply_splices,
    locate_hazard,
    resolve_hazard,
)
from doo.dispatch.executor.liveness import LivenessPolicy, LivenessProber, ProbeOutcome
from doo.dispatch.executor.send import HttpResponse, Sender
from doo.dispatch.finding import (
    FindingCommitOutcome,
    commit_finding,
    persist_transcript,
    record_verdict,
)
from doo.dispatch.interpreter.loop import (
    ConfirmLoopResult,
    MultiTurnLLMCaller,
    run_confirm_loop,
)
from doo.dispatch.interpreter.mode import select_interpreter_mode
from doo.dispatch.interpreter.models import InterpreterVerdict, SendToolResult
from doo.dispatch.interpreter.tools import ToolContext
from doo.dispatch.ledger import (
    DispatchLedger,
    record_armed,
    record_outcome,
    resolve_overrides,
)
from doo.dispatch.models import (
    ROLES_BY_TEST_CLASS,
    ConcreteRequest,
    DispatchLedgerEvent,
    DispatchRun,
    DispatchSelection,
    HazardInfo,
    RequestRole,
    RunBudget,
    RunOutcome,
)
from doo.dispatch.ontology import BodyStore, commit_agent_send
from doo.dispatch.reactive import ReactiveEmitter
from doo.dispatch.rotation import is_waiting_on_rotation
from doo.dispatch.secrets import AuthMaterial, SecretStore, SlotMaterialMissing
from doo.dispatch.selection import count_already_completed, select_testcases
from doo.events.execution import DISPATCH_STATUSES, DispatchStatus
from doo.ids import (
    AuthContextId,
    DispatchRunId,
    EngagementId,
    ObservationId,
    TraceId,
)
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.ids import new_trace_id
from doo.observability.logging import bind_correlation, get_logger
from doo.setup.config import ArmingMode, EngagementConfig, InterpreterMode

log = get_logger(__name__)

# #181: how often `execute_run` fires `on_progress` while draining — a coarse
# "still working" heartbeat for long runs, not a per-send line.
_PROGRESS_EVERY = 10


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
    # The engagement's `auth.session_cookie_names` (ADR-0026), threaded onto every
    # loaded `EvidenceObservation` so cookie-kind credentials are spliced under the
    # configured name (#176). Empty → the `_splice_auth` `"session"` fallback.
    session_cookie_names: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RunResult:
    """Outcome of one `execute_run` call: the armed run + per-TestCase outcomes."""

    run: DispatchRun
    outcomes: tuple[RunOutcome, ...]
    requests_sent: int
    # ADR-0044: True iff ≥1 authz 4xx fell back to `ok` because no liveness
    # endpoint was resolvable for its AuthContext (the negatives are unverified).
    liveness_unverified: bool = False
    # #180: TestCases skipped because they already had an `ok` primary (resume
    # semantics). Only meaningful on the graph-backed selection path with
    # `selection.skip_completed`; 0 when forced or when `testcases` was injected.
    skipped_completed: int = 0
    # #181: the drain stopped early on a Ctrl-C or an unexpected per-TestCase
    # raise — `outcomes` is whatever drained before the stop. The summary is still
    # rendered (and noted as partial) instead of being lost with the run.
    interrupted: bool = False


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
    skipped_completed: int | None = None,
    on_progress: Callable[[int, int, int], None] | None = None,
) -> RunResult:
    """Drain a dispatch run: select → per-TestCase (construct → dispatch → record).

    `testcases` is injectable for tests and for the CLI's pre-run path (which has
    already selected the to-send list); when `None`, the graph-backed selection
    runs. `skipped_completed` lets that caller pass the resume-skipped count it
    already computed (ignored on the graph-backed path, which computes its own).
    `on_progress(sent, drained, selected)` is invoked every `_PROGRESS_EVERY`
    TestCases for a coarse progress line (the CLI prints one even under `--quiet`).

    The run is recorded in the dispatch ledger (`armed` row first, then a
    `RunOutcome` per TestCase). The Dispatcher's budget tracker is shared across
    every TestCase so the run-wide `request_budget` is a true ceiling. A Ctrl-C or
    an unexpected per-TestCase raise stops the drain but still returns a
    `RunResult` (`interrupted=True`) with whatever drained — the summary is never
    lost (#181).
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

    # #180: on the graph-backed path, the count of finished TestCases the resume
    # filter excluded. When `testcases` is injected, honour the caller's
    # pre-computed count (the CLI pre-run path) and default to 0 otherwise.
    if testcases is not None:
        selected = testcases
        skipped = skipped_completed or 0
    else:
        selected = select_testcases(
            deps.neo4j, engagement_id=run.engagement_id, selection=run.selection
        )
        skipped = (
            count_already_completed(
                deps.neo4j, engagement_id=run.engagement_id, selection=run.selection
            )
            if run.selection.skip_completed
            else 0
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

    # Hazard overrides set via `doo dispatch review` (set-hint / ignore-hazard);
    # read once, consulted per-TestCase before resolving its replay_hazards (S5).
    overrides = resolve_overrides(deps.ledger, run.engagement_id)

    outcomes: list[RunOutcome] = []
    interrupted = False
    # #181: a Ctrl-C or an unexpected per-TestCase raise stops the drain but still
    # returns a `RunResult` from whatever drained, so the human summary (and the
    # already-committed `EXECUTED_AS` edges) are never lost with the run.
    try:
        for tc in selected:
            outcome = _execute_one(
                tc,
                run=run,
                deps=deps,
                dispatcher=dispatcher,
                prober=prober,
                overrides=overrides,
                now=datetime.now(UTC),
            )
            record_outcome(deps.ledger, outcome)
            outcomes.append(outcome)
            if on_progress is not None and len(outcomes) % _PROGRESS_EVERY == 0:
                on_progress(tracker.sent, len(outcomes), len(selected))
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
    except KeyboardInterrupt:
        interrupted = True
        log.warning(
            "dispatch.run.interrupted",
            engagement_id=run.engagement_id,
            run_id=run.run_id,
            drained=len(outcomes),
            selected=len(selected),
        )
    except Exception as exc:
        # An unexpected raise inside a TestCase (not the Interpreter, which is
        # isolated per-TestCase by #179). Preserve the partial run + summary
        # instead of losing it; the traceback rides the structured log.
        interrupted = True
        log.warning(
            "dispatch.run.aborted",
            engagement_id=run.engagement_id,
            run_id=run.run_id,
            drained=len(outcomes),
            selected=len(selected),
            error=f"{type(exc).__name__}: {exc}",
        )

    log.info(
        "dispatch.run.complete",
        engagement_id=run.engagement_id,
        run_id=run.run_id,
        selected=len(selected),
        drained=len(outcomes),
        requests_sent=tracker.sent,
        interrupted=interrupted,
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
        skipped_completed=skipped,
        interrupted=interrupted,
    )


def _execute_one(
    tc: DispatchTestCase,
    *,
    run: DispatchRun,
    deps: RunDependencies,
    dispatcher: Dispatcher,
    prober: LivenessProber | None,
    overrides: dict[tuple[str, str], DispatchLedgerEvent],
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

    # --- rotation-watermark guard (ADR-0053, #170). A TestCase whose `primary`
    # already came back `auth_invalid` must NOT be re-dispatched until its slot
    # has rotated past that failure (an `active` declared AuthContext newer than
    # the failed edge). Below the watermark, refuse without sending — this is the
    # anti-storm gate that stops blind re-runs hammering a still-dead slot (#166).
    # Skipped when the attacker identity is absent (pre-ADR-0049 TestCases). ---
    if (
        tc.attacker_principal is not None
        and tc.attacker_slot is not None
        and is_waiting_on_rotation(
            deps.neo4j,
            engagement_id=eid,
            key_hash=tc.key_hash,
            principal_label=tc.attacker_principal,
            slot=tc.attacker_slot,
        )
    ):
        return _outcome(
            tc,
            run,
            "waiting_on_rotation",
            reason=(
                "slot has not rotated since the last auth_invalid; "
                "re-dispatch refused (waiting on rotation)"
            ),
            now=now,
        )

    # --- evidence load. ---
    loader = deps.evidence_loader or (
        lambda t: load_evidence(
            deps.neo4j,
            engagement_id=eid,
            testcase=t,
            session_cookie_names=deps.session_cookie_names,
        )
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

    # --- auth-material lookup (ADR-0012/0015 + ADR-0049 slot indirection). ---
    try:
        material = deps.secrets.material_for(tc.auth_context_id)
    except SlotMaterialMissing as exc:
        return _outcome(
            tc,
            run,
            "hazard_unresolved",
            reason=(
                f"declared principal {exc.principal_label!r} slot {exc.slot!r} "
                f"has no live material (env unset and no rotation entry)"
            ),
            now=now,
        )
    if material is None:
        return _outcome(
            tc,
            run,
            "hazard_unresolved",
            reason=(
                f"auth_context_id {tc.auth_context_id!r} is not a declared "
                f"credential (discovered-tier; un-armable)"
            ),
            now=now,
        )

    # --- replay-hazard resolution (S5, ADR-0041/0043): resolve each detected
    # hazard (csrf fetch+splice / nonce strip / timestamp now) into edits applied
    # to the evidence before the pure constructor runs. Warmup fetches are real
    # Dispatcher sends (role `hazard_warmup`). An unresolved hazard refuses the
    # `primary` send and surfaces in `doo dispatch review`. ---
    hazard_sends: list[_SendRecord] = []
    if tc.replay_hazards:
        adjusted, unresolved, hazard_sends = _resolve_replay_hazards(
            tc,
            run=run,
            deps=deps,
            dispatcher=dispatcher,
            evidence=evidence,
            material=material,
            overrides=overrides,
            now=now,
        )
        if unresolved is not None:
            return _outcome(
                tc,
                run,
                "hazard_unresolved",
                reason=f"{unresolved.kind} on {unresolved.param!r}: {unresolved.reason}",
                hazard=unresolved,
                now=now,
            )
        evidence = adjusted
    sends.extend(hazard_sends)

    # --- verify-on-first-use (ADR-0053, #168). Material resolved from the
    # rotation overlay is a freshly-minted, not-yet-proven credential. Probe it
    # before sending ANY primary against it: a `dead` probe refuses the primary
    # (don't burn it) and fires the ADR-0014 reactive event so the helper
    # rotates; `live`/`unknown` fall through. The probe is cached per
    # (principal, slot), so a later authz-4xx disambiguation reuses this verdict
    # (no second send). A real probe send is committed as its own `liveness`
    # observation regardless of the verdict, so no wire send goes unobserved. ---
    if material.from_rotation and prober is not None:
        pre = prober.probe(
            auth_context_id=tc.auth_context_id,
            material=material,
            evidence=evidence,
            test_class=tc.test_class,  # type: ignore[arg-type]
            now=now,
        )
        if (
            pre.sent
            and pre.request is not None
            and pre.dispatch_result is not None
            and pre.dispatch_result.sent
        ):
            pre_obs = commit_agent_send(
                deps.neo4j,
                engagement_id=eid,
                run_id=run.run_id,
                key_hash=tc.key_hash,
                request=pre.request,
                response=pre.dispatch_result.response,
                dispatch_status="ok",
                role="liveness",
                auth_context_id=tc.auth_context_id,
                bodies=deps.bodies,
                now=now,
            )
            sends.append(
                _SendRecord(role="liveness", status="ok", observation_id=pre_obs)
            )
        if pre.result == "dead":
            if deps.reactive is not None:
                deps.reactive.emit_auth_invalid(
                    engagement_id=eid,
                    run_id=run.run_id,
                    auth_context_id=tc.auth_context_id,
                    principal_label=material.principal_label,
                    key_hash=tc.key_hash,
                )
            return _outcome(
                tc,
                run,
                "auth_unverified",
                reason="rotated credential failed pre-flight liveness probe",
                sends=tuple(
                    (s.role, s.status, s.observation_id) for s in sends
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
        reason=result.reason,
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
    finding_reasserted: tuple[str, str] | None = None
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
            for (r, s, o) in loop.extra_sends
        )
        # #125: a re-commit onto a decided Finding surfaces in the run summary.
        if (
            loop.finding is not None
            and not loop.finding.created
            and loop.finding.finding_status != "proposed"
        ):
            finding_reasserted = (
                str(loop.finding.finding_key),
                loop.finding.finding_status,
            )

    return _outcome(
        tc,
        run,
        "executed",
        reason=None,
        sends=tuple((s.role, s.status, s.observation_id) for s in sends),
        finding_reasserted=finding_reasserted,
        now=now,
    )


#: Test classes whose verdict requires a baseline differential (any class whose
#: role enum has more than `primary`). Derived from `ROLES_BY_TEST_CLASS` so a
#: new authz class automatically picks up the guard.
_DIFFERENTIAL_CLASSES: frozenset[str] = frozenset(
    cls for cls, roles in ROLES_BY_TEST_CLASS.items() if len(roles) > 1
)
#: For each differential class, the non-`primary` roles the guard expects the
#: confirm loop to have exercised. Keyed `str` (matching the guard's `test_class`
#: param) so the lookup needs no `TestClass` cast.
_BASELINE_ROLES_BY_CLASS: dict[str, tuple[RequestRole, ...]] = {
    cls: tuple(r for r in roles if r != "primary")
    for cls, roles in ROLES_BY_TEST_CLASS.items()
    if len(roles) > 1
}


@dataclass(frozen=True, slots=True)
class _InterpreterOutcome:
    """`_run_interpreter`'s return: extra sends + the (optional) Finding outcome.

    `extra_sends` are the loop's non-`primary` sends (for `RunOutcome.sends`).
    `finding` is the `commit_finding` result when the (guarded) verdict was
    `vulnerable`; the caller surfaces a re-assert on a decided Finding (#125).
    """

    extra_sends: list[tuple[RequestRole, DispatchStatus, ObservationId | None]]
    finding: FindingCommitOutcome | None


def _guard_differential_verdict(
    verdict: InterpreterVerdict,
    *,
    test_class: str,
    sent_roles: dict[RequestRole, SendToolResult],
) -> InterpreterVerdict:
    """ADR-0047 fail-closed: a differential `vulnerable` with no `ok` baseline → `inconclusive`.

    The Interpreter is advisory; this deterministic guard is the floor. A
    `vulnerable` verdict on a differential test class (idor / bola / auth-bypass
    / privilege-escalation / boundary-violation) where no non-`primary` role
    reached `dispatch_status='ok'` cannot be sound — there is no comparison
    evidence. Downgrade to `inconclusive` and log; the original LLM verdict is
    preserved verbatim in the persisted transcript (the run driver passes
    `loop_result.verdict` to `persist_transcript`).
    """

    if verdict.verdict != "vulnerable" or test_class not in _DIFFERENTIAL_CLASSES:
        return verdict
    baseline_ok = any(
        role != "primary" and r.dispatch_status == "ok"
        for role, r in sent_roles.items()
    )
    if baseline_ok:
        return verdict
    # #124 acceptance criterion 2: if the Interpreter attempted EVERY baseline
    # this class offers and the system could arm none of them
    # (`dispatch_status="unarmable"` — discovered-tier victim with no live
    # material, recorded by the send tool before raising `ToolError`), defer to
    # the LLM verdict. The tool error already steers it toward `inconclusive`
    # unless the primary body alone is conclusive; that judgment is the floor
    # here. A baseline that *could* be armed but failed on the wire
    # (`transport_error` etc.) is NOT this case — that's a re-run, downgrade.
    expected_baselines = _BASELINE_ROLES_BY_CLASS[test_class]
    if expected_baselines and all(
        sent_roles.get(r) is not None
        and sent_roles[r].dispatch_status == "unarmable"
        for r in expected_baselines
    ):
        log.info(
            "interpreter.verdict_deferred",
            test_class=test_class,
            reason="all baseline roles unarmable; deferring to LLM judgment",
            baselines=list(expected_baselines),
        )
        return verdict
    log.warning(
        "interpreter.verdict_downgraded",
        test_class=test_class,
        from_="vulnerable",
        to="inconclusive",
        reason="no baseline role reached dispatch_status=ok",
    )
    return InterpreterVerdict(
        verdict="inconclusive",
        justification=(
            "[deterministic downgrade: differential test, no baseline reached "
            f"the wire] {verdict.justification}"
        ),
        observed_vs_expected=verdict.observed_vs_expected,
        evidence_refs=verdict.evidence_refs,
        # vuln_category / proposed_severity / affected_refs MUST be absent on
        # `inconclusive` (`InterpreterVerdict._vulnerable_requires_category`).
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
) -> _InterpreterOutcome:
    """Drive the confirm loop for one TestCase; record verdict (+ Finding on vulnerable).

    Returns the loop's additional sends (for `RunOutcome.sends`) and the
    `commit_finding` outcome (so a re-assert on a decided Finding surfaces in
    the run summary, #125). The full transcript is persisted to blobs keyed by
    `(run_id, key_hash)` (ADR-0045 replayability).
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

    # #124 / ADR-0047: deterministic floor under the LLM verdict. The
    # *transcript* (below) records the original verdict; the *recorded* verdict
    # and Finding commit use the guarded one.
    verdict = _guard_differential_verdict(
        loop_result.verdict, test_class=tc.test_class, sent_roles=ctx.sent_roles
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
        verdict=verdict,
        run_id=run.run_id,
        transcript_key=transcript_key,
        now=now,
    )

    finding_outcome: FindingCommitOutcome | None = None
    if verdict.verdict == "vulnerable":
        finding_outcome = commit_finding(
            deps.neo4j,
            engagement_id=run.engagement_id,
            testcase=tc,
            verdict=verdict,
            run_id=run.run_id,
            transcript_key=transcript_key,
            now=now,
        )

    # Follow-ups → the InterpreterMode strategy (ADR-0042/0045/S8). `confirm`
    # re-validates + commits them at `review_status=proposed` (source
    # `llm-interpreter`); `freelance` raises (unimplemented seam). Never in-run.
    if loop_result.verdict.follow_ups:
        select_interpreter_mode(run.interpreter).handle_follow_ups(
            loop_result.verdict.follow_ups,
            neo4j=deps.neo4j,
            engagement_id=run.engagement_id,
            auth_context_id=tc.auth_context_id,
            default_target_endpoint_id=tc.target_endpoint_id,
            now=now,
        )

    log.info(
        "interpreter.loop.complete",
        engagement_id=run.engagement_id,
        run_id=run.run_id,
        key_hash=tc.key_hash,
        verdict=verdict.verdict,
        llm_verdict=loop_result.verdict.verdict,
        tool_calls_used=loop_result.tool_calls_used,
        terminated_by=loop_result.terminated_by,
    )

    # The loop's additional sends (excluding the pre-loaded `primary`). Filter
    # to real `DispatchStatus` values: `sent_roles` may carry the loop-local
    # `"unarmable"` sentinel (recorded by the send tool when a baseline could
    # not be armed — see `_guard_differential_verdict`), which never reached
    # the wire and is NOT a valid `EXECUTED_AS.dispatch_status` / ledger send.
    extra_sends: list[tuple[RequestRole, DispatchStatus, ObservationId | None]] = [
        (r.role, r.dispatch_status, r.observation_id)
        for role, r in ctx.sent_roles.items()
        if role != "primary" and r.dispatch_status in DISPATCH_STATUSES
    ]
    return _InterpreterOutcome(extra_sends=extra_sends, finding=finding_outcome)


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


def _parse_hints(hints: tuple[str, ...]) -> dict[str, str]:
    """Parse `("csrf_token=<url>", …)` into `{kind: url}` (planner-emitted hints)."""

    out: dict[str, str] = {}
    for h in hints:
        kind, _, url = h.partition("=")
        if kind and url:
            out[kind] = url
    return out


def _resolve_replay_hazards(
    tc: DispatchTestCase,
    *,
    run: DispatchRun,
    deps: RunDependencies,
    dispatcher: Dispatcher,
    evidence: EvidenceObservation,
    material: AuthMaterial,
    overrides: dict[tuple[str, str], DispatchLedgerEvent],
    now: datetime,
) -> tuple[EvidenceObservation, HazardInfo | None, list[_SendRecord]]:
    """Resolve `tc.replay_hazards` into evidence edits (ADR-0041/0043).

    Returns `(adjusted_evidence, unresolved_or_None, warmup_sends)`. For each
    hazard kind: an `ignore_hazard` override drops it (send anyway); otherwise the
    field is located in the evidence and resolved (csrf fetch+splice / nonce strip
    / timestamp now). The CSRF `source_hint` precedence is: `set_hint` override →
    planner-emitted hint → the evidence's observed `Referer`. The first
    `Unresolved` hazard short-circuits to a refusal.
    """

    planner_hints = _parse_hints(tc.hazard_source_hints)
    referer = next(
        (v for k, v in evidence.headers.items() if k.lower() == "referer"), None
    )
    warmup_sends: list[_SendRecord] = []
    splices: list[HazardSplice] = []

    for kind in tc.replay_hazards:
        ov = overrides.get((str(tc.key_hash), kind))
        if ov is not None and ov.override_action == "ignore_hazard":
            continue  # tester accepted the replay_invalid risk — send anyway.

        located = locate_hazard(kind, evidence)  # type: ignore[arg-type]
        if located is None:
            # Detected at plan time but absent from this evidence — nothing to
            # replay, so nothing to break.
            continue

        source_hint: str | None = None
        if ov is not None and ov.override_action == "set_hint":
            source_hint = ov.hint
        source_hint = source_hint or planner_hints.get(kind) or referer

        def _fetch(method: str, path: str) -> HttpResponse | None:
            req = _warmup_request(
                method=method, path=path, evidence=evidence, material=material,
                auth_context_id=tc.auth_context_id,
            )
            dr = dispatcher.dispatch(
                req,
                test_class=tc.test_class,  # type: ignore[arg-type]
                payload_class="benign-probe",
                role="hazard_warmup",
                principal_tier=material.tier,
                target_confidence=evidence.confidence,
                now=now,
            )
            if dr.sent and dr.response is not None:
                obs = commit_agent_send(
                    deps.neo4j,
                    engagement_id=run.engagement_id,
                    run_id=run.run_id,
                    key_hash=tc.key_hash,
                    request=req,
                    response=dr.response,
                    dispatch_status="ok",
                    role="hazard_warmup",
                    auth_context_id=tc.auth_context_id,
                    bodies=deps.bodies,
                    now=now,
                )
                warmup_sends.append(
                    _SendRecord(role="hazard_warmup", status="ok", observation_id=obs)
                )
                return dr.response
            return None

        resolution = resolve_hazard(located, source_hint=source_hint, fetch=_fetch)
        if isinstance(resolution, Unresolved):
            return evidence, HazardInfo(
                kind=resolution.kind, param=resolution.param, reason=resolution.reason
            ), warmup_sends
        splices.extend(resolution.splices)

    return apply_splices(evidence, tuple(splices)), None, warmup_sends


def _warmup_request(
    *,
    method: str,
    path: str,
    evidence: EvidenceObservation,
    material: AuthMaterial,
    auth_context_id: AuthContextId,
) -> ConcreteRequest:
    """A standalone `hazard_warmup` GET to the source_hint page under the test's auth."""

    headers, cookies = _splice_auth(
        headers={},
        cookies={},
        material=material,
        session_cookie_names=evidence.session_cookie_names,
    )
    return ConcreteRequest(
        method=method,
        host=evidence.host,
        path=path,
        path_template=path,
        query=(),
        headers=tuple(sorted(headers.items())),
        cookies=tuple(sorted(cookies.items())),
        body=None,
        auth_context_id=auth_context_id,
    )


def _outcome(
    tc: DispatchTestCase,
    run: DispatchRun,
    kind: str,
    *,
    reason: str | None,
    now: datetime,
    hazard: HazardInfo | None = None,
    sends: tuple[tuple[RequestRole, DispatchStatus, ObservationId | None], ...] = (),
    finding_reasserted: tuple[str, str] | None = None,
) -> RunOutcome:
    return RunOutcome(
        engagement_id=run.engagement_id,
        run_id=run.run_id,
        key_hash=tc.key_hash,
        test_class=tc.test_class,  # type: ignore[arg-type]
        outcome=kind,  # type: ignore[arg-type]
        reason=reason,
        hazard=hazard,
        sends=sends,
        finding_reasserted=finding_reasserted,
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
