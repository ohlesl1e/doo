"""The Dispatcher gate: kill-switch lease → OPA → budget guards → wire (ADR-0042/0046).

**Every** wire send — `primary`, baselines, hazard-warmup, liveness probes —
passes through `Dispatcher.dispatch()`. There is no side channel. The gate
sequence is fixed and the deny precedence is asserted in unit tests:

1. **Kill-switch lease** (ADR-0014): the agent process only **reads** the lease
   the keepalive sibling refreshes. Absent / not-`"active"` → `dispatcher_blocked`
   with reason `"kill_switch"`. This is the check the tester's Ctrl-C hits.
2. **Wallclock budget** (ADR-0042): cheap monotonic compare; over →
   `dispatcher_blocked("wallclock_budget_exhausted")`.
3. **Request budget** (ADR-0042): counts every send, including warmup/liveness.
   At/over → `dispatcher_blocked("request_budget_exhausted")`.
4. **OPA** (ADR-0046): the authoritative policy check. The planner's
   `is_in_scope` is NOT a substitute (CLAUDE.md hard rule). S1 ships a
   `StubOpaClient(allow=True)`; S2 swaps in the real Rego client without
   touching the gate sequence.
5. **Wire** (`Sender.send`). On `TransportError` → `transport_error`; otherwise
   the response is handed to `executor.classify`.

Each gate is an injected dependency (Protocol) so deny precedence and
no-send-on-deny are unit-testable in isolation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

from doo.dispatch.executor.classify import classify
from doo.dispatch.executor.send import HttpResponse, Sender, TransportError
from doo.dispatch.models import (
    ConcreteRequest,
    DispatchRun,
    OpaInput,
    RequestRole,
    RunBudget,
)
from doo.events.execution import DispatchStatus, TestClass
from doo.ids import EngagementId
from doo.infra.redis_lease import LEASE_VALUE_ACTIVE, RedisLease
from doo.observability.logging import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Gate Protocols (each independently mockable in unit tests).
# ---------------------------------------------------------------------------


class LeaseReader(Protocol):
    """Read-only kill-switch lease check (ADR-0014 trust split)."""

    def is_alive(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class RedisLeaseReader:
    """`LeaseReader` backed by the existing `RedisLease.read()` (read-only)."""

    lease: RedisLease

    def is_alive(self) -> bool:
        return self.lease.read() == LEASE_VALUE_ACTIVE


@dataclass(frozen=True, slots=True)
class AlwaysAliveLease:
    """Test/stub `LeaseReader`. NEVER use against a real target."""

    alive: bool = True

    def is_alive(self) -> bool:
        return self.alive


@dataclass(frozen=True, slots=True)
class OpaDecision:
    """One policy decision (ADR-0046)."""

    allow: bool
    reason: str | None = None


class OpaClient(Protocol):
    """The dispatcher's policy gate (ADR-0046)."""

    def evaluate(self, input: OpaInput) -> OpaDecision: ...


@dataclass(frozen=True, slots=True)
class StubOpaClient:
    """S1 placeholder OPA client (always-allow). Real Rego is S2.

    Kept as a named class (not an inline lambda) so the run driver and the e2e
    name it explicitly — a future grep for `StubOpaClient` finds every place the
    real client must be wired.
    """

    allow: bool = True
    reason: str | None = None

    def evaluate(self, input: OpaInput) -> OpaDecision:  # noqa: ARG002
        return OpaDecision(allow=self.allow, reason=self.reason)


class BudgetTracker:
    """Per-run request + wallclock budget (ADR-0042).

    `request_budget` counts every `dispatch()` that reaches the wire; warmup and
    liveness sends count (ADR-0043). The tracker is owned by the `DispatchRun`
    driver and shared across every TestCase in the run.
    """

    def __init__(self, budget: RunBudget, *, started_monotonic: float | None = None) -> None:
        self._budget = budget
        self._sent = 0
        self._started = (
            started_monotonic if started_monotonic is not None else time.monotonic()
        )

    @property
    def sent(self) -> int:
        return self._sent

    def wallclock_exceeded(self) -> bool:
        return (time.monotonic() - self._started) >= self._budget.wallclock_budget_s

    def request_budget_exhausted(self) -> bool:
        return self._sent >= self._budget.request_budget

    def record_send(self) -> None:
        self._sent += 1


# ---------------------------------------------------------------------------
# Dispatch result + the gate itself.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DispatchResult:
    """Outcome of one `dispatch()` call.

    On a gate deny, `response` is `None` and `dispatch_status` is
    `dispatcher_blocked` (or `rate_limited` once S2 adds the rate guard) with a
    `reason`. On a wire send, `response` is set and `dispatch_status` is the
    classifier's verdict. `sent` is True iff bytes left the process — the unit
    tests assert it is False on every deny path.
    """

    dispatch_status: DispatchStatus
    sent: bool
    response: HttpResponse | None = None
    reason: str | None = None
    opa_input: OpaInput | None = None


class Dispatcher:
    """The gate every wire send passes through (ADR-0042/0046).

    Holds the run-wide dependencies (lease reader, OPA client, budget tracker,
    sender) and exposes one method: `dispatch(request, …)`. The Executor's
    constructors and the (future) Interpreter tool functions call this; nothing
    else in the codebase calls `Sender.send` directly.
    """

    def __init__(
        self,
        *,
        run: DispatchRun,
        lease: LeaseReader,
        opa: OpaClient,
        budget: BudgetTracker,
        sender: Sender,
    ) -> None:
        self._run = run
        self._lease = lease
        self._opa = opa
        self._budget = budget
        self._sender = sender

    @property
    def engagement_id(self) -> EngagementId:
        return self._run.engagement_id

    def dispatch(
        self,
        request: ConcreteRequest,
        *,
        test_class: TestClass,
        payload_class: str,
        role: RequestRole,
        principal_tier: str,
        target_confidence: float,
        now: object,
    ) -> DispatchResult:
        """Gate one send: lease → wallclock → request-budget → OPA → wire → classify."""

        # --- (1) kill-switch lease (ADR-0014). The check the tester's Ctrl-C hits. ---
        if not self._lease.is_alive():
            return self._blocked("kill_switch")

        # --- (2) wallclock budget (ADR-0042). ---
        if self._budget.wallclock_exceeded():
            return self._blocked("wallclock_budget_exhausted")

        # --- (3) request budget (ADR-0042). Checked BEFORE the send so the cap
        # is a hard ceiling, not a soft one. ---
        if self._budget.request_budget_exhausted():
            return self._blocked("request_budget_exhausted")

        # --- (4) OPA (ADR-0046). The authoritative policy check; the planner's
        # `is_in_scope` is NOT a substitute (CLAUDE.md hard rule). ---
        opa_input = OpaInput.from_send(
            run=self._run,
            request=request,
            test_class=test_class,
            payload_class=payload_class,  # type: ignore[arg-type]
            role=role,
            principal_tier=principal_tier,  # type: ignore[arg-type]
            target_confidence=target_confidence,
            now=now,  # type: ignore[arg-type]
        )
        decision = self._opa.evaluate(opa_input)
        if not decision.allow:
            return self._blocked(
                f"opa_deny: {decision.reason or 'policy denied'}", opa_input=opa_input
            )

        # --- (5) wire. The ONLY place bytes leave the process. ---
        self._budget.record_send()
        try:
            response = self._sender.send(request)
        except TransportError as exc:
            log.warning(
                "dispatcher.transport_error",
                engagement_id=self._run.engagement_id,
                run_id=self._run.run_id,
                role=role,
                error=str(exc),
            )
            return DispatchResult(
                dispatch_status="transport_error",
                sent=True,
                response=None,
                reason=str(exc),
                opa_input=opa_input,
            )

        status = classify(
            response=response, test_class=test_class, role=role, transport_error=None
        )
        log.info(
            "dispatcher.sent",
            engagement_id=self._run.engagement_id,
            run_id=self._run.run_id,
            role=role,
            method=request.method,
            host=request.host.canonical_hostname,
            path=request.path,
            http_status=response.status,
            dispatch_status=status,
            budget_sent=self._budget.sent,
        )
        return DispatchResult(
            dispatch_status=status,
            sent=True,
            response=response,
            reason=None,
            opa_input=opa_input,
        )

    def _blocked(
        self, reason: str, *, opa_input: OpaInput | None = None
    ) -> DispatchResult:
        log.warning(
            "dispatcher.blocked",
            engagement_id=self._run.engagement_id,
            run_id=self._run.run_id,
            reason=reason,
        )
        return DispatchResult(
            dispatch_status="dispatcher_blocked",
            sent=False,
            response=None,
            reason=reason,
            opa_input=opa_input,
        )
