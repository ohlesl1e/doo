"""Dispatcher gate unit tests: deny precedence + no-send-on-deny (ADR-0042/0046).

Each gate (lease, wallclock, request-budget, OPA) is independently mockable; the
tests assert (a) the deny short-circuits with the right `reason`, (b) **no bytes
leave the process** on any deny, and (c) the precedence is
lease > wallclock > request-budget > OPA.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from doo.canonical.value_objects import HostRef
from doo.dispatch.executor.dispatcher import (
    AlwaysAliveLease,
    BudgetTracker,
    Dispatcher,
    OpaDecision,
    StubOpaClient,
)
from doo.dispatch.executor.send import HttpResponse, StubSender, TransportError
from doo.dispatch.models import (
    ConcreteRequest,
    DispatchRun,
    DispatchSelection,
    RunBudget,
)
from doo.ids import AuthContextId, DispatchRunId, EngagementId, TraceId


def _run(*, budget: RunBudget | None = None) -> DispatchRun:
    return DispatchRun(
        engagement_id=EngagementId("eng-x"),
        run_id=DispatchRunId("run-aaaaaaaaaaaa"),
        trace_id=TraceId("0" * 32),
        environment="staging",
        arming="review",
        interpreter="confirm",
        selection=DispatchSelection(),
        budget=budget or RunBudget(request_budget=10, wallclock_budget_s=300, max_tool_calls=6),
        actor="tester",
        armed_at=datetime.now(UTC),
    )


def _request() -> ConcreteRequest:
    return ConcreteRequest(
        method="GET",
        host=HostRef(scheme="https", canonical_hostname="api.example.com"),
        path="/orders/123",
        path_template="/orders/{order_id}",
        headers=(("Authorization", "Bearer atk"),),
        auth_context_id=AuthContextId("ac-attacker"),
    )


def _dispatcher(
    *,
    lease_alive: bool = True,
    opa_allow: bool = True,
    budget: RunBudget | None = None,
    sender: StubSender | None = None,
    started_monotonic: float | None = None,
) -> tuple[Dispatcher, StubSender, BudgetTracker]:
    run = _run(budget=budget)
    s = sender or StubSender()
    tracker = BudgetTracker(run.budget, started_monotonic=started_monotonic)
    d = Dispatcher(
        run=run,
        lease=AlwaysAliveLease(alive=lease_alive),
        opa=StubOpaClient(allow=opa_allow, reason=None if opa_allow else "host_not_in_scope"),
        budget=tracker,
        sender=s,
    )
    return d, s, tracker


def _send(d: Dispatcher) -> object:
    return d.dispatch(
        _request(),
        test_class="idor",
        payload_class="auth-token-swap",
        role="primary",
        principal_tier="declared",
        target_confidence=1.0,
        now=datetime.now(UTC),
    )


def test_happy_path_sends_and_classifies_ok() -> None:
    d, sender, tracker = _dispatcher()
    res = _send(d)
    assert res.dispatch_status == "ok"  # type: ignore[attr-defined]
    assert res.sent is True  # type: ignore[attr-defined]
    assert res.response is not None  # type: ignore[attr-defined]
    assert len(sender.sent) == 1
    assert tracker.sent == 1
    # OPA input was built with both concrete path AND path_template (ADR-0046).
    assert res.opa_input is not None  # type: ignore[attr-defined]
    assert res.opa_input.request["path"] == "/orders/123"  # type: ignore[attr-defined]
    assert res.opa_input.request["path_template"] == "/orders/{order_id}"  # type: ignore[attr-defined]


def test_dead_lease_blocks_with_no_send() -> None:
    """Gate (1): kill-switch lease absent → `dispatcher_blocked(kill_switch)`, no wire."""
    d, sender, tracker = _dispatcher(lease_alive=False)
    res = _send(d)
    assert res.dispatch_status == "dispatcher_blocked"  # type: ignore[attr-defined]
    assert res.reason == "kill_switch"  # type: ignore[attr-defined]
    assert res.sent is False  # type: ignore[attr-defined]
    assert len(sender.sent) == 0
    assert tracker.sent == 0


def test_request_budget_is_a_hard_ceiling() -> None:
    """Gate (3): at the cap, the next send is refused with no wire."""
    d, sender, tracker = _dispatcher(
        budget=RunBudget(request_budget=2, wallclock_budget_s=300, max_tool_calls=6)
    )
    assert _send(d).sent is True  # type: ignore[attr-defined]
    assert _send(d).sent is True  # type: ignore[attr-defined]
    res = _send(d)
    assert res.dispatch_status == "dispatcher_blocked"  # type: ignore[attr-defined]
    assert res.reason == "request_budget_exhausted"  # type: ignore[attr-defined]
    assert res.sent is False  # type: ignore[attr-defined]
    assert len(sender.sent) == 2
    assert tracker.sent == 2


def test_wallclock_budget_exceeded_blocks() -> None:
    """Gate (2): a started-in-the-past tracker is over wallclock → blocked, no wire."""
    import time

    d, sender, _ = _dispatcher(
        budget=RunBudget(request_budget=10, wallclock_budget_s=1, max_tool_calls=6),
        started_monotonic=time.monotonic() - 5.0,
    )
    res = _send(d)
    assert res.reason == "wallclock_budget_exhausted"  # type: ignore[attr-defined]
    assert res.sent is False  # type: ignore[attr-defined]
    assert len(sender.sent) == 0


def test_opa_deny_blocks_with_reason_and_no_send() -> None:
    """Gate (4): OPA deny → `dispatcher_blocked(opa_deny: …)`, no wire."""
    d, sender, _ = _dispatcher(opa_allow=False)
    res = _send(d)
    assert res.dispatch_status == "dispatcher_blocked"  # type: ignore[attr-defined]
    assert "opa_deny" in str(res.reason)  # type: ignore[attr-defined]
    assert "host_not_in_scope" in str(res.reason)  # type: ignore[attr-defined]
    assert res.sent is False  # type: ignore[attr-defined]
    assert len(sender.sent) == 0


def test_deny_precedence_lease_before_opa() -> None:
    """Precedence: a dead lease wins over an OPA deny (lease is checked first)."""
    d, sender, _ = _dispatcher(lease_alive=False, opa_allow=False)
    res = _send(d)
    assert res.reason == "kill_switch"  # type: ignore[attr-defined]
    assert len(sender.sent) == 0


def test_transport_error_is_classified_not_blocked() -> None:
    """A wire-layer failure is `transport_error` (the gate allowed; the network failed)."""

    class BoomSender:
        def __init__(self) -> None:
            self.called = 0

        def send(self, request: ConcreteRequest) -> HttpResponse:
            self.called += 1
            raise TransportError("connection refused")

    boom = BoomSender()
    d, _, tracker = _dispatcher()
    # Swap the sender in (re-build with the boom sender).
    run = _run()
    d = Dispatcher(
        run=run,
        lease=AlwaysAliveLease(alive=True),
        opa=StubOpaClient(allow=True),
        budget=BudgetTracker(run.budget),
        sender=boom,
    )
    res = _send(d)
    assert res.dispatch_status == "transport_error"  # type: ignore[attr-defined]
    assert res.sent is True  # type: ignore[attr-defined]
    assert res.response is None  # type: ignore[attr-defined]
    assert boom.called == 1


def test_dispatchrun_rejects_auto_on_production() -> None:
    """ADR-0042 defence-in-depth: a CLI `--arming auto` override on production raises."""
    with pytest.raises(ValueError, match="environment=production"):
        DispatchRun(
            engagement_id=EngagementId("eng-x"),
            run_id=DispatchRunId("run-aaaaaaaaaaaa"),
            trace_id=TraceId("0" * 32),
            environment="production",
            arming="auto",
            interpreter="confirm",
            selection=DispatchSelection(),
            budget=RunBudget(request_budget=1, wallclock_budget_s=1, max_tool_calls=1),
            actor="tester",
            armed_at=datetime.now(UTC),
        )


class _RecordingOpa:
    """`OpaClient` that records every input it sees (for the OpaInput-shape assert)."""

    def __init__(self) -> None:
        self.inputs: list[object] = []

    def evaluate(self, input: object) -> OpaDecision:
        self.inputs.append(input)
        return OpaDecision(allow=True)


def test_opa_input_shape_matches_adr0046() -> None:
    """The `OpaInput` snapshot carries the ADR-0046 fields verbatim."""
    run = _run()
    opa = _RecordingOpa()
    d = Dispatcher(
        run=run,
        lease=AlwaysAliveLease(alive=True),
        opa=opa,
        budget=BudgetTracker(run.budget),
        sender=StubSender(),
    )
    _send(d)
    assert len(opa.inputs) == 1
    inp = opa.inputs[0]
    dump = inp.model_dump(mode="json")  # type: ignore[attr-defined]
    assert dump["engagement_id"] == "eng-x"
    assert dump["environment"] == "staging"
    assert dump["request_role"] == "primary"
    assert dump["payload_class"] == "auth-token-swap"
    assert dump["test_class"] == "idor"
    assert dump["principal_tier"] == "declared"
    assert set(dump["request"]) == {"scheme", "method", "host", "path", "path_template"}
