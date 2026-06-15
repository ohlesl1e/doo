"""Interpreter confirm-loop unit tests via `FakeMultiTurnCaller` (ADR-0042/0043/0045).

The deterministic loop/tool-dispatch/verdict-commit path is what these assert on;
the fake plays back canned `tool_use` turns so no model is involved. Asserts:
- baseline constructors emit the right bytes (table-driven, like S1's),
- `send` tool: out-of-enum role refused, idempotent per role, every send goes
  through the SAME Dispatcher gate (budget counted),
- cap enforced: N+1th non-verdict tool_use → forced `inconclusive`,
- `emit_verdict` parsed; hallucinated `evidence_refs` dropped,
- `InterpreterVerdict` model: `vulnerable` requires category+severity.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from doo.canonical.value_objects import HostRef
from doo.dispatch.executor.constructors import (
    idor_baseline_negative,
    idor_baseline_victim,
)
from doo.dispatch.executor.dispatcher import (
    AlwaysAliveLease,
    BudgetTracker,
    Dispatcher,
    StubOpaClient,
)
from doo.dispatch.executor.evidence import DispatchTestCase, EvidenceObservation
from doo.dispatch.executor.send import HttpResponse, StubSender
from doo.dispatch.interpreter.loop import FakeMultiTurnCaller, run_confirm_loop
from doo.dispatch.interpreter.models import InterpreterVerdict, SendToolResult
from doo.dispatch.interpreter.tools import (
    ToolContext,
    ToolError,
    read_response_body,
    send_http_request_within_scope,
)
from doo.dispatch.models import DispatchRun, DispatchSelection, RunBudget
from doo.dispatch.ontology import NoopBodyStore
from doo.dispatch.secrets import AuthMaterial
from doo.ids import (
    AuthContextId,
    DispatchRunId,
    EngagementId,
    ObservationId,
    TestCaseKeyHash,
    TraceId,
)

# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


def _testcase() -> DispatchTestCase:
    return DispatchTestCase(
        engagement_id=EngagementId("eng-x"),
        key_hash=TestCaseKeyHash("k" * 64),
        test_class="idor",
        payload_class="auth-token-swap",
        auth_context_id=AuthContextId("ac-attacker"),
        target_endpoint_id="ep-1",
        target_parameter_id=None,
        target_trust_boundary_id=None,
        hold=("order_id",),
        replay_hazards=(),
        expected_yield=0.9,
        generator="c2",
        confidence=0.99,
    )


def _evidence() -> EvidenceObservation:
    return EvidenceObservation(
        observation_id=ObservationId("obs-victim-1"),
        method="GET",
        host=HostRef(scheme="https", canonical_hostname="api.example.com"),
        concrete_path="/orders/123",
        path_template="/orders/{order_id}",
        headers={"Authorization": "Bearer victim", "Accept": "application/json"},
        victim_auth_context_id=AuthContextId("ac-victim"),
    )


def _run(*, max_tool_calls: int = 6, request_budget: int = 10) -> DispatchRun:
    return DispatchRun(
        engagement_id=EngagementId("eng-x"),
        run_id=DispatchRunId("run-aaaaaaaaaaaa"),
        trace_id=TraceId("0" * 32),
        environment="staging",
        arming="review",
        interpreter="confirm",
        selection=DispatchSelection(),
        budget=RunBudget(
            request_budget=request_budget, wallclock_budget_s=300, max_tool_calls=max_tool_calls
        ),
        actor="t",
        armed_at=datetime.now(UTC),
    )


class _DictSecretStore:
    def __init__(self, by_id: dict[str, AuthMaterial]) -> None:
        self._by_id = by_id

    def material_for(self, ac_id: AuthContextId) -> AuthMaterial | None:
        return self._by_id.get(ac_id)


class _NoopNeo4j:
    """A `Neo4jClient` stand-in that swallows writes (loop unit tests don't assert
    on graph state — `commit_agent_send` is exercised in the e2e)."""

    def execute_write(self, cypher: str, **params: object) -> list[dict[str, object]]:
        return [{"id": "obs"}]

    def execute_read(self, cypher: str, **params: object) -> list[dict[str, object]]:
        return []


def _ctx(
    *,
    sender: StubSender | None = None,
    secrets: _DictSecretStore | None = None,
    run: DispatchRun | None = None,
) -> tuple[ToolContext, StubSender, BudgetTracker]:
    r = run or _run()
    s = sender or StubSender(response=HttpResponse(status=200, body=b'{"id":123}'))
    tracker = BudgetTracker(r.budget)
    dispatcher = Dispatcher(
        run=r,
        lease=AlwaysAliveLease(alive=True),
        opa=StubOpaClient(allow=True),
        budget=tracker,
        sender=s,
    )
    sec = secrets or _DictSecretStore(
        {
            "ac-attacker": AuthMaterial(kind="bearer", raw="ATK", principal_label="b"),
            "ac-victim": AuthMaterial(kind="bearer", raw="VIC", principal_label="a"),
        }
    )
    ctx = ToolContext(
        run=r,
        neo4j=_NoopNeo4j(),  # type: ignore[arg-type]
        dispatcher=dispatcher,
        secrets=sec,  # type: ignore[arg-type]
        bodies=NoopBodyStore(),
        testcase=_testcase(),
        evidence=_evidence(),
        attacker_material=sec.material_for(AuthContextId("ac-attacker")),  # type: ignore[arg-type]
    )
    return ctx, s, tracker


# ---------------------------------------------------------------------------
# Baseline constructors (ADR-0043).
# ---------------------------------------------------------------------------


def test_idor_baseline_victim_uses_victim_auth_and_victim_ac() -> None:
    """`baseline_victim`: same held object, OWNER'S auth, OBSERVED_UNDER the victim."""
    req = idor_baseline_victim(
        _testcase(),
        _evidence(),
        AuthMaterial(kind="bearer", raw="VICTIM-TOKEN", principal_label="a"),
    )
    assert req.path == "/orders/123"
    assert dict(req.headers).get("Authorization") == "Bearer VICTIM-TOKEN"
    # OBSERVED_UNDER the victim's AuthContext, not the TestCase's attacker.
    assert req.auth_context_id == "ac-victim"


def test_idor_baseline_negative_swaps_path_variable_to_sentinel() -> None:
    """`baseline_negative`: held `{order_id}` segment → sentinel, attacker's auth."""
    req = idor_baseline_negative(
        _testcase(),
        _evidence(),
        AuthMaterial(kind="bearer", raw="ATK", principal_label="b"),
    )
    assert req.path != "/orders/123"
    assert req.path.startswith("/orders/")
    assert "doo-nonexistent" in req.path
    # Attacker's AuthContext (we're testing the attacker's view of a nonexistent id).
    assert req.auth_context_id == "ac-attacker"
    assert dict(req.headers).get("Authorization") == "Bearer ATK"


# ---------------------------------------------------------------------------
# `send_http_request_within_scope` tool.
# ---------------------------------------------------------------------------


def test_send_tool_refuses_role_outside_test_class_enum() -> None:
    """ADR-0043 confirm-mode boundary: `liveness` is not Interpreter-selectable."""
    ctx, _, _ = _ctx()
    with pytest.raises(ToolError, match="confirm-mode boundary"):
        send_http_request_within_scope(ctx, role="liveness")


def test_send_tool_is_idempotent_per_role() -> None:
    """A second `send(role=primary)` returns the cached result; no extra wire send."""
    ctx, sender, tracker = _ctx()
    a = send_http_request_within_scope(ctx, role="primary")
    b = send_http_request_within_scope(ctx, role="primary")
    assert a.observation_id == b.observation_id
    assert b.note == "cached (already sent this role)"
    assert len(sender.sent) == 1
    assert tracker.sent == 1


def test_send_tool_counts_against_run_budget() -> None:
    """Every Interpreter-driven send passes the SAME Dispatcher gate (ADR-0046)."""
    ctx, sender, tracker = _ctx()
    send_http_request_within_scope(ctx, role="primary")
    send_http_request_within_scope(ctx, role="baseline_victim")
    send_http_request_within_scope(ctx, role="baseline_negative")
    assert tracker.sent == 3
    assert len(sender.sent) == 3
    # baseline_victim went out under the VICTIM'S token.
    assert dict(sender.sent[1].headers).get("Authorization") == "Bearer VIC"


def test_send_tool_baseline_victim_without_victim_material_raises_toolerror() -> None:
    """No declared victim material → surfaced as a `ToolError`, not a crash."""
    ctx, _, _ = _ctx(
        secrets=_DictSecretStore(
            {"ac-attacker": AuthMaterial(kind="bearer", raw="ATK", principal_label="b")}
        )
    )
    with pytest.raises(ToolError, match="baseline_victim requires"):
        send_http_request_within_scope(ctx, role="baseline_victim")


def test_read_response_body_unknown_ref_is_tool_error() -> None:
    ctx, _, _ = _ctx()
    with pytest.raises(ToolError, match="not a ref returned by"):
        read_response_body(ctx, body_ref="role:nope")


# ---------------------------------------------------------------------------
# Confirm loop.
# ---------------------------------------------------------------------------


def _seed_primary(ctx: ToolContext) -> None:
    """Pre-load the `primary` result the way the run driver does (ADR-0043)."""
    ctx.sent_roles["primary"] = SendToolResult(
        role="primary",
        dispatch_status="ok",
        http_status=200,
        response_size=10,
        observation_id=ObservationId("obs-primary"),
        body_ref="role:primary",
    )
    ctx.bodies_by_ref["role:primary"] = b'{"id":123,"owner":"victim"}'
    ctx.observation_ids.append(ObservationId("obs-primary"))


def test_loop_ends_on_emit_verdict_vulnerable() -> None:
    """Scripted: send baseline → emit_verdict(vulnerable) → typed verdict returned."""
    ctx, sender, _ = _ctx()
    _seed_primary(ctx)
    fake = FakeMultiTurnCaller(
        script=[
            [("send_http_request_within_scope", {"role": "baseline_victim"})],
            [
                (
                    "emit_verdict",
                    {
                        "verdict": "vulnerable",
                        "justification": "primary 200 returned victim data; "
                        "baseline_victim body matches",
                        "observed_vs_expected": "200 with owner=victim under attacker auth",
                        "evidence_refs": ["obs-primary", "obs-hallucinated"],
                        "proposed_severity": "high",
                        "vuln_category": "idor",
                        "affected_refs": ["TARGET"],
                    },
                )
            ],
        ]
    )
    out = run_confirm_loop(ctx, fake, max_tool_calls=5, expected_outcome="200 with victim data")
    assert out.terminated_by == "emit_verdict"
    assert out.verdict.verdict == "vulnerable"
    assert out.verdict.vuln_category == "idor"
    # Hallucinated evidence_ref dropped; the real one kept.
    assert "obs-hallucinated" not in [str(r) for r in out.verdict.evidence_refs]
    assert "obs-primary" in [str(r) for r in out.verdict.evidence_refs]
    assert out.tool_calls_used == 1
    # The baseline send actually went on the wire (through the Dispatcher).
    assert len(sender.sent) == 1


def test_loop_cap_forces_inconclusive() -> None:
    """ADR-0042: N+1th non-verdict tool_use → loop terminates `inconclusive`."""
    ctx, _, _ = _ctx()
    _seed_primary(ctx)
    # 3 turns of `read_response_body` (cheap, no wire); cap=2 → 3rd is refused.
    fake = FakeMultiTurnCaller(
        script=[
            [("read_response_body", {"body_ref": "role:primary"})],
            [("read_response_body", {"body_ref": "role:primary"})],
            [("read_response_body", {"body_ref": "role:primary"})],
        ]
    )
    out = run_confirm_loop(ctx, fake, max_tool_calls=2, expected_outcome="…")
    assert out.terminated_by == "cap"
    assert out.verdict.verdict == "inconclusive"
    assert out.tool_calls_used == 2


def test_loop_no_tool_call_forces_inconclusive() -> None:
    """An assistant turn with no tool_use → forced `inconclusive` (free text ignored)."""
    ctx, _, _ = _ctx()
    _seed_primary(ctx)
    fake = FakeMultiTurnCaller(script=[[]])
    out = run_confirm_loop(ctx, fake, max_tool_calls=5, expected_outcome="…")
    assert out.terminated_by == "no_tool_call"
    assert out.verdict.verdict == "inconclusive"


def test_loop_out_of_enum_role_surfaces_as_tool_result_error() -> None:
    """A bad role is fed back as a tool_result error; loop continues to verdict."""
    ctx, sender, _ = _ctx()
    _seed_primary(ctx)
    fake = FakeMultiTurnCaller(
        script=[
            [("send_http_request_within_scope", {"role": "hazard_warmup"})],
            [
                (
                    "emit_verdict",
                    {
                        "verdict": "not_vulnerable",
                        "justification": "boundary held",
                        "observed_vs_expected": "403",
                    },
                )
            ],
        ]
    )
    out = run_confirm_loop(ctx, fake, max_tool_calls=5, expected_outcome="…")
    assert out.terminated_by == "emit_verdict"
    assert out.verdict.verdict == "not_vulnerable"
    # No wire send happened for the bad role.
    assert len(sender.sent) == 0
    # The error was surfaced in the transcript as a tool message.
    tool_msgs = [m for m in out.transcript if m.get("role") == "tool"]
    assert any("confirm-mode boundary" in str(m.get("content")) for m in tool_msgs)


# ---------------------------------------------------------------------------
# `InterpreterVerdict` model.
# ---------------------------------------------------------------------------


def test_verdict_vulnerable_requires_category_and_severity() -> None:
    with pytest.raises(ValueError, match="vuln_category"):
        InterpreterVerdict(
            verdict="vulnerable",
            justification="x",
            observed_vs_expected="x",
        )


def test_verdict_not_vulnerable_rejects_finding_fields() -> None:
    with pytest.raises(ValueError, match="carries no vuln_category"):
        InterpreterVerdict(
            verdict="not_vulnerable",
            justification="x",
            observed_vs_expected="x",
            vuln_category="idor",
            proposed_severity="high",
        )
