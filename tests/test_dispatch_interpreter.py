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
    authz_baseline_anonymous,
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
    primary_result_for_prompt,
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


def test_authz_baseline_anonymous_strips_all_auth() -> None:
    """#126: same evidence request as `primary`, NO auth header / cookies,
    attributed to the engagement's anonymous-singleton AuthContext."""
    from doo.canonical.identity import auth_context_id, compute_anonymous_auth_hash

    req = authz_baseline_anonymous(
        _testcase(),
        _evidence(),
        AuthMaterial(kind="bearer", raw="ATK", principal_label="b"),  # ignored
    )
    assert req.path == "/orders/123"
    assert "Authorization" not in dict(req.headers)
    assert req.cookies == ()
    assert req.auth_context_id == auth_context_id(
        EngagementId("eng-x"), compute_anonymous_auth_hash()
    )


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


def test_send_tool_baseline_anonymous_allowed_for_priv_esc_not_idor() -> None:
    """#126: `baseline_anonymous` is in priv-esc/boundary's role enum (the
    confirm-mode boundary), NOT in idor's. The wire send carries no auth."""
    import dataclasses

    # idor (the default _testcase()) → not in role set.
    ctx_idor, _, _ = _ctx()
    with pytest.raises(ToolError, match="confirm-mode boundary"):
        send_http_request_within_scope(ctx_idor, role="baseline_anonymous")

    # privilege-escalation → allowed; one wire send, no Authorization header.
    ctx, sender, tracker = _ctx()
    ctx = dataclasses.replace(
        ctx,
        testcase=dataclasses.replace(ctx.testcase, test_class="privilege-escalation"),
    )
    out = send_http_request_within_scope(ctx, role="baseline_anonymous")
    assert out.dispatch_status == "ok"
    assert tracker.sent == 1
    assert "Authorization" not in dict(sender.sent[0].headers)
    assert sender.sent[0].cookies == ()


def test_send_tool_baseline_victim_without_victim_material_raises_toolerror() -> None:
    """No declared victim material → surfaced as a `ToolError`, not a crash.

    #124: the refusal text steers toward `inconclusive`, not "judge from primary
    alone" (which produced FPs on differential tests).
    """
    ctx, _, _ = _ctx(
        secrets=_DictSecretStore(
            {"ac-attacker": AuthMaterial(kind="bearer", raw="ATK", principal_label="b")}
        )
    )
    with pytest.raises(ToolError) as exc:
        send_http_request_within_scope(ctx, role="baseline_victim")
    msg = str(exc.value)
    assert "baseline_victim requires" in msg
    assert "Emit `inconclusive`" in msg
    assert "bare 200 without a baseline is NOT evidence" in msg
    assert "Judge from primary alone" not in msg
    # The attempt is recorded with a sentinel `dispatch_status="unarmable"` so
    # the differential guard can distinguish "Interpreter never tried" from
    # "Interpreter tried, system couldn't arm it" (#124 acceptance criterion 2).
    assert "baseline_victim" in ctx.sent_roles
    rec = ctx.sent_roles["baseline_victim"]
    assert rec.dispatch_status == "unarmable"
    assert rec.observation_id is None  # nothing reached the wire


# ---------------------------------------------------------------------------
# `primary_sent_as` in the pack (#124 part B).
# ---------------------------------------------------------------------------


def test_pack_includes_primary_sent_as() -> None:
    """The Interpreter is told who `primary` was sent as (ADR-0049 identity)."""
    import dataclasses

    ctx, _, _ = _ctx()
    ctx = dataclasses.replace(
        ctx,
        testcase=dataclasses.replace(
            ctx.testcase, attacker_principal="alice", attacker_slot="cookie"
        ),
    )
    pack = primary_result_for_prompt(ctx, ctx.testcase.key_hash)
    assert pack["primary_sent_as"] == {"principal_label": "alice", "slot": "cookie"}


def test_pack_primary_sent_as_none_when_unmigrated() -> None:
    """Pre-ADR-0049 TestCases (no `attacker_principal`) → `primary_sent_as: None`."""
    ctx, _, _ = _ctx()  # _testcase() doesn't set attacker_principal
    pack = primary_result_for_prompt(ctx, ctx.testcase.key_hash)
    assert pack["primary_sent_as"] is None


def test_system_prompt_names_primary_sent_as() -> None:
    """#124: the base prompt names `primary_sent_as` (the TestCase's attacker
    identity). The "do NOT assume unauthenticated" steer applies to the
    *general* case — per-class guidance overrides for `auth-bypass` (whose
    constructor strips all auth, so its `primary` IS anonymous on the wire)."""
    from doo.dispatch.interpreter.loop import SYSTEM_PROMPT

    assert "primary_sent_as" in SYSTEM_PROMPT
    assert "do NOT assume it was unauthenticated" in SYSTEM_PROMPT


def test_authbypass_guidance_says_no_credential() -> None:
    """#126 corrects a #124 regression: `authbypass_primary` strips ALL auth
    regardless of `primary_sent_as`, so the per-class guidance must say so."""
    from doo.dispatch.interpreter.loop import system_prompt_for

    ab = system_prompt_for("auth-bypass")
    assert "NO credential" in ab
    assert "strips all auth" in ab
    # `baseline_anonymous` is NOT offered for auth-bypass (primary IS anonymous).
    assert "baseline_anonymous" not in ab


def test_privesc_and_boundary_guidance_offer_baseline_anonymous() -> None:
    """#126: priv-esc / boundary `primary` splices the attacker's auth, so the
    anonymous probe is a genuinely-different baseline when victim is un-armable."""
    from doo.dispatch.interpreter.loop import system_prompt_for

    for cls in ("privilege-escalation", "boundary-violation"):
        guidance = system_prompt_for(cls)
        assert "baseline_anonymous" in guidance
        assert "CWE-306" in guidance
    # idor/bola unchanged.
    assert "baseline_anonymous" not in system_prompt_for("idor")


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


# ---------------------------------------------------------------------------
# Deterministic verdict guard (#124 part C / ADR-0047 fail-closed).
# ---------------------------------------------------------------------------


def _send(role: str, *, ds: str = "ok") -> SendToolResult:
    return SendToolResult(
        role=role,  # type: ignore[arg-type]
        dispatch_status=ds,
        http_status=200 if ds == "ok" else None,
        response_size=10,
        observation_id=ObservationId(f"obs-{role}"),
        body_ref=None,
    )


def _vuln() -> InterpreterVerdict:
    return InterpreterVerdict(
        verdict="vulnerable",
        justification="primary 200 with victim data",
        observed_vs_expected="200 vs expected 403",
        evidence_refs=(ObservationId("obs-primary"),),
        proposed_severity="high",
        vuln_category="broken-auth",
    )


def test_guard_downgrades_vulnerable_when_no_baseline() -> None:
    """Differential test class + only `primary` reached `ok` → `inconclusive`."""
    from doo.dispatch.run import _guard_differential_verdict

    out = _guard_differential_verdict(
        _vuln(), test_class="auth-bypass", sent_roles={"primary": _send("primary")}
    )
    assert out.verdict == "inconclusive"
    assert out.justification.startswith("[deterministic downgrade:")
    assert "primary 200 with victim data" in out.justification
    # Finding fields stripped (the validator enforces it).
    assert out.vuln_category is None and out.proposed_severity is None
    # Evidence refs preserved.
    assert out.evidence_refs == (ObservationId("obs-primary"),)


def test_guard_downgrades_when_baseline_sent_but_not_ok() -> None:
    """A `baseline_victim` that hit `transport_error` / refusal is NOT a baseline."""
    from doo.dispatch.run import _guard_differential_verdict

    out = _guard_differential_verdict(
        _vuln(),
        test_class="idor",
        sent_roles={
            "primary": _send("primary"),
            "baseline_victim": _send("baseline_victim", ds="transport_error"),
        },
    )
    assert out.verdict == "inconclusive"


def test_guard_keeps_vulnerable_when_baseline_ok() -> None:
    from doo.dispatch.run import _guard_differential_verdict

    v = _vuln()
    out = _guard_differential_verdict(
        v,
        test_class="auth-bypass",
        sent_roles={
            "primary": _send("primary"),
            "baseline_victim": _send("baseline_victim"),
        },
    )
    assert out is v  # unchanged object


def test_guard_keeps_vulnerable_when_baseline_anonymous_ok() -> None:
    """#126: `baseline_anonymous` reaching `ok` satisfies the differential guard
    (any non-`primary` `ok` counts)."""
    from doo.dispatch.run import _guard_differential_verdict

    v = _vuln()
    out = _guard_differential_verdict(
        v,
        test_class="privilege-escalation",
        sent_roles={
            "primary": _send("primary"),
            "baseline_anonymous": _send("baseline_anonymous"),
        },
    )
    assert out is v


def test_guard_defers_to_llm_when_all_baselines_unarmable() -> None:
    """#124 acceptance criterion 2: `auth-bypass` with `baseline_victim`
    un-armable (discovered-tier victim, no live material) and no other baseline
    role available → the LLM's escape-hatch judgment stands. The Interpreter
    *did* try; the system couldn't arm it. The tool error already steers toward
    `inconclusive` unless the primary body alone is conclusive — that judgment
    is the floor here, not the unconditional downgrade."""
    from doo.dispatch.run import _guard_differential_verdict

    v = _vuln()
    out = _guard_differential_verdict(
        v,
        test_class="auth-bypass",
        sent_roles={
            "primary": _send("primary"),
            "baseline_victim": _send("baseline_victim", ds="unarmable"),
        },
    )
    assert out is v


def test_guard_still_downgrades_when_unarmable_but_other_baseline_unattempted() -> None:
    """#126 fallback: priv-esc has `baseline_anonymous` available. If
    `baseline_victim` is un-armable but the Interpreter never tried the
    anonymous fallback, the guard still downgrades — the loop had a satisfiable
    baseline and didn't use it (the original #124 lazy-Interpreter case)."""
    from doo.dispatch.run import _guard_differential_verdict

    out = _guard_differential_verdict(
        _vuln(),
        test_class="privilege-escalation",
        sent_roles={
            "primary": _send("primary"),
            "baseline_victim": _send("baseline_victim", ds="unarmable"),
        },
    )
    assert out.verdict == "inconclusive"


def test_guard_still_downgrades_when_unarmable_mixed_with_wire_failure() -> None:
    """`unarmable` is special; `transport_error` is not. A baseline that *could*
    be armed but failed on the wire is the re-run case — downgrade so C5
    surfaces it. Only "every baseline is structurally un-armable" defers."""
    from doo.dispatch.run import _guard_differential_verdict

    out = _guard_differential_verdict(
        _vuln(),
        test_class="privilege-escalation",
        sent_roles={
            "primary": _send("primary"),
            "baseline_victim": _send("baseline_victim", ds="unarmable"),
            "baseline_anonymous": _send("baseline_anonymous", ds="transport_error"),
        },
    )
    assert out.verdict == "inconclusive"


def test_unarmable_sentinel_is_not_a_dispatch_status() -> None:
    """Regression: the `"unarmable"` sentinel the send tool records in
    `ctx.sent_roles` is loop-local — it must NOT be a valid `DispatchStatus`
    (else it would leak to `RunOutcome.sends` / `EXECUTED_AS.dispatch_status`
    via `_run_interpreter`'s `extra_sends` sweep, which filters on
    `DISPATCH_STATUSES`). If this fails because someone added `unarmable` to
    the enum, the filter in `_run_interpreter` is now a no-op and the graph
    will grow `EXECUTED_AS` edges for sends that never reached the wire."""
    from doo.events.execution import DISPATCH_STATUSES

    assert "unarmable" not in DISPATCH_STATUSES


def test_guard_passthrough_on_non_differential_class() -> None:
    """A class not in `ROLES_BY_TEST_CLASS` (or with only `primary`) is untouched."""
    from doo.dispatch.run import _guard_differential_verdict

    v = _vuln()
    out = _guard_differential_verdict(
        v, test_class="forced_browsing", sent_roles={"primary": _send("primary")}
    )
    assert out is v


def test_guard_passthrough_on_not_vulnerable() -> None:
    from doo.dispatch.run import _guard_differential_verdict

    nv = InterpreterVerdict(
        verdict="not_vulnerable", justification="403", observed_vs_expected="403"
    )
    out = _guard_differential_verdict(
        nv, test_class="auth-bypass", sent_roles={"primary": _send("primary")}
    )
    assert out is nv
