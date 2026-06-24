"""Interpreter tool implementations — the Executor functions the LLM calls (ADR-0043).

Each tool is a pure-ish `(args) → result` function with an **MCP-ready
signature** (no globals; all dependencies via the `ToolContext`). The LLM emits
JSON; **our** code executes — narrowness is enforced identically to an MCP tool.
The Dispatcher gate is invoked from inside `send_http_request_within_scope`, so
every Interpreter-driven send passes the same kill-switch → OPA → budget gate as
the `primary` (no side channel, ADR-0046).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast

from doo.dispatch.executor.constructors import ConstructorMissingError, constructor_for
from doo.dispatch.executor.dispatcher import Dispatcher
from doo.dispatch.executor.evidence import DispatchTestCase, EvidenceObservation
from doo.dispatch.interpreter.models import SendToolResult
from doo.dispatch.models import ROLES_BY_TEST_CLASS, DispatchRun, RequestRole
from doo.dispatch.ontology import BodyStore, commit_agent_send
from doo.dispatch.secrets import AuthMaterial, SecretStore
from doo.events.execution import TestClass
from doo.ids import ObservationId, TestCaseKeyHash
from doo.infra.neo4j_driver import Neo4jClient
from doo.observability.logging import get_logger

log = get_logger(__name__)

# Default role set for a test class not in `ROLES_BY_TEST_CLASS` — typed so the
# `dict.get` default matches the value type (`tuple[RequestRole, ...]`).
_PRIMARY_ONLY: tuple[RequestRole, ...] = ("primary",)


@dataclass
class ToolContext:
    """Everything the tool implementations need for ONE TestCase's confirm loop.

    Built by the run driver per-TestCase; the loop hands it to each tool call.
    `sent_roles` records which roles have already been sent (idempotency: a
    second `send(role=primary)` returns the prior result rather than spending
    another wire send). `bodies_by_ref` is the in-loop body cache so
    `read_response_body` does not re-read object storage.
    """

    run: DispatchRun
    neo4j: Neo4jClient
    dispatcher: Dispatcher
    secrets: SecretStore
    bodies: BodyStore
    testcase: DispatchTestCase
    evidence: EvidenceObservation
    attacker_material: AuthMaterial
    # Per-loop state.
    sent_roles: dict[RequestRole, SendToolResult] = field(default_factory=dict)
    bodies_by_ref: dict[str, bytes] = field(default_factory=dict)
    observation_ids: list[ObservationId] = field(default_factory=list)

    def allowed_roles(self) -> tuple[RequestRole, ...]:
        # `DispatchTestCase.test_class` is a `str` (read from the graph); by
        # construction it is a committed `TestClass`, so narrow it for the lookup.
        return ROLES_BY_TEST_CLASS.get(
            cast(TestClass, self.testcase.test_class), _PRIMARY_ONLY
        )


class ToolError(Exception):
    """A tool call failed deterministically (e.g. role not in this class's enum).

    Surfaced to the LLM as a `tool_result` error string (so it can correct), NOT
    as an exception that crashes the loop — same discipline as the Planner's
    `DraftRejected`.
    """


def send_http_request_within_scope(ctx: ToolContext, *, role: str) -> SendToolResult:
    """Construct + dispatch one request for THIS TestCase in `role` (ADR-0043).

    The `confirm`-mode boundary: any `role` not in this `test_class`'s enum is
    refused (it is by definition a different test, ADR-0043). The constructor is
    pure; the Dispatcher gate runs (lease → OPA → budget → wire); the result is
    committed as `RequestObservation(source="agent")` + `EXECUTED_AS{role,
    run_id}`. Idempotent per role within one loop.
    """

    if role not in ctx.allowed_roles():
        raise ToolError(
            f"role {role!r} is not in this test_class={ctx.testcase.test_class!r}'s "
            f"role set {list(ctx.allowed_roles())!r} (ADR-0043 confirm-mode boundary)"
        )
    typed_role: RequestRole = role

    if typed_role in ctx.sent_roles:
        # Idempotent: a re-ask returns the prior result, no extra wire send.
        prior = ctx.sent_roles[typed_role]
        return prior.model_copy(update={"note": "cached (already sent this role)"})

    try:
        construct = constructor_for(ctx.testcase.test_class, typed_role)
    except ConstructorMissingError as exc:
        raise ToolError(str(exc)) from exc

    # `baseline_victim` sends under the **victim's** material; everything else
    # under the attacker's (the TestCase's `auth_context_id`).
    material = ctx.attacker_material
    if typed_role == "baseline_victim":
        victim_ac = ctx.evidence.baseline_victim_auth_context_id
        victim_mat = ctx.secrets.material_for(victim_ac) if victim_ac else None
        if victim_mat is None:
            # Record the attempt BEFORE raising so the differential guard
            # (`_guard_differential_verdict`) can distinguish "Interpreter
            # never tried a baseline" (the #124 lazy case → downgrade) from
            # "Interpreter tried, system couldn't arm it" (#124 acceptance
            # criterion 2 → defer to the LLM's escape-hatch judgment below).
            # `unarmable` is loop-local — never an `EXECUTED_AS.dispatch_status`.
            ctx.sent_roles[typed_role] = SendToolResult(
                role=typed_role,
                dispatch_status="unarmable",
                http_status=None,
                response_size=0,
                observation_id=None,
                body_ref=None,
                note="no live victim material (discovered-tier evidence)",
            )
            raise ToolError(
                "baseline_victim requires the victim's live auth material; the "
                "evidence observation's AuthContext is not a declared principal "
                "(no ${VAR} ref). Emit `inconclusive` unless the primary "
                "response body ALONE discloses data the attacker should not see "
                "(e.g. structured records, secrets, another tenant's "
                "identifiers). A bare 200 without a baseline is NOT evidence of "
                "bypass."
            )
        material = victim_mat
    if typed_role == "baseline_anonymous":
        # The constructor strips all auth; `material` is unused on the wire.
        # A no-auth sentinel keeps `principal_tier` for the OPA input
        # consistent with how `auth-bypass primary` already passes the gate
        # (the attacker's `tier='declared'` flows through; same here, #126).
        material = AuthMaterial(
            kind="bearer", raw="", principal_label="anonymous", tier="declared"
        )

    request = construct(ctx.testcase, ctx.evidence, material)
    now = datetime.now(UTC)
    result = ctx.dispatcher.dispatch(
        request,
        test_class=ctx.testcase.test_class,  # type: ignore[arg-type]
        payload_class=ctx.testcase.payload_class,
        role=typed_role,
        principal_tier=material.tier,
        target_confidence=ctx.evidence.confidence,
        now=now,
    )

    obs_id: ObservationId | None = None
    body_ref: str | None = None
    http_status: int | None = None
    size = 0
    if result.sent:
        obs_id = commit_agent_send(
            ctx.neo4j,
            engagement_id=ctx.run.engagement_id,
            run_id=ctx.run.run_id,
            key_hash=ctx.testcase.key_hash,
            request=request,
            response=result.response,
            dispatch_status=result.dispatch_status,
            reason=result.reason,
            role=typed_role,
            auth_context_id=request.auth_context_id,
            bodies=ctx.bodies,
            now=now,
        )
        ctx.observation_ids.append(obs_id)
        if result.response is not None:
            http_status = result.response.status
            size = len(result.response.body)
            if result.response.body:
                # Loop-local body_ref: `role:<role>` keys the in-memory cache.
                # The blob (if any) was written by `commit_agent_send`; the
                # Interpreter reads via this ref, not the blob key, so a
                # `NoopBodyStore` run still lets it diff bodies.
                body_ref = f"role:{typed_role}"
                ctx.bodies_by_ref[body_ref] = result.response.body

    out = SendToolResult(
        role=typed_role,
        dispatch_status=result.dispatch_status,
        http_status=http_status,
        response_size=size,
        observation_id=obs_id,
        body_ref=body_ref,
        note=result.reason if not result.sent else None,
    )
    ctx.sent_roles[typed_role] = out
    return out


# Bodies above this size are summarised, not inlined (the prompt budget is the
# tool-call cap, not a token cap, but a 5MB body in a `tool_result` is still a
# bad idea). The Interpreter sees a head + size note instead.
_MAX_INLINE_BODY = 16 * 1024


def read_response_body(ctx: ToolContext, *, body_ref: str) -> str:
    """Return a response body by its loop-local `body_ref` (ADR-0045).

    Bodies stay in object storage and are NOT in the prompt by default; this
    tool fetches one on demand. Large bodies are head-truncated with a size
    note. An unknown `body_ref` is a `ToolError` (the LLM invented it).
    """

    body = ctx.bodies_by_ref.get(body_ref)
    if body is None:
        raise ToolError(
            f"body_ref {body_ref!r} is not a ref returned by a prior "
            "`send_http_request_within_scope` call in this loop"
        )
    if len(body) > _MAX_INLINE_BODY:
        head = body[:_MAX_INLINE_BODY].decode("utf-8", errors="replace")
        return (
            f"[body truncated: {len(body)} bytes total, showing first "
            f"{_MAX_INLINE_BODY}]\n{head}"
        )
    return body.decode("utf-8", errors="replace")


# Tool name → implementation (the dispatch table the loop reads). The two tools
# have different signatures, so the value type is the generic callable.
TOOL_IMPLS: dict[str, Callable[..., object]] = {
    "send_http_request_within_scope": send_http_request_within_scope,
    "read_response_body": read_response_body,
}


def primary_result_for_prompt(
    ctx: ToolContext, key_hash: TestCaseKeyHash
) -> dict[str, object]:
    """The first user message: the `primary` result + the TestCase's expected_outcome.

    The `primary` was already sent by the run driver before the loop starts
    (S1); the Interpreter is handed it on turn 1 (ADR-0043: pre-send
    always-useful roles). The TestCase's `expected_outcome` (what the Planner
    said would confirm it) and the target description give the model what to
    judge against.
    """

    primary = ctx.sent_roles.get("primary")
    # #124: tell the model WHO the `primary` was sent as. Without this the
    # Interpreter assumes "no auth" (the C1 shape) and mis-reasons on C2/C2b
    # tests where the attacker is a declared principal.
    sent_as: dict[str, str] | None = None
    if ctx.testcase.attacker_principal is not None:
        sent_as = {
            "principal_label": ctx.testcase.attacker_principal,
            "slot": ctx.testcase.attacker_slot or "",
        }
    return {
        "testcase_key_hash": key_hash[:12],
        "test_class": ctx.testcase.test_class,
        "primary_sent_as": sent_as,
        "target": {
            "method": ctx.evidence.method,
            "host": ctx.evidence.host.canonical_hostname,
            "path_template": ctx.evidence.path_template,
            "concrete_path": ctx.evidence.concrete_path,
            "handle": "TARGET",
        },
        "hold": list(ctx.testcase.hold),
        "primary_result": primary.model_dump(mode="json") if primary else None,
        "allowed_roles": list(ctx.allowed_roles()),
    }
