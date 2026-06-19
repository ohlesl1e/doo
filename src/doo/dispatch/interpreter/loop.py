"""The Interpreter's multi-turn confirm loop (ADR-0042/0043/0045).

Deterministic Python drives `litellm.completion(tools=[…])`: on each `tool_use`
block, dispatch on `tool_name` to the Executor functions in `tools.py` and feed
`tool_result` back. The loop ends on `emit_verdict` (or the tool-call cap →
`inconclusive`). The full transcript — every message, every tool call, every
result, the final verdict — is returned for blob persistence keyed by
`(run_id, key_hash)` (ADR-0037 applied to the Interpreter).

`MultiTurnLLMCaller` is the seam: `LiteLLMMultiTurnCaller` is the real client
(same `litellm.completion` as the Planner, just multi-message); `FakeMultiTurnCaller`
plays back canned assistant turns for tests.

No LLM in request construction (CLAUDE.md hard rule): the LLM picks `role`s;
deterministic constructors build requests; the Dispatcher gates them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from doo.dispatch.interpreter.models import (
    EMIT_VERDICT_TOOL,
    FollowUpProposal,
    InterpreterVerdict,
    interpreter_tools,
)
from doo.dispatch.interpreter.tools import (
    TOOL_IMPLS,
    ToolContext,
    ToolError,
    primary_result_for_prompt,
)
from doo.observability.logging import get_logger

log = get_logger(__name__)

# Prompt/algorithm version stamped on the persisted transcript (ADR-0005); bump
# when the system prompt or tool schemas change. /2 adds per-test_class
# guidance. /3 (#124) names the `primary` principal and tightens the
# missing-baseline steer toward `inconclusive`. /4 (#126) adds
# `baseline_anonymous` for priv-esc/boundary and corrects the auth-bypass
# guidance (its `primary` is always anonymous on the wire — `authbypass_primary`
# strips all auth regardless of `primary_sent_as`).
INTERPRETER_PROMPT_VERSION = "interpreter-confirm/4"

# Per-`test_class` guidance appended to the base prompt (S7/#92). Mirrors the
# Planner's per-kind prompt selection: the deciding question differs by class.
_CLASS_GUIDANCE: dict[str, str] = {
    "idor": (
        "\n\nTHIS CLASS — IDOR: the attacker requested another user's object by id. "
        "Vulnerable = the attacker's `primary` returns the VICTIM's object "
        "(compare `baseline_victim`); rule out a generic-200 with `baseline_negative`."
    ),
    "bola": (
        "\n\nTHIS CLASS — BOLA (broken object-level authz): like IDOR but the "
        "object is a collection/sub-resource. Vulnerable = the attacker reads/acts "
        "on an object owned by another tenant/user. Diff `baseline_victim`; "
        "`baseline_negative` rules out 'any id works'."
    ),
    "auth-bypass": (
        "\n\nTHIS CLASS — AUTH-BYPASS: the `primary` was sent with NO credential "
        "on the wire (the constructor strips all auth regardless of "
        "`primary_sent_as` — that field is the TestCase's attacker identity, "
        "not what was spliced). Vulnerable = an endpoint that should require "
        "auth served sensitive content anonymously. Compare `baseline_victim` "
        "(the same request WITH the owner's auth). If `baseline_victim` is "
        "unavailable, emit `inconclusive` unless the `primary` body ALONE "
        "discloses clearly-sensitive structured data."
    ),
    "privilege-escalation": (
        "\n\nTHIS CLASS — PRIVILEGE-ESCALATION: a lower-tier principal hit a "
        "higher-privilege action. Vulnerable = the low-tier `primary` succeeded "
        "where only the privileged `baseline_victim` should. If "
        "`baseline_victim` is unavailable, send `baseline_anonymous` (same "
        "request, NO auth): if anonymous gets the same body as `primary`, the "
        "endpoint has no auth check at all — emit `vulnerable` with "
        "`vuln_category='broken-auth'` (CWE-306). If anonymous 4xx, the "
        "attacker's credential was the gate; without the victim baseline emit "
        "`inconclusive`."
    ),
    "boundary-violation": (
        "\n\nTHIS CLASS — BOUNDARY-VIOLATION: the test crosses a declared "
        "TrustBoundary (capability/tenant, ADR-0039). Vulnerable = the attacker "
        "side reached what only the stronger/other side should; `baseline_victim` "
        "is that authorized side. If `baseline_victim` is unavailable, send "
        "`baseline_anonymous` (same request, NO auth): if anonymous gets the "
        "same body as `primary`, the endpoint has no auth check at all — emit "
        "`vulnerable` with `vuln_category='broken-auth'` (CWE-306). If "
        "anonymous 4xx, without the victim baseline emit `inconclusive`."
    ),
}


def system_prompt_for(test_class: str) -> str:
    """The Interpreter system prompt for a `test_class` (base + per-class clause)."""

    return SYSTEM_PROMPT + _CLASS_GUIDANCE.get(test_class, "")


SYSTEM_PROMPT = (
    "You are the INTERPRETER for one approved security test case. The test has "
    "already been sent (the `primary` request, under the attacker's auth — see "
    "`primary_sent_as` for which principal; do NOT assume it was "
    "unauthenticated); you are given its result. Your job: decide whether the "
    "hypothesis held — did "
    "the boundary fail (vulnerable), hold (not_vulnerable), or can you not tell "
    "(inconclusive)?\n\n"
    "Tools:\n"
    "- `send_http_request_within_scope(role)`: send a control request for THIS "
    "test case. You choose only the `role` from the allowed set; the request is "
    "constructed deterministically. Use `baseline_victim` (same object, owner's "
    "auth) to diff against a generic-200; use `baseline_negative` (nonexistent "
    "id, attacker's auth) to rule out 'any id 200s'.\n"
    "- `read_response_body(body_ref)`: read a body by its ref. Bodies are NOT in "
    "your context by default — call this only when status alone cannot decide.\n"
    "- `emit_verdict(...)`: your FINAL action. Call exactly once.\n\n"
    "Rules:\n"
    "- You do NOT compose URLs, headers, or bodies. You pick roles.\n"
    "- A 2xx on `primary` is NOT automatically vulnerable: compare against "
    "`baseline_victim` (does the attacker see the victim's data?) and/or "
    "`baseline_negative` (does any id 200?).\n"
    "- A 4xx on `primary` is `not_vulnerable` (boundary held) UNLESS "
    "`dispatch_status` says the send didn't reach the test path.\n"
    "- You have a tool-call budget. If you cannot decide within it, "
    "`emit_verdict(inconclusive)`.\n"
    "- Cite `observation_id`s in `evidence_refs`."
)


# ---------------------------------------------------------------------------
# Multi-turn caller seam.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AssistantTurn:
    """One assistant response: either tool calls, or terminal content (no tools)."""

    tool_calls: tuple[dict[str, Any], ...]
    content: str | None
    raw: dict[str, Any]


class MultiTurnLLMCaller(Protocol):
    """One `litellm.completion` per turn over an accumulating message list."""

    def turn(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> AssistantTurn: ...


@dataclass
class FakeMultiTurnCaller:
    """Plays back a scripted sequence of assistant turns (for tests).

    Each item in `script` is a list of `(tool_name, args)` tuples for one turn;
    an empty list means the assistant returned no tool calls (loop forces
    `inconclusive`). Records the message list it was given each turn.
    """

    script: list[list[tuple[str, dict[str, Any]]]]
    seen_messages: list[list[dict[str, Any]]] = field(default_factory=list)

    def turn(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> AssistantTurn:
        self.seen_messages.append([dict(m) for m in messages])
        if not self.script:
            return AssistantTurn(tool_calls=(), content=None, raw={})
        calls = self.script.pop(0)
        tool_calls = tuple(
            {
                "id": f"call_{i}",
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(args)},
            }
            for i, (name, args) in enumerate(calls)
        )
        return AssistantTurn(
            tool_calls=tool_calls,
            content=None,
            raw={"tool_calls": [dict(tc) for tc in tool_calls]},
        )


class LiteLLMMultiTurnCaller:
    """The real multi-turn caller — `litellm.completion` over the message list.

    Same routing/timeout/tool-choice knobs as `planner.llm.LiteLLMCaller`;
    `litellm` is imported lazily. `tool_choice="auto"` (the model picks; the
    system prompt tells it to end on `emit_verdict`). A response with no tool
    call is handed back as `tool_calls=()` and the loop forces `inconclusive`.
    """

    def __init__(
        self,
        model: str,
        *,
        temperature: float | None = 0.0,
        api_base: str | None = None,
        api_key: str | None = None,
        timeout_s: float | None = 120.0,
    ) -> None:
        self._model = model
        self._temperature = temperature
        self._api_base = api_base
        self._api_key = api_key
        self._timeout_s = timeout_s

    def turn(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> AssistantTurn:
        import litellm  # type: ignore[import-not-found, unused-ignore]

        litellm.suppress_debug_info = True
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
        }
        if self._temperature is not None:
            kwargs["temperature"] = self._temperature
        if self._api_base is not None:
            kwargs["api_base"] = self._api_base
        if self._timeout_s is not None:
            kwargs["timeout"] = self._timeout_s
        if self._api_key is not None:
            kwargs["api_key"] = self._api_key
        completion = litellm.completion(**kwargs)
        raw = (
            completion.model_dump()
            if hasattr(completion, "model_dump")
            else dict(completion)
        )
        msg = raw["choices"][0]["message"]
        tool_calls = tuple(msg.get("tool_calls") or [])
        return AssistantTurn(
            tool_calls=tool_calls, content=msg.get("content"), raw=raw
        )


# ---------------------------------------------------------------------------
# The confirm loop.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConfirmLoopResult:
    """Outcome of one TestCase's confirm loop.

    `verdict` is the parsed `InterpreterVerdict` (forced `inconclusive` on cap /
    no-tool-call). `transcript` is the full message list (system → user →
    assistant → tool → … → assistant) for blob persistence (ADR-0045
    replayability). `tool_calls_used` feeds the cap-enforcement assert.
    """

    verdict: InterpreterVerdict
    transcript: tuple[dict[str, Any], ...]
    tool_calls_used: int
    terminated_by: str  # "emit_verdict" | "cap" | "no_tool_call" | "error"


def run_confirm_loop(
    ctx: ToolContext,
    caller: MultiTurnLLMCaller,
    *,
    max_tool_calls: int,
    expected_outcome: str,
) -> ConfirmLoopResult:
    """Drive one TestCase's ≤N-turn confirm loop to a typed verdict (ADR-0042).

    The `primary` is already in `ctx.sent_roles` (the run driver sent it before
    starting the loop, ADR-0043 pre-send). Each turn: call the model with the
    accumulated message list; for each `tool_use` block, dispatch to the
    Executor function and append a `tool` message; on `emit_verdict`, parse and
    return. At `max_tool_calls` non-verdict tool calls, force `inconclusive`
    (ADR-0042: bounded). Any role not in this `test_class`'s enum is a
    `ToolError` surfaced as a tool_result, not a crash.
    """

    tools = interpreter_tools(ctx.testcase.test_class)  # type: ignore[arg-type]
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt_for(ctx.testcase.test_class)},
        {
            "role": "user",
            "content": json.dumps(
                {
                    **primary_result_for_prompt(ctx, ctx.testcase.key_hash),
                    "expected_outcome": expected_outcome,
                    "tool_call_budget": max_tool_calls,
                },
                indent=2,
                sort_keys=True,
            ),
        },
    ]

    used = 0
    while True:
        turn = caller.turn(messages, tools)
        messages.append(
            {
                "role": "assistant",
                "content": turn.content,
                "tool_calls": list(turn.tool_calls) or None,
            }
        )

        if not turn.tool_calls:
            # No tool call → the model produced free text. Force inconclusive.
            return _forced_inconclusive(
                ctx, messages, used, "no_tool_call: assistant returned no tool_use"
            )

        for tc in turn.tool_calls:
            name = tc["function"]["name"]
            args_raw = tc["function"].get("arguments", "{}")
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else dict(args_raw)
            except json.JSONDecodeError:
                args = {}

            if name == "emit_verdict":
                verdict = _parse_verdict(args, ctx=ctx)
                return ConfirmLoopResult(
                    verdict=verdict,
                    transcript=tuple(messages),
                    tool_calls_used=used,
                    terminated_by="emit_verdict",
                )

            # Non-verdict tool: enforce the cap BEFORE dispatch (ADR-0042 hard cap).
            if used >= max_tool_calls:
                return _forced_inconclusive(
                    ctx,
                    messages,
                    used,
                    f"cap: tool-call budget {max_tool_calls} exhausted before "
                    "emit_verdict",
                )
            used += 1

            impl = TOOL_IMPLS.get(name)
            if impl is None:
                result_str = json.dumps(
                    {"error": f"unknown tool {name!r}; allowed: "
                              f"{sorted(TOOL_IMPLS) + ['emit_verdict']}"}
                )
            else:
                try:
                    out = impl(ctx, **args)
                    result_str = (
                        out.model_dump_json()
                        if hasattr(out, "model_dump_json")
                        else json.dumps(out) if not isinstance(out, str) else out
                    )
                except ToolError as exc:
                    result_str = json.dumps({"error": str(exc)})
                except TypeError as exc:
                    # Bad args (e.g. missing `role`): surface, don't crash.
                    result_str = json.dumps({"error": f"bad arguments: {exc}"})

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.get("id", f"call_{used}"),
                    "name": name,
                    "content": result_str,
                }
            )
            log.debug(
                "interpreter.tool_result",
                run_id=ctx.run.run_id,
                key_hash=ctx.testcase.key_hash,
                tool=name,
                used=used,
                cap=max_tool_calls,
            )


def _parse_verdict(args: dict[str, Any], *, ctx: ToolContext) -> InterpreterVerdict:
    """Parse + validate `emit_verdict` args; coerce on validation failure to
    `inconclusive` rather than crashing (the LLM may emit a malformed verdict).

    `evidence_refs` is constrained to observation_ids the loop actually produced
    (the same hallucination guard as the Planner's handle resolution, ADR-0037):
    any ref the LLM invented is dropped, and if none survive the loop's own
    `observation_ids` are substituted.
    """

    valid_obs = set(str(o) for o in ctx.observation_ids) | {
        str(r.observation_id) for r in ctx.sent_roles.values() if r.observation_id
    }
    refs = [r for r in (args.get("evidence_refs") or []) if str(r) in valid_obs]
    args = {**args, "evidence_refs": refs or sorted(valid_obs)}
    # `affected_refs` is constrained to the single target handle the prompt named.
    if args.get("affected_refs"):
        args["affected_refs"] = [r for r in args["affected_refs"] if r == "TARGET"]
    # Parse `follow_ups` defensively: a malformed one is dropped + logged, never
    # fatal to the verdict (the run driver re-validates the survivors, ADR-0045).
    if args.get("follow_ups"):
        good: list[FollowUpProposal] = []
        for raw in args["follow_ups"]:
            try:
                good.append(FollowUpProposal.model_validate(raw))
            except Exception as exc:  # noqa: BLE001 - drop the bad follow-up
                log.warning(
                    "interpreter.follow_up_unparseable",
                    key_hash=ctx.testcase.key_hash,
                    error=str(exc),
                )
        args["follow_ups"] = good
    try:
        return InterpreterVerdict.model_validate(args)
    except Exception as exc:  # noqa: BLE001 - any validation failure → inconclusive
        log.warning(
            "interpreter.verdict_unparseable",
            key_hash=ctx.testcase.key_hash,
            error=str(exc),
        )
        return InterpreterVerdict(
            verdict="inconclusive",
            justification=f"emit_verdict arguments did not validate: {exc}",
            observed_vs_expected="(unparseable verdict)",
            evidence_refs=tuple(ctx.observation_ids),
        )


def _forced_inconclusive(
    ctx: ToolContext,
    messages: list[dict[str, Any]],
    used: int,
    reason: str,
) -> ConfirmLoopResult:
    log.info(
        "interpreter.forced_inconclusive",
        run_id=ctx.run.run_id,
        key_hash=ctx.testcase.key_hash,
        reason=reason,
        tool_calls_used=used,
    )
    return ConfirmLoopResult(
        verdict=InterpreterVerdict(
            verdict="inconclusive",
            justification=reason,
            observed_vs_expected="(loop terminated before emit_verdict)",
            evidence_refs=tuple(ctx.observation_ids),
        ),
        transcript=tuple(messages),
        tool_calls_used=used,
        terminated_by="cap" if reason.startswith("cap:") else "no_tool_call",
    )


def force_verdict_tool_choice() -> dict[str, Any]:
    """`tool_choice` pinning `emit_verdict` for the final turn (when supported).

    Some models reject forced `tool_choice` (the same constraint the Planner's
    `tool_choice_mode` exists for); the loop already handles a no-tool-call turn
    by forcing `inconclusive`, so this is an optimisation, not load-bearing.
    """

    return {"type": "function", "function": {"name": EMIT_VERDICT_TOOL["function"]["name"]}}
