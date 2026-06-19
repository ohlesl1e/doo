"""`InterpreterVerdict` + the confirm-loop tool schemas (ADR-0045).

The Interpreter's output is a typed forced tool call (same mechanism as the
Planner, ADR-0037). The verdict is the **fourth orthogonal axis** on `TestCase`
alongside `status` / `review_status` / `dispatch_status` (ADR-0045): `vulnerable`
/ `not_vulnerable` / `inconclusive`. C5 (ADR-0047) treats `inconclusive` as
**untested** — fail-closed.

Tool schemas mirror these models exactly so parsing is deterministic. The
Interpreter sees `(testcase_id, role)` and `blob_ref` — never a URL, header, or
body to compose (CLAUDE.md hard rule).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from doo.dispatch.models import ROLES_BY_TEST_CLASS, RequestRole
from doo.events.execution import FindingCategory, FindingSeverity, PayloadClass, TestClass
from doo.ids import ObservationId

Verdict = Literal["vulnerable", "not_vulnerable", "inconclusive"]
VERDICTS: tuple[Verdict, ...] = ("vulnerable", "not_vulnerable", "inconclusive")


class FollowUpProposal(BaseModel):
    """A genuinely-new test the confirm loop surfaced (ADR-0045, S8/#93).

    NOT dispatched in-run: in `confirm` mode it goes back through the slice-3
    Validator + commit path (`source = "llm-interpreter"`) and lands at
    `review_status = proposed` for human review — same scope/XOR/dedup guards as a
    Planner proposal. `target_handle` is `"TARGET"` (the current TestCase's own
    target) or an endpoint id the Validator resolves + scope-checks; a
    hallucinated/out-of-scope handle is discarded-and-logged, never committed.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    test_class: TestClass
    payload_class: PayloadClass
    target_handle: str = Field(min_length=1)
    justification: str = Field(min_length=1)
    expected_outcome: str = Field(min_length=1)


class InterpreterVerdict(BaseModel):
    """The Interpreter's typed final output (ADR-0045).

    `evidence_refs` are the `EXECUTED_AS` observation ids that demonstrate the
    verdict (the `primary` + any baselines). On `vulnerable`, the proposed
    severity / category / affected refs feed the `Finding` commit; on
    `not_vulnerable` / `inconclusive` they are absent (the verdict on the
    TestCase IS the record — no Finding, ADR-0045). `follow_ups` reuses the
    slice-3 Validator path (`source = "llm-interpreter"`) — out of S3 scope but
    the field is reserved.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    verdict: Verdict
    justification: str = Field(min_length=1)
    observed_vs_expected: str = Field(min_length=1)
    evidence_refs: tuple[ObservationId, ...] = ()

    proposed_severity: FindingSeverity | None = None
    vuln_category: FindingCategory | None = None
    # Endpoint / TrustBoundary handles (the TestCase's resolved target). The
    # Interpreter sees pack-local handles, not raw node ids; the deterministic
    # commit code resolves them — same hallucination guard as the Planner.
    affected_refs: tuple[str, ...] = ()
    # Genuinely-new tests the loop surfaced (S8/#93). Re-validated + committed at
    # `review_status = proposed`, `source = "llm-interpreter"` — never dispatched
    # in-run (confirm mode). Empty for most verdicts.
    follow_ups: tuple[FollowUpProposal, ...] = ()

    @model_validator(mode="after")
    def _vulnerable_requires_category(self) -> InterpreterVerdict:
        if self.verdict == "vulnerable":
            if self.vuln_category is None or self.proposed_severity is None:
                raise ValueError(
                    "verdict=vulnerable requires vuln_category + proposed_severity "
                    "(ADR-0045: a Finding is a structured claim, not free text)"
                )
        else:
            # `not_vulnerable` / `inconclusive` carry no Finding fields.
            if self.vuln_category is not None or self.proposed_severity is not None:
                raise ValueError(
                    f"verdict={self.verdict!r} carries no vuln_category / "
                    "proposed_severity (no Finding is committed)"
                )
        return self


# ---------------------------------------------------------------------------
# Tool schemas (litellm `tools=[...]` / OpenAI-compatible function format).
# ---------------------------------------------------------------------------


def send_tool_schema(test_class: TestClass) -> dict[str, Any]:
    """`send_http_request_within_scope(role)` — the per-`test_class` role enum.

    The Interpreter's only authority over the wire is which `role` to send next
    for *this* TestCase. The enum is keyed on `test_class` (ADR-0043) so a role
    not in this class's set is unrepresentable in the schema — the model
    physically cannot ask for `baseline_negative` on an `auth-bypass` test.
    `testcase_id` is implicit (the loop is per-TestCase); the tool takes only
    `role`.
    """

    roles = list(ROLES_BY_TEST_CLASS.get(test_class, ("primary",)))
    return {
        "type": "function",
        "function": {
            "name": "send_http_request_within_scope",
            "description": (
                "Send one request for THIS test case in the given role. The "
                "request is constructed deterministically from the approved "
                "TestCase + the evidence observation; you choose only the role. "
                "Returns {role, http_status, response_size, observation_id, "
                "body_ref} — call `read_response_body` to read the body."
            ),
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "role": {
                        "type": "string",
                        "enum": roles,
                        "description": (
                            "Which request to send: 'primary' (the test, under the "
                            "attacker's auth), 'baseline_victim' (same held object "
                            "under the owner's auth), 'baseline_negative' (held id "
                            "swapped to a known-nonexistent value)."
                        ),
                    },
                },
                "required": ["role"],
            },
        },
    }


READ_BODY_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "read_response_body",
        "description": (
            "Read a response body by its `body_ref` (returned by "
            "`send_http_request_within_scope`). Bodies stay in object storage and "
            "are NOT in the prompt by default — call this only when the status "
            "code alone cannot decide (e.g. soft-200 vs. real data)."
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "body_ref": {
                    "type": "string",
                    "description": "The `body_ref` value from a prior send result.",
                },
            },
            "required": ["body_ref"],
        },
    },
}


EMIT_VERDICT_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "emit_verdict",
        "description": (
            "Emit your final verdict for this TestCase. Call this exactly once, "
            "as your last action. `vulnerable` means the boundary did NOT hold "
            "(the attacker reached the victim's resource); `not_vulnerable` means "
            "it held; `inconclusive` means you could not decide within the tool "
            "budget. Cite the observation_ids that demonstrate the verdict."
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": list(VERDICTS),
                },
                "justification": {
                    "type": "string",
                    "description": "Why this verdict, citing the responses.",
                },
                "observed_vs_expected": {
                    "type": "string",
                    "description": (
                        "What you observed vs. what the TestCase's "
                        "`expected_outcome` said would confirm it."
                    ),
                },
                "evidence_refs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "observation_id(s) demonstrating the verdict.",
                },
                "proposed_severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "description": "ONLY if verdict=vulnerable.",
                },
                "vuln_category": {
                    "type": "string",
                    "enum": [
                        "idor",
                        "broken-access-control",
                        "broken-auth",
                        "ssrf",
                        "info-disclosure",
                        "boundary-violation",
                        "other",
                    ],
                    "description": "ONLY if verdict=vulnerable.",
                },
                "affected_refs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Target handle(s) ('TARGET'). ONLY if verdict=vulnerable.",
                },
                "follow_ups": {
                    "type": "array",
                    "description": (
                        "OPTIONAL: genuinely-NEW test hypotheses you noticed while "
                        "judging (e.g. the same endpoint exposes another param). "
                        "These are NOT sent now — they go to human review. Leave "
                        "empty unless you saw something concrete and out-of-scope "
                        "of THIS test."
                    ),
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "test_class": {"type": "string"},
                            "payload_class": {"type": "string"},
                            "target_handle": {
                                "type": "string",
                                "description": "'TARGET' (this endpoint) or an endpoint id.",
                            },
                            "justification": {"type": "string"},
                            "expected_outcome": {"type": "string"},
                        },
                        "required": [
                            "test_class",
                            "payload_class",
                            "target_handle",
                            "justification",
                            "expected_outcome",
                        ],
                    },
                },
            },
            "required": ["verdict", "justification", "observed_vs_expected"],
        },
    },
}


def interpreter_tools(test_class: TestClass) -> list[dict[str, Any]]:
    """The full tool list for one TestCase's confirm loop (ADR-0043 surface)."""

    return [send_tool_schema(test_class), READ_BODY_TOOL, EMIT_VERDICT_TOOL]


# ---------------------------------------------------------------------------
# Per-send tool result (what the Interpreter sees after a `send`).
# ---------------------------------------------------------------------------


class SendToolResult(BaseModel):
    """The structured `tool_result` for one `send_http_request_within_scope` call.

    Carries only what the Interpreter needs to judge: status, size, the
    `observation_id` (for `evidence_refs`), and a `body_ref` (for
    `read_response_body`). The body itself is NEVER inlined (ADR-0045: bodies
    stay in object storage). `dispatch_status != ok` is surfaced so the model
    knows the send did not reach the test path (and should not over-interpret a
    `transport_error`).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: RequestRole
    dispatch_status: str
    http_status: int | None
    response_size: int
    observation_id: ObservationId | None
    body_ref: str | None
    note: str | None = None
