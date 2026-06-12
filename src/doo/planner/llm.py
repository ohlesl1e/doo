"""The LLM proposer for the slice-3 planner (ADR-0037, S2a).

The *only* non-deterministic step in the planner. Given a deterministically
assembled `ContextPack`, the LLM proposes one authz test for the candidate gap by
**selecting handles and classifying** — it never writes an HTTP request (hard
rule). Structured output is a **forced tool call** whose schema mirrors
`LLMProposalDraft`, so parsing is deterministic (no free-form JSON scraping).

The model is reached through one `LLMCaller` seam:
- `LiteLLMCaller` routes to the configured provider via the org LiteLLM gateway
  (default Claude Opus 4.8); `litellm` is imported lazily so this module — and the
  whole test suite — imports without the dependency.
- `FakeLLMCaller` returns a canned draft for tests; the deterministic
  resolve/validate path is what the tests actually exercise.

`resolve_draft` is the deterministic bridge back: it maps the draft's pack handles
to concrete node ids, **rejects any handle the LLM invented** (ADR-0037 "kills
hallucinated targets"), and builds the concrete-id `PlannerProposal`. `payload_class`
is fixed here (`auth-token-swap`, `payload_spec = none`) — the replay carries no
bytes (ADR-0041), so it is not the LLM's to choose.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from doo.observability.logging import get_logger
from doo.planner.models import (
    ContextPack,
    GeneratorId,
    LLMProposalDraft,
    PayloadSpec,
    PlannerProposal,
)

log = get_logger(__name__)

# Prompt/algorithm version stamped on every proposal's provenance (ADR-0005); bump
# when the prompt or tool schema changes so stale proposals are identifiable.
PROMPT_VERSION = "planner-c2/3"

SYSTEM_PROMPT = (
    "You are a black-box web application security tester proposing ONE "
    "authorization test for a specific, already-identified coverage gap. You are "
    "given a structured context pack describing one endpoint, the holdable target "
    "references, and the candidate auth contexts.\n\n"
    "Rules:\n"
    "- You do NOT write HTTP requests or payloads. You select a target and an auth "
    "context by their HANDLES (e.g. 'T1', 'A2') and classify the test.\n"
    "- Only use handles that appear in the pack. Never invent a handle or id.\n"
    "- The test is an authorization replay: the request to the endpoint is replayed "
    "under a different (attacker) auth context while the resource it identifies is "
    "held constant.\n"
    "- `hold` lists the TARGET handle(s) — the 'T...' handles from `targets` — whose "
    "object identity must stay fixed during the replay (the target whose id encodes "
    "the victim's resource). `hold` entries are ALWAYS target handles ('T1', 'T2', "
    "...). A `hold` entry is NEVER an auth-context handle ('A1'/'A2'), NEVER a "
    "principal label or id, and NEVER free text. The attacker principal belongs in "
    "`auth_context_ref`, never in `hold`. For a single-target pack, `hold` is "
    "normally just that one target handle (e.g. ['T1']).\n"
    "- Choose `auth_context_ref` = the attacker side: the AUTH-CONTEXT handle ('A...') "
    "of the principal that did NOT reach the endpoint (marked is_attacker_candidate).\n"
    "- Choose `test_class` by STRUCTURE, not reflex:\n"
    "    * `idor` / `bola` ONLY when the endpoint path carries an object/owner "
    "identifier the attacker would hold (a '{id}'-style segment, e.g. "
    "'/orders/{order_id}'): `idor` for a single object reference, `bola` when the "
    "object is owned within a collection/tenant ('/orgs/{org_id}/...').\n"
    "    * `auth-bypass` when a principal reached an endpoint another simply could "
    "not and there is NO object identifier in the path (e.g. '/', '/dashboard', a "
    "login like '/auth/local') — a presence gap, not object-level access.\n"
    "    * `privilege-escalation` when the attacker is a lower-tier AUTHENTICATED "
    "principal that would gain a higher-tier action.\n"
    "- `expected_outcome`: state the SINGLE response that CONFIRMS the issue. A 2xx "
    "under the attacker context confirms the boundary is bypassable; a 401/403 means "
    "it held (NOT a finding). Do not hedge both directions.\n"
    "- `expected_yield` is calibrated, not reflexive: reserve >0.8 for a clean "
    "object-id authz gap; a paramless presence gap or an odd/ambiguous case is lower.\n"
    "- Respond by calling the `propose_test` tool exactly once."
)

# Forced-tool-use schema — mirrors LLMProposalDraft. tool_choice pins this tool so
# the model must return structured arguments.
PROPOSE_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "propose_test",
        "description": "Propose one authorization test for the candidate gap.",
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "test_class": {
                    "type": "string",
                    "enum": ["idor", "bola", "auth-bypass", "privilege-escalation"],
                    "description": "The authorization vulnerability class.",
                },
                "target_ref": {
                    "type": "string",
                    "description": "TARGET handle from `targets` (a 'T...' handle, e.g. 'T1').",
                },
                "auth_context_ref": {
                    "type": "string",
                    "description": (
                        "AUTH-CONTEXT handle of the attacker (an 'A...' handle, e.g. "
                        "'A2'; the one marked is_attacker_candidate)."
                    ),
                },
                "hold": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "TARGET handle(s) ('T...') whose object identity is held "
                        "constant during the replay. Each entry MUST be a target handle "
                        "from `targets` (e.g. 'T1') — never an auth handle ('A...'), "
                        "never a principal label/id, never free text."
                    ),
                },
                "justification": {
                    "type": "string",
                    "description": "Why this test, citing the candidate gap.",
                },
                "expected_outcome": {
                    "type": "string",
                    "description": "What response would confirm the vulnerability.",
                },
                "expected_yield": {
                    "type": "number",
                    "description": "0..1 hunch this reveals a real issue (priority).",
                },
            },
            "required": [
                "test_class",
                "target_ref",
                "auth_context_ref",
                "justification",
                "expected_outcome",
                "expected_yield",
            ],
        },
    },
}


def build_user_prompt(pack: ContextPack) -> str:
    """The per-candidate user message: the id-free pack + the concrete ask."""

    payload = json.dumps(pack.to_llm_payload(), indent=2, sort_keys=True)
    return (
        f"Context pack:\n{payload}\n\n"
        "This endpoint returned 2xx for the principal that reached it, but not for "
        "the other principal. Propose a test that checks whether the attacker auth "
        "context can reach the other principal's resource. Identify which "
        "reference(s) hold the victim's object identity (`hold`) and which auth "
        "context is the attacker (`auth_context_ref`). Call `propose_test`."
    )


C3_SYSTEM_PROMPT = (
    "You are a black-box web application security tester proposing ONE test for a "
    "leak-to-input pivot: a value the application returned in one response is "
    "accepted as input by a different in-scope endpoint. You are given a context "
    "pack with the target endpoint, the input parameter to test (a target handle), "
    "the auth context to send as, and the leaked value's shape.\n\n"
    "Rules:\n"
    "- You do NOT write requests or payloads. The already-observed value is replayed "
    "as the input automatically; you SELECT the target parameter handle (e.g. 'T1') "
    "and the auth-context handle (e.g. 'A1') and CLASSIFY the test.\n"
    "- Only use handles present in the pack. Never invent one.\n"
    "- Classify by the value's shape: 'ssrf'/'open-redirect' for URL-shaped values, "
    "'idor' for identifier-shaped values reused across an ownership boundary, else "
    "'leak_replay'.\n"
    "- Respond by calling `propose_test` exactly once."
)


def build_c3_user_prompt(pack: ContextPack) -> str:
    """The per-candidate user message for a C3 leak-replay (id-free pack + the ask)."""

    payload = json.dumps(pack.to_llm_payload(), indent=2, sort_keys=True)
    return (
        f"Context pack:\n{payload}\n\n"
        "A value this app handed out is accepted as input by the target endpoint. "
        "Propose a test that sends that already-observed value as the input and "
        "classify what it would reveal. Pick the target parameter (`target_ref`) and "
        "the auth context to send as (`auth_context_ref`), and classify "
        "(`test_class`). Call `propose_test`."
    )


# C3 forced-tool schema — leak-replay classes, no authz `hold` (not a session replay).
C3_PROPOSE_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "propose_test",
        "description": "Propose one leak-to-input test for the candidate pivot.",
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "test_class": {
                    "type": "string",
                    "enum": ["leak_replay", "ssrf", "idor", "open-redirect"],
                    "description": "The vulnerability class the leaked value enables.",
                },
                "target_ref": {
                    "type": "string",
                    "description": "TARGET handle of the input parameter (e.g. 'T1').",
                },
                "auth_context_ref": {
                    "type": "string",
                    "description": "Handle of the auth context to send the value as (e.g. 'A1').",
                },
                "justification": {
                    "type": "string",
                    "description": "Why this test, citing the leak-to-input pivot.",
                },
                "expected_outcome": {
                    "type": "string",
                    "description": "What response would confirm the issue.",
                },
                "expected_yield": {
                    "type": "number",
                    "description": "0..1 hunch this reveals a real issue (priority).",
                },
            },
            "required": [
                "test_class",
                "target_ref",
                "auth_context_ref",
                "justification",
                "expected_outcome",
                "expected_yield",
            ],
        },
    },
}


BOUNDARY_SYSTEM_PROMPT = (
    "You are a black-box web application security tester proposing ONE test for a "
    "specific TRUST BOUNDARY (a capability tier or a tenant separation) the graph "
    "inferred. You are given a context pack with the boundary as the target handle, "
    "the concrete endpoint its evidence was observed on, and the two sides as auth "
    "contexts (one marked is_attacker_candidate — the weaker tier, or the other "
    "tenant).\n\n"
    "Rules:\n"
    "- You do NOT write requests or payloads. The evidenced request is replayed "
    "under the attacker side automatically; you SELECT the boundary target handle "
    "(e.g. 'T1') and the attacker auth-context handle (e.g. 'A2') and classify.\n"
    "- Only use handles present in the pack. Never invent one.\n"
    "- `hold` is the boundary target handle ('T...') — the resource held constant "
    "while the attacker auth is swapped in. Never an auth handle or free text.\n"
    "- `auth_context_ref` = the attacker side (is_attacker_candidate): the weaker "
    "capability token, or the other tenant's auth.\n"
    "- Classify: `privilege-escalation` for a capability tier, `idor`/`bola` for a "
    "tenant object/ownership crossing, else `boundary-violation`.\n"
    "- `expected_outcome`: a 2xx under the attacker side confirms the boundary is "
    "bypassable; a 401/403 means it held. State the single confirming response.\n"
    "- Respond by calling `propose_test` exactly once."
)


def build_boundary_user_prompt(pack: ContextPack) -> str:
    """The per-candidate user message for a capability/tenant boundary replay."""

    payload = json.dumps(pack.to_llm_payload(), indent=2, sort_keys=True)
    return (
        f"Context pack:\n{payload}\n\n"
        "Propose a boundary-violation test: replay the evidenced request under the "
        "attacker side while holding the boundary target, and classify what a 2xx "
        "would reveal. Pick `target_ref` (the boundary), `auth_context_ref` (the "
        "attacker), `hold` (the boundary), and `test_class`. Call `propose_test`."
    )


# Boundary forced-tool schema — classes are the boundary set; `hold` is the boundary.
BOUNDARY_PROPOSE_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "propose_test",
        "description": "Propose one trust-boundary replay test.",
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "test_class": {
                    "type": "string",
                    "enum": ["boundary-violation", "privilege-escalation", "idor", "bola"],
                    "description": "The boundary-crossing vulnerability class.",
                },
                "target_ref": {
                    "type": "string",
                    "description": "TARGET handle of the boundary (a 'T...' handle, e.g. 'T1').",
                },
                "auth_context_ref": {
                    "type": "string",
                    "description": "Attacker AUTH-CONTEXT handle ('A...'; is_attacker_candidate).",
                },
                "hold": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "The boundary target handle(s) ('T...') held during replay.",
                },
                "justification": {"type": "string", "description": "Why this test, citing the boundary."},
                "expected_outcome": {"type": "string", "description": "The single response that confirms it."},
                "expected_yield": {"type": "number", "description": "0..1 priority hunch."},
            },
            "required": [
                "test_class",
                "target_ref",
                "auth_context_ref",
                "justification",
                "expected_outcome",
                "expected_yield",
            ],
        },
    },
}


SINK_SYSTEM_PROMPT = (
    "You are a black-box web application security tester proposing ONE test for a "
    "SINK parameter — a request parameter that consumes a caller-controlled address "
    "(a URL, redirect target, or file path). You are given a context pack with the "
    "sink parameter as the target handle and the endpoint it belongs to.\n\n"
    "Rules:\n"
    "- You do NOT write requests or payloads. A single configured probe (the "
    "tester's callback URL / canonical marker) is sent as the parameter "
    "automatically; you SELECT the target parameter handle (e.g. 'T1') and the "
    "auth-context handle (e.g. 'A1') and CLASSIFY.\n"
    "- Only use handles present in the pack. Never invent one.\n"
    "- Classify by the sink role: `ssrf` for a server-side URL fetch, "
    "`open-redirect` for a redirect target, `path-traversal` for a file/path sink.\n"
    "- `expected_outcome`: a callback hit (SSRF) / a 3xx to the probe (open-redirect) "
    "/ unintended file contents (path-traversal) confirms the sink.\n"
    "- Respond by calling `propose_test` exactly once."
)


def build_sink_user_prompt(pack: ContextPack) -> str:
    """The per-candidate user message for a sink-parameter test."""

    payload = json.dumps(pack.to_llm_payload(), indent=2, sort_keys=True)
    return (
        f"Context pack:\n{payload}\n\n"
        "This endpoint takes a parameter that consumes a caller-controlled address. "
        "Propose a test that sends the configured probe as that parameter and "
        "classify what it would reveal. Pick `target_ref` (the sink parameter) and "
        "`auth_context_ref`, and classify (`test_class`). Call `propose_test`."
    )


# Sink forced-tool schema — the dangerous-sink classes; no authz `hold`.
SINK_PROPOSE_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "propose_test",
        "description": "Propose one sink-parameter test.",
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "test_class": {
                    "type": "string",
                    "enum": ["ssrf", "open-redirect", "path-traversal"],
                    "description": "The sink vulnerability class.",
                },
                "target_ref": {
                    "type": "string",
                    "description": "TARGET handle of the sink parameter (e.g. 'T1').",
                },
                "auth_context_ref": {
                    "type": "string",
                    "description": "Handle of the auth context to send as (e.g. 'A1').",
                },
                "justification": {"type": "string", "description": "Why this test, citing the sink."},
                "expected_outcome": {"type": "string", "description": "What would confirm the sink."},
                "expected_yield": {"type": "number", "description": "0..1 priority hunch."},
            },
            "required": [
                "test_class",
                "target_ref",
                "auth_context_ref",
                "justification",
                "expected_outcome",
                "expected_yield",
            ],
        },
    },
}


def _select_prompt_tool(pack: ContextPack) -> tuple[str, str, dict[str, Any]]:
    """Pick the (system, user, tool) triple for the pack's candidate kind."""

    if pack.candidate_kind == "C3":
        return C3_SYSTEM_PROMPT, build_c3_user_prompt(pack), C3_PROPOSE_TOOL
    if pack.candidate_kind == "sink":
        return SINK_SYSTEM_PROMPT, build_sink_user_prompt(pack), SINK_PROPOSE_TOOL
    if pack.candidate_kind in ("capability", "tenant"):
        return (
            BOUNDARY_SYSTEM_PROMPT,
            build_boundary_user_prompt(pack),
            BOUNDARY_PROPOSE_TOOL,
        )
    return SYSTEM_PROMPT, build_user_prompt(pack), PROPOSE_TOOL


@dataclass(frozen=True, slots=True)
class LLMCallResult:
    """One LLM proposal call: the parsed draft plus the raw I/O for the audit trail.

    `request` and `response` are persisted verbatim to object storage (ADR-0037
    replayability); they are plain dicts so they serialise without provider types.
    """

    draft: LLMProposalDraft
    request: dict[str, Any]
    response: dict[str, Any]


@runtime_checkable
class LLMCaller(Protocol):
    """The single LLM seam. Deterministic code owns everything around it."""

    def propose(self, pack: ContextPack) -> LLMCallResult: ...


class FakeLLMCaller:
    """A canned caller for tests — returns a fixed draft, records the request.

    The deterministic resolve/validate/commit path is what the tests assert on; the
    fake lets them run without a model or `litellm`.
    """

    def __init__(self, draft: LLMProposalDraft) -> None:
        self._draft = draft

    def propose(self, pack: ContextPack) -> LLMCallResult:
        system, user, tool = _select_prompt_tool(pack)
        request = {
            "system": system,
            "user": user,
            "tool": tool,
            "tool_choice": "propose_test",
        }
        response = {"tool_use": {"name": "propose_test", "input": self._draft.model_dump()}}
        return LLMCallResult(draft=self._draft, request=request, response=response)


class LiteLLMCaller:
    """The real caller — forced tool-use via litellm (ADR-0037).

    `litellm` routes by the `model` id: a provider-prefixed id reaches that provider
    directly (`anthropic/claude-sonnet-4-6` + `ANTHROPIC_API_KEY`), while an
    OpenAI-compatible gateway / local LiteLLM proxy is reached with an `openai/<name>`
    id plus `api_base` (the org-standard path). `api_base` / `api_key` are optional
    overrides; when unset, litellm resolves credentials from its provider env vars.

    `timeout_s` bounds a single proposing call. Generators call this once per gap,
    sequentially, so without a bound a stalled gateway hangs the whole `propose`
    run. A timed-out call raises `LLMProposalError`, which each generator already
    catches and records as an `LLMSkipped` — the run continues. `None` disables
    the bound (litellm's provider default applies).

    `litellm` is imported lazily so the module imports without the dependency; only
    constructing/using this caller requires it.
    """

    def __init__(
        self,
        model: str,
        *,
        temperature: float = 0.0,
        api_base: str | None = None,
        api_key: str | None = None,
        timeout_s: float | None = 60.0,
    ) -> None:
        self._model = model
        self._temperature = temperature
        self._api_base = api_base
        self._api_key = api_key
        self._timeout_s = timeout_s

    def propose(self, pack: ContextPack) -> LLMCallResult:
        # lazy production-only dep; ignore covers both "litellm absent" (CI) and
        # "litellm present" (the unused-ignore that would otherwise fire locally).
        import litellm  # type: ignore[import-not-found, unused-ignore]

        system, user, tool = _select_prompt_tool(pack)
        # `request` is persisted verbatim to object storage (replay audit), so it
        # must stay secret-free: `api_base` (a URL) is safe and useful to record,
        # but `api_key` is passed to litellm out-of-band and NEVER persisted.
        request: dict[str, Any] = {
            "model": self._model,
            "temperature": self._temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "tools": [tool],
            "tool_choice": {"type": "function", "function": {"name": "propose_test"}},
        }
        if self._api_base is not None:
            request["api_base"] = self._api_base
        if self._timeout_s is not None:
            request["timeout"] = self._timeout_s
        call_kwargs = dict(request)
        if self._api_key is not None:
            call_kwargs["api_key"] = self._api_key  # out-of-band; not in `request`
        try:
            completion = litellm.completion(**call_kwargs)
        except litellm.exceptions.Timeout as exc:
            # Surface as a parse-level failure so the generator records an
            # `LLMSkipped` and moves on instead of the whole run blocking.
            raise LLMProposalError(
                f"LLM call timed out after {self._timeout_s}s"
            ) from exc
        response = completion.model_dump() if hasattr(completion, "model_dump") else dict(completion)
        draft = _parse_tool_call(response)
        return LLMCallResult(draft=draft, request=request, response=response)


def _parse_tool_call(response: dict[str, Any]) -> LLMProposalDraft:
    """Extract the forced `propose_test` tool arguments into a typed draft.

    Raises `LLMProposalError` if the response has no parsable tool call — the
    service treats that as a failed proposal (logged), not a silent drop.
    """

    try:
        message = response["choices"][0]["message"]
        tool_calls = message.get("tool_calls") or []
        if not tool_calls:
            raise KeyError("tool_calls")
        args = tool_calls[0]["function"]["arguments"]
        data = json.loads(args) if isinstance(args, str) else args
    except (KeyError, IndexError, json.JSONDecodeError, TypeError) as exc:
        raise LLMProposalError(f"no parsable propose_test tool call: {exc}") from exc
    return LLMProposalDraft.model_validate(data)


class LLMProposalError(Exception):
    """The LLM response could not be parsed into a valid draft."""


@dataclass(frozen=True, slots=True)
class DraftRejected:
    """A draft whose handles do not resolve against the pack (ADR-0037).

    `code` is a stable discriminator (`unknown_target`, `unknown_auth`,
    `unknown_hold`); the proposal is discarded and logged, never committed.
    """

    code: str
    reason: str


def resolve_draft(
    pack: ContextPack, draft: LLMProposalDraft, *, generator: GeneratorId = "c2"
) -> PlannerProposal | DraftRejected:
    """Resolve an authz-replay draft's pack handles to a `PlannerProposal` (ADR-0037).

    Shared by C2 / C2b (endpoint target) and the capability/tenant **boundary**
    generators (a `boundary` target → `TARGETS_BOUNDARY`, ADR-0039). Rejects any
    handle absent from the pack (hallucination guard) before building the proposal.
    `payload_class`/`payload_spec` are fixed for an authz replay (`auth-token-swap` /
    `none`); `hold` handles resolve to human-readable labels. `generator` stamps the
    proposal's provenance (the committed `source` is `llm-planner` for all of them).
    """

    targets = {t.handle: t for t in pack.targets}
    auths = {a.handle: a for a in pack.auth_contexts}

    target = targets.get(draft.target_ref)
    if target is None:
        return _reject("unknown_target", pack, draft, f"target_ref {draft.target_ref!r}")
    auth = auths.get(draft.auth_context_ref)
    if auth is None:
        return _reject("unknown_auth", pack, draft, f"auth_context_ref {draft.auth_context_ref!r}")

    held: list[str] = []
    for h in draft.hold:
        ht = targets.get(h)
        if ht is None:
            return _reject("unknown_hold", pack, draft, f"hold handle {h!r}")
        held.append(_hold_label(ht))

    target_endpoint_id = target.endpoint_id if target.kind == "endpoint" else None
    target_parameter_id = target.parameter_id if target.kind == "parameter" else None
    target_trust_boundary_id = (
        target.trust_boundary_id if target.kind == "boundary" else None
    )

    return PlannerProposal(
        engagement_id=pack.engagement_id,
        generator=generator,
        mode="llm",
        test_class=draft.test_class,
        payload_class="auth-token-swap",
        payload_spec=PayloadSpec(kind="none"),
        auth_context_id=auth.auth_context_id,
        target_endpoint_id=target_endpoint_id,
        target_parameter_id=target_parameter_id,
        target_trust_boundary_id=target_trust_boundary_id,
        expected_yield=draft.expected_yield,
        confidence_method="llm-self-reported",
        justification=draft.justification,
        expected_outcome=draft.expected_outcome,
        hold=tuple(held),
    )


def resolve_c3_draft(
    pack: ContextPack, draft: LLMProposalDraft
) -> PlannerProposal | DraftRejected:
    """Resolve a C3 leak-replay draft to a concrete-id `PlannerProposal` (ADR-0037).

    Same hallucination guard as `resolve_draft` (reject any handle absent from the
    pack), but the payload is the **leaked observed value**: `payload_class` is the
    benign leak-replay probe and `payload_spec = observed_value(value_hash)` — fixed
    by the deterministic assembler/resolver, never the LLM (the value is known at
    propose time, ADR-0037). C3 targets a `Parameter` (the input the value is sent
    to); there is no authz `hold`. `auth_context_ref` is the single identity the
    leaked value is replayed *as* (assembler-provided), validated like any handle.
    """

    if pack.observed_value_hash is None:
        # An assembler invariant: a C3 pack always carries the leaked value's hash.
        return DraftRejected(
            code="missing_observed_value",
            reason="C3 context pack carries no observed_value_hash to resolve the payload",
        )

    targets = {t.handle: t for t in pack.targets}
    auths = {a.handle: a for a in pack.auth_contexts}

    target = targets.get(draft.target_ref)
    if target is None:
        return _reject("unknown_target", pack, draft, f"target_ref {draft.target_ref!r}")
    if target.kind != "parameter" or target.parameter_id is None:
        return _reject(
            "unknown_target", pack, draft, f"target_ref {draft.target_ref!r} is not a parameter"
        )
    auth = auths.get(draft.auth_context_ref)
    if auth is None:
        return _reject("unknown_auth", pack, draft, f"auth_context_ref {draft.auth_context_ref!r}")

    return PlannerProposal(
        engagement_id=pack.engagement_id,
        generator="c3",
        mode="llm",
        test_class=draft.test_class,
        payload_class="benign-probe",
        payload_spec=PayloadSpec(kind="observed_value", value_hash=pack.observed_value_hash),
        auth_context_id=auth.auth_context_id,
        target_parameter_id=target.parameter_id,
        expected_yield=draft.expected_yield,
        confidence_method="llm-self-reported",
        justification=draft.justification,
        expected_outcome=draft.expected_outcome,
    )


def resolve_sink_draft(
    pack: ContextPack, draft: LLMProposalDraft, *, config_key: str
) -> PlannerProposal | DraftRejected:
    """Resolve a sink-parameter draft to a configured-payload proposal (ADR-0037).

    Same hallucination guard as `resolve_c3_draft`; the target is the sink
    `Parameter` and the payload is the single **configured** canonical probe
    (`payload_class = ssrf-callback`, `payload_spec = configured(config_key)`) — fixed
    by code, not the LLM (the slice-4 dispatcher resolves the real callback under OPA).
    """

    targets = {t.handle: t for t in pack.targets}
    auths = {a.handle: a for a in pack.auth_contexts}

    target = targets.get(draft.target_ref)
    if target is None:
        return _reject("unknown_target", pack, draft, f"target_ref {draft.target_ref!r}")
    if target.kind != "parameter" or target.parameter_id is None:
        return _reject(
            "unknown_target", pack, draft, f"target_ref {draft.target_ref!r} is not a parameter"
        )
    auth = auths.get(draft.auth_context_ref)
    if auth is None:
        return _reject("unknown_auth", pack, draft, f"auth_context_ref {draft.auth_context_ref!r}")

    return PlannerProposal(
        engagement_id=pack.engagement_id,
        generator="sink",
        mode="llm",
        test_class=draft.test_class,
        payload_class="ssrf-callback",
        payload_spec=PayloadSpec(kind="configured", config_key=config_key),
        auth_context_id=auth.auth_context_id,
        target_parameter_id=target.parameter_id,
        expected_yield=draft.expected_yield,
        confidence_method="llm-self-reported",
        justification=draft.justification,
        expected_outcome=draft.expected_outcome,
    )


def _hold_label(t: PackTargetLike) -> str:
    if t.param_name is not None:
        return f"{t.method} {t.path_template} param {t.param_name}"
    return f"{t.method} {t.path_template}"


def _reject(
    code: str, pack: ContextPack, draft: LLMProposalDraft, what: str
) -> DraftRejected:
    reason = f"{what} is not a handle present in the context pack (hallucinated)"
    log.warning(
        "planner.llm.draft_rejected",
        engagement_id=pack.engagement_id,
        code=code,
        reason=reason,
        target_handles=sorted(pack.target_handles()),
        auth_handles=sorted(pack.auth_handles()),
    )
    return DraftRejected(code=code, reason=reason)


# Structural type for `_hold_label` (a PackTarget); avoids importing the concrete
# class name twice and keeps the helper signature self-documenting.
class PackTargetLike(Protocol):
    method: str
    path_template: str
    param_name: str | None
