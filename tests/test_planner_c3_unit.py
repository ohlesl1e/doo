"""Unit tests for the S3 C3 leak-replay resolver (ADR-0037) — no docker, no model.

Exercises `resolve_c3_draft`: the deterministic bridge that maps a C3 draft's pack
handles to a parameter-targeted `PlannerProposal` with the leaked value fixed as the
`observed_value` payload, plus the hallucination guard. The Validator's
parameter-target + observed_value resolution is covered by the e2e (it needs a real
graph).
"""

from __future__ import annotations

from datetime import UTC, datetime

from doo.ids import AuthContextId, EngagementId, ParameterId, Sha256Hex
from doo.planner.llm import DraftRejected, resolve_c3_draft
from doo.planner.models import (
    ContextPack,
    LLMProposalDraft,
    PackAuthContext,
    PackTarget,
    PlannerProposal,
)

_VALUE_HASH = Sha256Hex("a" * 64)


def _pack(*, with_value: bool = True, target_kind: str = "parameter") -> ContextPack:
    return ContextPack(
        engagement_id=EngagementId("eng-1"),
        candidate_kind="C3",
        candidate_reason="C3 leak-to-input: a url value leaked from GET /me is accepted "
        "as parameter 'next' by in-scope GET /redirect",
        endpoint_method="GET",
        endpoint_path_template="/redirect",
        targets=(
            PackTarget(
                handle="T1",
                kind=target_kind,  # type: ignore[arg-type]
                method="GET",
                path_template="/redirect",
                param_name="next",
                location="query",
                endpoint_id="ep-redirect",
                parameter_id=ParameterId("param-next") if target_kind == "parameter" else None,
            ),
        ),
        auth_contexts=(
            PackAuthContext(
                handle="A1",
                principal_label="user",
                is_attacker_candidate=False,
                auth_context_id=AuthContextId("ac-user"),
            ),
        ),
        observed_value_hash=_VALUE_HASH if with_value else None,
        code_version="planner-c3/1",
        generated_at=datetime.now(UTC),
    )


def _draft(**over: object) -> LLMProposalDraft:
    base: dict[str, object] = {
        "test_class": "ssrf",
        "target_ref": "T1",
        "auth_context_ref": "A1",
        "justification": "a leaked URL is consumed as the redirect target; test SSRF",
        "expected_outcome": "the server fetching an attacker-influenced URL confirms SSRF",
        "expected_yield": 0.6,
    }
    base.update(over)
    return LLMProposalDraft.model_validate(base)


def test_resolve_c3_builds_parameter_targeted_observed_value_proposal() -> None:
    proposal = resolve_c3_draft(_pack(), _draft())
    assert isinstance(proposal, PlannerProposal)
    assert proposal.generator == "c3"
    assert proposal.mode == "llm"
    assert proposal.test_class == "ssrf"
    # leak-replay → benign probe + the leaked value fixed as the observed payload.
    assert proposal.payload_class == "benign-probe"
    assert proposal.payload_spec.kind == "observed_value"
    assert proposal.payload_spec.value_hash == _VALUE_HASH
    # targets the input PARAMETER (not an endpoint); no authz hold.
    assert proposal.target_parameter_id == "param-next"
    assert proposal.target_endpoint_id is None
    assert proposal.hold == ()
    assert proposal.auth_context_id == "ac-user"
    assert proposal.confidence_method == "llm-self-reported"


def test_resolve_c3_rejects_hallucinated_target() -> None:
    out = resolve_c3_draft(_pack(), _draft(target_ref="T9"))
    assert isinstance(out, DraftRejected) and out.code == "unknown_target"


def test_resolve_c3_rejects_hallucinated_auth() -> None:
    out = resolve_c3_draft(_pack(), _draft(auth_context_ref="A9"))
    assert isinstance(out, DraftRejected) and out.code == "unknown_auth"


def test_resolve_c3_rejects_non_parameter_target() -> None:
    # A C3 target must be a parameter; an endpoint-kind handle is rejected.
    out = resolve_c3_draft(_pack(target_kind="endpoint"), _draft())
    assert isinstance(out, DraftRejected) and out.code == "unknown_target"


def test_resolve_c3_rejects_pack_missing_observed_value() -> None:
    out = resolve_c3_draft(_pack(with_value=False), _draft())
    assert isinstance(out, DraftRejected) and out.code == "missing_observed_value"


def test_resolve_c3_classifies_leak_replay_default() -> None:
    proposal = resolve_c3_draft(_pack(), _draft(test_class="leak_replay"))
    assert isinstance(proposal, PlannerProposal)
    assert proposal.test_class == "leak_replay"
