"""Unit tests for the S2a LLM-proposing core (ADR-0037) — no docker, no model.

Exercises the deterministic bridge around the LLM: handle resolution
(`resolve_draft`), the hallucination guard, and the fixed authz-replay payload —
driven by a `FakeLLMCaller` so no `litellm` / model is involved.
"""

from __future__ import annotations

from datetime import UTC, datetime

from doo.ids import AuthContextId, EngagementId
from doo.planner.llm import DraftRejected, FakeLLMCaller, resolve_draft
from doo.planner.models import (
    ContextPack,
    LLMProposalDraft,
    PackAuthContext,
    PackTarget,
    PlannerProposal,
)


def _pack() -> ContextPack:
    return ContextPack(
        engagement_id=EngagementId("eng-1"),
        candidate_kind="C2",
        candidate_reason="reached as admin (2xx), not as user_b",
        endpoint_method="GET",
        endpoint_path_template="/orgs/{org_id}/orders/{order_id}",
        targets=(
            PackTarget(
                handle="T1",
                kind="endpoint",
                method="GET",
                path_template="/orgs/{org_id}/orders/{order_id}",
                endpoint_id="ep-orders",
            ),
        ),
        auth_contexts=(
            PackAuthContext(
                handle="A1",
                principal_label="admin",
                is_attacker_candidate=False,
                auth_context_id=AuthContextId("ac-admin"),
            ),
            PackAuthContext(
                handle="A2",
                principal_label="user_b",
                is_attacker_candidate=True,
                auth_context_id=AuthContextId("ac-user-b"),
            ),
        ),
        code_version="planner-c2/1",
        generated_at=datetime.now(UTC),
    )


def _draft(**over: object) -> LLMProposalDraft:
    base: dict[str, object] = {
        "test_class": "idor",
        "target_ref": "T1",
        "auth_context_ref": "A2",
        "hold": ("T1",),
        "justification": "admin reached the order; check user_b can read it",
        "expected_outcome": "2xx returning the admin order body confirms IDOR",
        "expected_yield": 0.7,
    }
    base.update(over)
    return LLMProposalDraft.model_validate(base)


def test_resolve_draft_builds_concrete_proposal() -> None:
    proposal = resolve_draft(_pack(), _draft())
    assert isinstance(proposal, PlannerProposal)
    assert proposal.generator == "c2"
    assert proposal.mode == "llm"
    assert proposal.test_class == "idor"
    # authz replay -> fixed payload class + sentinel-resolvable spec, attacker auth.
    assert proposal.payload_class == "auth-token-swap"
    assert proposal.payload_spec.kind == "none"
    assert proposal.auth_context_id == "ac-user-b"  # the attacker side (A2)
    assert proposal.target_endpoint_id == "ep-orders"
    assert proposal.confidence_method == "llm-self-reported"
    # hold handle resolved to a human-readable label, never a raw id.
    assert proposal.hold == ("GET /orgs/{org_id}/orders/{order_id}",)


def test_resolve_draft_rejects_hallucinated_target() -> None:
    out = resolve_draft(_pack(), _draft(target_ref="T9"))
    assert isinstance(out, DraftRejected)
    assert out.code == "unknown_target"


def test_resolve_draft_rejects_hallucinated_auth() -> None:
    out = resolve_draft(_pack(), _draft(auth_context_ref="A9"))
    assert isinstance(out, DraftRejected)
    assert out.code == "unknown_auth"


def test_resolve_draft_rejects_hallucinated_hold() -> None:
    out = resolve_draft(_pack(), _draft(hold=("T1", "T7")))
    assert isinstance(out, DraftRejected)
    assert out.code == "unknown_hold"


def test_fake_caller_round_trips_draft_through_pack() -> None:
    draft = _draft()
    result = FakeLLMCaller(draft).propose(_pack())
    assert result.draft == draft
    # the request the audit will persist carries the id-free prompt, never raw ids.
    assert "ac-admin" not in result.request["user"]
    assert "ep-orders" not in result.request["user"]
    assert "T1" in result.request["user"] and "A2" in result.request["user"]
