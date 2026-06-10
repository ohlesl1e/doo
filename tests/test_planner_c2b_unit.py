"""Unit tests for the S2b replay-hazard detector + C2b resolve path (ADR-0041/0037).

Two halves, both docker/model-free:

1. The **deterministic replay-hazard detector** (`replay_hazards.py`): positive
   classification of `csrf_token` / `nonce` / `signature` / `timestamp` by name and
   by header name, and negatives (ordinary params unclassified). Pure functions over
   `HazardField`s — no graph, no LLM.
2. The C2b **resolve path**: a `FakeLLMCaller` draft resolved against a C2b pack
   yields an IDOR proposal, and a code-set `replay_hazards` annotation rides along
   without changing the ADR-0007 `key_hash` (identity must be hazard-independent).
"""

from __future__ import annotations

from datetime import UTC, datetime

from doo.events.l2 import ValueCandidate
from doo.events.slice4 import compute_testcase_key_hash
from doo.ids import AuthContextId, EngagementId
from doo.planner.llm import resolve_draft
from doo.planner.models import (
    ContextPack,
    LLMProposalDraft,
    PackAuthContext,
    PackTarget,
    PlannerProposal,
)
from doo.planner.replay_hazards import (
    HazardField,
    detect_replay_hazards,
    hazards_for_value_candidates,
)

# ---------------------------------------------------------------------------
# 1. Replay-hazard detector — positives (by name and by header name).
# ---------------------------------------------------------------------------


def test_csrf_detected_by_param_name() -> None:
    for name in ("csrf_token", "_csrf", "csrfmiddlewaretoken", "authenticity_token"):
        assert detect_replay_hazards((HazardField(name=name),)) == ("csrf_token",), name


def test_csrf_detected_by_header_name() -> None:
    # The X-CSRF-Token header is the demo case: header-borne, value secret (None).
    field = HazardField(name="X-CSRF-Token", value=None, is_header=True)
    assert detect_replay_hazards((field,)) == ("csrf_token",)
    assert detect_replay_hazards(
        (HazardField(name="X-XSRF-TOKEN", is_header=True),)
    ) == ("csrf_token",)


def test_nonce_detected_by_name() -> None:
    assert detect_replay_hazards((HazardField(name="nonce"),)) == ("nonce",)
    assert detect_replay_hazards(
        (HazardField(name="request_nonce", value="a8F3kZ91qLpw"),)
    ) == ("nonce",)


def test_signature_detected_by_name_and_shape() -> None:
    assert detect_replay_hazards((HazardField(name="signature"),)) == ("signature",)
    assert detect_replay_hazards((HazardField(name="hmac"),)) == ("signature",)
    assert detect_replay_hazards((HazardField(name="sig"),)) == ("signature",)


def test_timestamp_detected_only_with_temporal_value() -> None:
    # Epoch seconds + ISO-8601 -> timestamp; a small int with a ts-name does NOT.
    assert detect_replay_hazards(
        (HazardField(name="timestamp", value="1717000000"),)
    ) == ("timestamp",)
    assert detect_replay_hazards(
        (HazardField(name="ts", value="2026-06-09T12:00:00Z"),)
    ) == ("timestamp",)
    # `expires=2` is a timestamp NAME but not a timestamp VALUE -> unclassified.
    assert detect_replay_hazards((HazardField(name="expires", value="2"),)) == ()


def test_multiple_roles_sorted_and_deduped() -> None:
    fields = (
        HazardField(name="X-CSRF-Token", is_header=True),
        HazardField(name="timestamp", value="1717000000"),
        HazardField(name="nonce"),
        HazardField(name="csrf_token"),  # duplicate role
    )
    # Sorted in REPLAY_HAZARD_ROLES order: csrf_token, nonce, signature, timestamp.
    assert detect_replay_hazards(fields) == ("csrf_token", "nonce", "timestamp")


# ---------------------------------------------------------------------------
# 1b. Replay-hazard detector — negatives (ordinary params unclassified).
# ---------------------------------------------------------------------------


def test_ordinary_params_unclassified() -> None:
    for name in ("id", "page", "q", "name", "order_id", "limit", "offset", "sort"):
        assert detect_replay_hazards((HazardField(name=name, value="42"),)) == (), name


def test_signature_name_substring_does_not_overmatch() -> None:
    # `assignee` / `design` contain "sign" but are not signatures.
    assert detect_replay_hazards((HazardField(name="assignee", value="bob"),)) == ()
    assert detect_replay_hazards((HazardField(name="design", value="flat"),)) == ()


def test_empty_and_blank_fields_unclassified() -> None:
    assert detect_replay_hazards(()) == ()
    assert detect_replay_hazards((HazardField(name="   "),)) == ()


# ---------------------------------------------------------------------------
# 1c. Adapter over stored value_candidates (header-borne + input/output filter).
# ---------------------------------------------------------------------------


def test_hazards_from_value_candidates_reads_header_input() -> None:
    candidates = (
        # A header-borne CSRF token (secret -> value None): detected by name.
        ValueCandidate(
            value_hash="a" * 64,
            kind="opaque_token",
            extractor="request-header:hazard_v1",
            role="input",
            section="header",
            value=None,
            value_length=32,
            header_name="X-CSRF-Token",
            parameter_name="X-CSRF-Token",
        ),
        # An ordinary query input -> no role.
        ValueCandidate(
            value_hash="b" * 64,
            kind="identifier",
            extractor="request-param:query_v1",
            role="input",
            section="body",
            value="42",
            parameter_name="id",
        ),
        # An output (response) candidate -> ignored (not a request field).
        ValueCandidate(
            value_hash="c" * 64,
            kind="identifier",
            extractor="response:json_v1",
            role="output",
            section="body",
            value="csrf-looking-but-output",
            json_pointer="/csrf",
        ),
    )
    assert hazards_for_value_candidates(candidates) == ("csrf_token",)


# ---------------------------------------------------------------------------
# 2. C2b resolve path: pack -> draft -> proposal carrying code-set replay_hazards,
#    and key_hash independence.
# ---------------------------------------------------------------------------


def _c2b_pack() -> ContextPack:
    """A C2b pack: two reaching principals, BOTH attacker candidates (ADR-0033)."""

    return ContextPack(
        engagement_id=EngagementId("eng-c2b"),
        candidate_kind="C2b",
        candidate_reason="reached (2xx) by admin and user with differing bodies",
        endpoint_method="GET",
        endpoint_path_template="/profile",
        targets=(
            PackTarget(
                handle="T1",
                kind="endpoint",
                method="GET",
                path_template="/profile",
                endpoint_id="ep-profile",
            ),
        ),
        auth_contexts=(
            PackAuthContext(
                handle="A1",
                principal_label="admin",
                is_attacker_candidate=True,
                auth_context_id=AuthContextId("ac-admin"),
            ),
            PackAuthContext(
                handle="A2",
                principal_label="user",
                is_attacker_candidate=True,
                auth_context_id=AuthContextId("ac-user"),
            ),
        ),
        code_version="planner-c2/2",
        generated_at=datetime.now(UTC),
    )


def _c2b_draft(**over: object) -> LLMProposalDraft:
    base: dict[str, object] = {
        "test_class": "idor",
        "target_ref": "T1",
        "auth_context_ref": "A2",  # replay as user against admin's differentiated body
        "hold": ("T1",),
        "justification": "both 200 with differing bodies; check user reads admin's",
        "expected_outcome": "2xx returning admin's body as user confirms IDOR/BOLA",
        "expected_yield": 0.75,
    }
    base.update(over)
    return LLMProposalDraft.model_validate(base)


def test_c2b_resolve_builds_idor_proposal() -> None:
    proposal = resolve_draft(_c2b_pack(), _c2b_draft())
    assert isinstance(proposal, PlannerProposal)
    assert proposal.test_class == "idor"
    assert proposal.mode == "llm"
    assert proposal.payload_class == "auth-token-swap"
    assert proposal.auth_context_id == "ac-user"  # the chosen attacker side (A2)
    assert proposal.target_endpoint_id == "ep-profile"
    # The resolver does NOT set replay_hazards — that is the generator's code-set step.
    assert proposal.replay_hazards == ()


def test_c2b_proposal_carries_code_set_replay_hazards() -> None:
    # The generator copies detected hazards onto the frozen proposal.
    proposal = resolve_draft(_c2b_pack(), _c2b_draft())
    assert isinstance(proposal, PlannerProposal)
    annotated = proposal.model_copy(update={"replay_hazards": ("csrf_token",)})
    assert annotated.replay_hazards == ("csrf_token",)


def test_replay_hazards_not_in_key_hash() -> None:
    """ADR-0041: replay_hazards is a derivable annotation, never an identity input."""

    base = resolve_draft(_c2b_pack(), _c2b_draft())
    assert isinstance(base, PlannerProposal)
    with_hazards = base.model_copy(update={"replay_hazards": ("csrf_token", "nonce")})

    def key(p: PlannerProposal) -> str:
        return compute_testcase_key_hash(
            engagement_id=p.engagement_id,
            test_class=p.test_class,
            target_endpoint_id=p.target_endpoint_id,
            target_parameter_id=p.target_parameter_id,
            target_trust_boundary_id=p.target_trust_boundary_id,
            payload_class=p.payload_class,
            payload_hash="0" * 64,  # same resolved payload for both
            auth_context_id=p.auth_context_id,
        )

    assert key(base) == key(with_hazards)
