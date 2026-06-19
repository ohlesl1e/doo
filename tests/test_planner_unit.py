"""Unit tests for the planner's deterministic, graph-free cores (issue #60).

These assert external behaviour over pure functions — no Neo4j needed:

- `TestCase` identity: `key_hash` determinism, the three-way XOR invariant,
  confidence-vs-yield separation (ADR-0007/0037).
- The C1 generator's deterministic proposal shape (ADR-0036): `forced_browsing`,
  `no-payload`, `payload_spec=none`, anonymous AuthContext, heuristic yield.
- The prioritiser ordering + top-N truncation (ADR-0036).
- The re-surface predicate (ADR-0040): permanent vs defer; confidence-up vs new
  evidence vs neither.
- The review ledger event shape + disposition rules (ADR-0040).
"""

from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from doo.canonical.identity import auth_context_id, compute_anonymous_auth_hash
from doo.events.execution import compute_testcase_key_hash
from doo.ids import EngagementId, TestCaseKeyHash
from doo.planner.generators import C1Generator, PlannerConfig, enabled_generators
from doo.planner.models import (
    Candidate,
    PayloadSpec,
    ProposedTestCaseView,
    ReviewLedgerEvent,
)
from doo.planner.prioritize import prioritize, priority_score
from doo.planner.validator import should_resurface

EID = EngagementId("eng-unit")


# ---------------------------------------------------------------------------
# TestCase identity (ADR-0007).
# ---------------------------------------------------------------------------


def test_key_hash_is_deterministic_and_content_addressed() -> None:
    empty = hashlib.sha256(b"").hexdigest()
    args = dict(
        engagement_id=EID,
        test_class="forced_browsing",
        target_endpoint_id="ep-1",
        target_parameter_id=None,
        target_trust_boundary_id=None,
        payload_class="no-payload",
        payload_hash=empty,  # type: ignore[arg-type]
        attacker_principal="anonymous",
        attacker_slot="anonymous",
    )
    a = compute_testcase_key_hash(**args)  # type: ignore[arg-type]
    b = compute_testcase_key_hash(**args)  # type: ignore[arg-type]
    assert a == b  # same content -> same hash

    # Different target -> different hash.
    other = compute_testcase_key_hash(**{**args, "target_endpoint_id": "ep-2"})  # type: ignore[arg-type]
    assert other != a


def test_key_hash_target_xor_is_enforced() -> None:
    empty = hashlib.sha256(b"").hexdigest()
    base = dict(
        engagement_id=EID,
        test_class="forced_browsing",
        payload_class="no-payload",
        payload_hash=empty,
        attacker_principal="anonymous",
        attacker_slot="anonymous",
    )
    # Zero targets -> error.
    with pytest.raises(ValueError):
        compute_testcase_key_hash(  # type: ignore[arg-type]
            target_endpoint_id=None,
            target_parameter_id=None,
            target_trust_boundary_id=None,
            **base,
        )
    # Two targets -> error.
    with pytest.raises(ValueError):
        compute_testcase_key_hash(  # type: ignore[arg-type]
            target_endpoint_id="ep-1",
            target_parameter_id="param-1",  # type: ignore[arg-type]
            target_trust_boundary_id=None,
            **base,
        )


def test_key_hash_stable_across_auth_context_rotation() -> None:
    """ADR-0049: same `(attacker_principal, slot)` → same key, regardless of which
    `auth_context_id` it was proposed under. `auth_context_id` is no longer a key
    input at all, so the key is rotation-stable by construction."""

    empty = hashlib.sha256(b"").hexdigest()
    base = dict(
        engagement_id=EID,
        test_class="idor",
        target_endpoint_id="ep-1",
        target_parameter_id=None,
        target_trust_boundary_id=None,
        payload_class="auth-token-swap",
        payload_hash=empty,
        attacker_principal="alice",
        attacker_slot="cookie",
    )
    k1 = compute_testcase_key_hash(**base)  # type: ignore[arg-type]
    k2 = compute_testcase_key_hash(**base)  # type: ignore[arg-type]
    assert k1 == k2

    # And a different attacker principal -> different key.
    k_other = compute_testcase_key_hash(  # type: ignore[arg-type]
        **{**base, "attacker_principal": "bob"}
    )
    assert k_other != k1


def test_key_hash_distinct_per_slot() -> None:
    """ADR-0007 intent preserved: weak vs strong credential slot of the SAME
    principal are distinct auth states (e.g. session cookie vs step-up token)."""

    empty = hashlib.sha256(b"").hexdigest()
    base = dict(
        engagement_id=EID,
        test_class="privilege-escalation",
        target_endpoint_id="ep-admin",
        target_parameter_id=None,
        target_trust_boundary_id=None,
        payload_class="auth-token-swap",
        payload_hash=empty,
        attacker_principal="alice",
    )
    k_session = compute_testcase_key_hash(**base, attacker_slot="session")  # type: ignore[arg-type]
    k_stepup = compute_testcase_key_hash(**base, attacker_slot="stepup")  # type: ignore[arg-type]
    assert k_session != k_stepup


def test_key_hash_anonymous_sentinel() -> None:
    """ADR-0049: the anonymous attacker is `("anonymous", "anonymous")` — stable."""

    empty = hashlib.sha256(b"").hexdigest()
    k = compute_testcase_key_hash(
        engagement_id=EID,
        test_class="forced_browsing",
        target_endpoint_id="ep-1",
        target_parameter_id=None,
        target_trust_boundary_id=None,
        payload_class="no-payload",
        payload_hash=empty,  # type: ignore[arg-type]
        attacker_principal="anonymous",
        attacker_slot="anonymous",
    )
    assert isinstance(k, str) and len(k) == 64
    # The C1 generator emits exactly this attacker pair for its anon probe.
    proposal = C1Generator().propose(
        Candidate(
            engagement_id=EID, generator="c1", reason="x", criticality=1.0,
            target_confidence=1.0, target_endpoint_id="ep-1",
        )
    )
    assert proposal.attacker_principal == "anonymous"
    assert proposal.attacker_slot == "anonymous"


def test_candidate_target_xor_invariant() -> None:
    # Exactly one target required.
    with pytest.raises(ValidationError):
        Candidate(
            engagement_id=EID,
            generator="c1",
            reason="x",
            criticality=1.0,
            target_confidence=1.0,
        )
    with pytest.raises(ValidationError):
        Candidate(
            engagement_id=EID,
            generator="c1",
            reason="x",
            criticality=1.0,
            target_confidence=1.0,
            target_endpoint_id="ep-1",
            target_parameter_id="param-1",  # type: ignore[arg-type]
        )
    # One target is fine.
    c = Candidate(
        engagement_id=EID,
        generator="c1",
        reason="x",
        criticality=1.0,
        target_confidence=1.0,
        target_endpoint_id="ep-1",
    )
    assert c.target_endpoint_id == "ep-1"


# ---------------------------------------------------------------------------
# C1 generator deterministic proposal (ADR-0036/0037).
# ---------------------------------------------------------------------------


def test_c1_generator_proposes_deterministic_forced_browsing() -> None:
    gen = C1Generator()
    assert gen.generator_id == "c1"
    assert gen.mode == "deterministic"

    candidate = Candidate(
        engagement_id=EID,
        generator="c1",
        reason="C1 dead endpoint: in-scope GET shop.example.com/admin",
        criticality=1.0,
        target_confidence=0.8,
        target_endpoint_id="ep-admin",
    )
    proposal = gen.propose(candidate)
    assert proposal.test_class == "forced_browsing"
    assert proposal.payload_class == "no-payload"
    assert proposal.payload_spec.kind == "none"
    assert proposal.target_endpoint_id == "ep-admin"
    assert proposal.mode == "deterministic"
    assert proposal.confidence_method == "heuristic"  # not llm-self-reported
    # Anonymous AuthContext (a benign GET as nobody).
    assert proposal.auth_context_id == auth_context_id(EID, compute_anonymous_auth_hash())
    # expected_yield is the priority hunch, distinct from validity.
    assert 0.0 <= proposal.expected_yield <= 1.0
    assert proposal.justification  # cites the gap
    assert proposal.expected_outcome


def test_payload_spec_none_carries_no_reference() -> None:
    PayloadSpec(kind="none")  # ok
    with pytest.raises(ValidationError):
        PayloadSpec(kind="observed_value")  # missing value_hash
    with pytest.raises(ValidationError):
        PayloadSpec(kind="none", config_key="x")  # reference on a 'none' spec


def test_enabled_generators_config_toggle() -> None:
    assert [g.generator_id for g in enabled_generators(PlannerConfig())] == ["c1"]
    assert [
        g.generator_id
        for g in enabled_generators(PlannerConfig(candidate_generators=("c1",)))
    ] == ["c1"]
    with pytest.raises(ValueError):
        enabled_generators(PlannerConfig(candidate_generators=("nope",)))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Prioritiser (ADR-0036).
# ---------------------------------------------------------------------------


def _view(key: str, *, yield_: float, crit: float, conf: float) -> ProposedTestCaseView:
    return ProposedTestCaseView(
        engagement_id=EID,
        key_hash=TestCaseKeyHash(key),
        test_class="forced_browsing",
        generator="c1",
        source="deterministic-c1",
        target_endpoint_id="ep",
        method="GET",
        host="shop.example.com",
        path_template="/x",
        payload_class="no-payload",
        expected_yield=yield_,
        confidence=0.99,
        effective_target_confidence=conf,
        criticality=crit,
        justification="j",
        expected_outcome="o",
        priority_score=priority_score(
            expected_yield=yield_, criticality=crit, effective_target_confidence=conf
        ),
    )


def test_prioritizer_orders_by_score_and_truncates_top_n() -> None:
    low = _view("a" * 64, yield_=0.2, crit=1.0, conf=0.9)
    high = _view("b" * 64, yield_=0.9, crit=1.0, conf=0.9)
    mid = _view("c" * 64, yield_=0.5, crit=1.0, conf=0.9)
    ordered = prioritize([low, high, mid])
    assert [v.key_hash[0] for v in ordered] == ["b", "c", "a"]
    # Top-N truncation.
    assert [v.key_hash[0] for v in prioritize([low, high, mid], top_n=2)] == ["b", "c"]
    assert prioritize([low, high, mid], top_n=0) == []


def test_prioritizer_discounts_shaky_target_confidence() -> None:
    # Same yield/criticality, but a shaky target (low effective confidence) sorts
    # below a solid one (ADR-0036 discount).
    solid = _view("a" * 64, yield_=0.6, crit=1.0, conf=0.95)
    shaky = _view("b" * 64, yield_=0.6, crit=1.0, conf=0.20)
    assert [v.key_hash[0] for v in prioritize([shaky, solid])] == ["a", "b"]


def test_prioritizer_is_stable_on_ties() -> None:
    # Equal scores break by (test_class, host, path, method, key_hash) — stable.
    a = _view("a" * 64, yield_=0.5, crit=1.0, conf=0.9)
    b = _view("b" * 64, yield_=0.5, crit=1.0, conf=0.9)
    assert [v.key_hash[0] for v in prioritize([b, a])] == ["a", "b"]
    assert [v.key_hash[0] for v in prioritize([a, b])] == ["a", "b"]


# ---------------------------------------------------------------------------
# Re-surface predicate (ADR-0040).
# ---------------------------------------------------------------------------


def test_resurface_permanent_never_resurfaces() -> None:
    v = should_resurface(
        disposition="permanent",
        snapshot_confidence=0.1,
        snapshot_derived_from_count=0,
        current_confidence=0.99,
        current_derived_from_count=10,
    )
    assert v.resurface is False


def test_resurface_defer_on_confidence_up() -> None:
    v = should_resurface(
        disposition="defer",
        snapshot_confidence=0.40,
        snapshot_derived_from_count=2,
        current_confidence=0.60,  # +0.20 material
        current_derived_from_count=2,
    )
    assert v.resurface is True
    assert v.reason is not None and "confidence" in v.reason


def test_resurface_defer_on_new_evidence() -> None:
    v = should_resurface(
        disposition="defer",
        snapshot_confidence=0.50,
        snapshot_derived_from_count=2,
        current_confidence=0.50,  # unchanged
        current_derived_from_count=5,  # new DERIVED_FROM
    )
    assert v.resurface is True
    assert v.reason is not None and "DERIVED_FROM" in v.reason


def test_resurface_defer_suppressed_when_nothing_changed() -> None:
    v = should_resurface(
        disposition="defer",
        snapshot_confidence=0.50,
        snapshot_derived_from_count=2,
        current_confidence=0.51,  # below the material delta
        current_derived_from_count=2,
    )
    assert v.resurface is False


# ---------------------------------------------------------------------------
# Review ledger event shape (ADR-0040).
# ---------------------------------------------------------------------------


def test_reject_event_requires_disposition() -> None:
    from datetime import UTC, datetime

    with pytest.raises(ValidationError):
        ReviewLedgerEvent(
            engagement_id=EID,
            key_hash=TestCaseKeyHash("k"),
            actor="alice",
            timestamp=datetime.now(UTC),
            decision="reject",
            prior_status="proposed",
            new_status="rejected",
            evidence_confidence=0.5,
        )


def test_approve_event_rejects_disposition() -> None:
    from datetime import UTC, datetime

    with pytest.raises(ValidationError):
        ReviewLedgerEvent(
            engagement_id=EID,
            key_hash=TestCaseKeyHash("k"),
            actor="alice",
            timestamp=datetime.now(UTC),
            decision="approve",
            disposition="defer",
            prior_status="proposed",
            new_status="approved",
            evidence_confidence=0.5,
        )
