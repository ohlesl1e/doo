"""Action-layer (L5) contracts construct cleanly and enforce their identity rules.

Cover the identity rule, the three-way XOR target, and the dispatch-status enum
for `TestCase` / `Finding` / `ExecutedAsEdge` — the shapes the Planner and dispatch
loop build against, locked in so they cannot drift silently.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from doo.events.execution import (
    DISPATCH_STATUSES,
    ExecutedAsEdge,
    Finding,
    TestCase,
    compute_testcase_key_hash,
)


def _now() -> datetime:
    return datetime.now(UTC)


def _testcase_kwargs() -> dict:
    payload_hash = hashlib.sha256(b"").hexdigest()
    key_hash = compute_testcase_key_hash(
        engagement_id="acme-2026",
        test_class="idor",
        target_endpoint_id="ep-1",
        target_parameter_id=None,
        target_trust_boundary_id=None,
        payload_class="benign-probe",
        payload_hash=payload_hash,
        attacker_principal="alice",
        attacker_slot="cookie",
    )
    return dict(
        source="manual",
        confidence=1.0,
        confidence_method="manual",
        first_seen=_now(),
        last_seen=_now(),
        ingested_at=_now(),
        inferred_at=_now(),
        code_version="planner-v1",
        engagement_id="acme-2026",
        test_class="idor",
        target_endpoint_id="ep-1",
        payload_class="benign-probe",
        payload_hash=payload_hash,
        attacker_principal="alice",
        attacker_slot="cookie",
        auth_context_id="ac-1",
        key_hash=key_hash,
    )


def test_testcase_constructs_when_hash_matches() -> None:
    tc = TestCase(**_testcase_kwargs())
    assert tc.test_class == "idor"


def test_testcase_rejects_wrong_key_hash() -> None:
    kwargs = _testcase_kwargs()
    kwargs["key_hash"] = "0" * 64
    with pytest.raises(ValidationError) as exc_info:
        TestCase(**kwargs)
    assert "key_hash" in str(exc_info.value)


def test_testcase_rejects_two_targets() -> None:
    payload_hash = hashlib.sha256(b"").hexdigest()
    # compute_testcase_key_hash itself enforces the XOR — so calling it with
    # two targets raises before we even build the TestCase.
    with pytest.raises(ValueError):
        compute_testcase_key_hash(
            engagement_id="acme-2026",
            test_class="idor",
            target_endpoint_id="ep-1",
            target_parameter_id="p-1",
            target_trust_boundary_id=None,
            payload_class="benign-probe",
            payload_hash=payload_hash,
            attacker_principal="alice",
            attacker_slot="cookie",
        )


def test_testcase_rejects_zero_targets() -> None:
    payload_hash = hashlib.sha256(b"").hexdigest()
    with pytest.raises(ValueError):
        compute_testcase_key_hash(
            engagement_id="acme-2026",
            test_class="idor",
            target_endpoint_id=None,
            target_parameter_id=None,
            target_trust_boundary_id=None,
            payload_class="benign-probe",
            payload_hash=payload_hash,
            attacker_principal="alice",
            attacker_slot="cookie",
        )


def test_testcase_strict_extra_forbid() -> None:
    bad = _testcase_kwargs()
    bad["bogus"] = 1
    with pytest.raises(ValidationError):
        TestCase(**bad)


def test_finding_requires_affects() -> None:
    base = dict(
        source="llm-asset-promotion",
        confidence=0.8,
        confidence_method="llm-self-reported",
        first_seen=_now(),
        last_seen=_now(),
        ingested_at=_now(),
        inferred_at=_now(),
        code_version="finding-v1",
        engagement_id="acme-2026",
        id="f-1",
        severity="high",
        category="idor",
        title="cross-tenant read",
        referenced_testcase_hashes=("a" * 64,),
    )
    # No affects → invalid.
    with pytest.raises(ValidationError):
        Finding(**base)


def test_finding_accepts_endpoint_affects() -> None:
    f = Finding(
        source="llm-asset-promotion",
        confidence=0.8,
        confidence_method="llm-self-reported",
        first_seen=_now(),
        last_seen=_now(),
        ingested_at=_now(),
        inferred_at=_now(),
        code_version="finding-v1",
        engagement_id="acme-2026",
        id="f-1",
        severity="high",
        category="idor",
        title="cross-tenant read",
        referenced_testcase_hashes=("a" * 64,),
        affected_endpoint_ids=("ep-1",),
    )
    assert f.id == "f-1"


def test_executed_as_edge_dispatch_status_enum() -> None:
    edge = ExecutedAsEdge(
        source="agent",
        confidence=1.0,
        confidence_method="manual",
        first_seen=_now(),
        last_seen=_now(),
        ingested_at=_now(),
        testcase_key_hash="a" * 64,
        request_observation_id="ro-1",
        engagement_id="acme-2026",
        dispatch_status="ok",
        request_role="primary",
        run_id="run-aaaaaaaaaaaa",
    )
    assert edge.dispatch_status == "ok"
    assert edge.request_role == "primary"


def test_executed_as_edge_rejects_unknown_status() -> None:
    with pytest.raises(ValidationError):
        ExecutedAsEdge(
            source="agent",
            confidence=1.0,
            confidence_method="manual",
            first_seen=_now(),
            last_seen=_now(),
            ingested_at=_now(),
            testcase_key_hash="a" * 64,
            request_observation_id="ro-1",
            engagement_id="acme-2026",
            dispatch_status="something-new",
            request_role="primary",
            run_id="run-aaaaaaaaaaaa",
        )


def test_dispatch_statuses_match_adr_0013() -> None:
    """Locks in the ADR-0013 (+ ADR-0041 `replay_invalid`) enum so a future change
    must update both this test and the contracts in one PR."""
    assert set(DISPATCH_STATUSES) == {
        "ok",
        "auth_invalid",
        "replay_invalid",
        "rate_limited",
        "dispatcher_blocked",
        "transport_error",
    }
