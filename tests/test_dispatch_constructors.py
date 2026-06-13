"""`executor.constructors` table-driven unit tests (ADR-0043).

A constructor is a **pure function** of `(DispatchTestCase, EvidenceObservation,
AuthMaterial)` → `ConcreteRequest`. These tests assert externally-observable
behaviour at the module boundary: given a fixture TestCase + evidence + material,
the constructor emits *these* bytes. No graph, no network, no LLM.
"""

from __future__ import annotations

import pytest

from doo.canonical.value_objects import HostRef
from doo.dispatch.executor.constructors import (
    ConstructorMissingError,
    constructor_for,
    has_constructor,
    idor_primary,
)
from doo.dispatch.executor.evidence import DispatchTestCase, EvidenceObservation
from doo.dispatch.secrets import AuthMaterial
from doo.ids import AuthContextId, EngagementId, ObservationId, TestCaseKeyHash


def _testcase(**over: object) -> DispatchTestCase:
    return DispatchTestCase(
        engagement_id=EngagementId("eng-x"),
        key_hash=TestCaseKeyHash("k" * 64),
        test_class=over.get("test_class", "idor"),  # type: ignore[arg-type]
        payload_class="auth-token-swap",
        auth_context_id=AuthContextId("ac-attacker"),
        target_endpoint_id="ep-1",
        target_parameter_id=None,
        target_trust_boundary_id=None,
        hold=tuple(over.get("hold", ("order_id",))),  # type: ignore[arg-type]
        replay_hazards=(),
        expected_yield=0.9,
        generator="c2",
        confidence=0.99,
    )


def _evidence(**over: object) -> EvidenceObservation:
    return EvidenceObservation(
        observation_id=ObservationId("obs-victim-1"),
        method=str(over.get("method", "GET")),
        host=HostRef(scheme="https", canonical_hostname="api.example.com"),
        concrete_path=str(over.get("concrete_path", "/orders/123")),
        path_template=str(over.get("path_template", "/orders/{order_id}")),
        query=dict(over.get("query", {})),  # type: ignore[arg-type]
        headers=dict(
            over.get(
                "headers",
                {
                    "Authorization": "Bearer victim-token",
                    "Accept": "application/json",
                    "X-Request-Id": "abc",
                },
            )
        ),  # type: ignore[arg-type]
        cookies=dict(over.get("cookies", {})),  # type: ignore[arg-type]
        victim_auth_context_id=AuthContextId("ac-victim"),
    )


@pytest.mark.parametrize(
    ("kind", "expect_header", "expect_value"),
    [
        ("bearer", "Authorization", "Bearer ATTACKER-TOKEN"),
        ("basic_auth", "Authorization", "Basic ATTACKER-TOKEN"),
        ("api_key", "X-API-Key", "ATTACKER-TOKEN"),
    ],
)
def test_idor_primary_swaps_auth_and_strips_victim_credential(
    kind: str, expect_header: str, expect_value: str
) -> None:
    """`(idor, primary)`: victim's request shape verbatim; attacker's auth swapped in.

    The victim's `Authorization` header MUST be stripped (replaying it alongside
    the attacker's would mask the authz hole — the test would pass for the wrong
    reason).
    """
    material = AuthMaterial(kind=kind, raw="ATTACKER-TOKEN", principal_label="user-b")  # type: ignore[arg-type]
    req = idor_primary(_testcase(), _evidence(), material)

    assert req.method == "GET"
    assert req.host.canonical_hostname == "api.example.com"
    # Hold applied: the victim's concrete path (their `order_id=123`) is replayed.
    assert req.path == "/orders/123"
    assert req.path_template == "/orders/{order_id}"
    # The TestCase's auth_context_id (attacker), not the evidence's (victim).
    assert req.auth_context_id == "ac-attacker"

    headers = dict(req.headers)
    # Victim's auth gone:
    assert headers.get("Authorization") != "Bearer victim-token"
    # Attacker's auth present:
    assert headers.get(expect_header) == expect_value
    # Non-auth headers preserved verbatim from evidence:
    assert headers.get("Accept") == "application/json"
    assert headers.get("X-Request-Id") == "abc"


def test_idor_primary_preserves_query_hold() -> None:
    """A query-param IDOR: the held query param is carried verbatim from evidence."""
    ev = _evidence(
        concrete_path="/orders",
        path_template="/orders",
        query={"order_id": "123", "format": "json"},
    )
    req = idor_primary(
        _testcase(hold=("order_id",)),
        ev,
        AuthMaterial(kind="bearer", raw="ATK", principal_label="user-b"),
    )
    assert dict(req.query) == {"order_id": "123", "format": "json"}


def test_registry_lookup_hits_and_misses() -> None:
    assert has_constructor("idor", "primary")
    fn = constructor_for("idor", "primary")
    assert fn is idor_primary

    assert not has_constructor("ssrf", "primary")
    with pytest.raises(ConstructorMissingError, match="no constructor registered"):
        constructor_for("ssrf", "primary")


def test_constructor_is_pure() -> None:
    """Same inputs → identical `ConcreteRequest` (constructors are reproducible)."""
    tc, ev = _testcase(), _evidence()
    mat = AuthMaterial(kind="bearer", raw="ATK", principal_label="user-b")
    a = idor_primary(tc, ev, mat)
    b = idor_primary(tc, ev, mat)
    assert a == b
