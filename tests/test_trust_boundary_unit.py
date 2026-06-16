"""Unit tests for the pure capability-claim-delta decision (ADR-0039).

These exercise `canonical/trust_boundary.py` in isolation — no graph, no I/O —
the evidence-gating rules a capability `TrustBoundary` rests on: a boundary is
drawn only where the decoded `identity_claims` actually distinguish two tiers, and
the boundary `kind` is the highest-precedence axis the delta touches.
"""

from __future__ import annotations

from doo.canonical.trust_boundary import (
    CAPABILITY_CLAIMS,
    TENANT_KIND,
    capability_kind_for_delta,
    differing_capability_claims,
)


def test_scope_delta_is_a_scope_boundary() -> None:
    a = {"sub": "u1", "scope": "read"}
    b = {"sub": "u1", "scope": "read write admin"}
    differing = differing_capability_claims(a, b)
    assert differing == frozenset({"scope"})
    assert capability_kind_for_delta(differing) == "scope"


def test_scope_is_order_insensitive() -> None:
    a = {"scope": "read write"}
    b = {"scope": "write read"}
    assert differing_capability_claims(a, b) == frozenset()
    assert capability_kind_for_delta(differing_capability_claims(a, b)) is None


def test_acr_delta_is_an_mfa_boundary() -> None:
    a = {"acr": "urn:mace:incommon:iap:silver"}
    b = {"acr": "urn:mace:incommon:iap:bronze"}
    differing = differing_capability_claims(a, b)
    assert differing == frozenset({"acr"})
    assert capability_kind_for_delta(differing) == "mfa"


def test_amr_delta_is_an_mfa_boundary_and_order_insensitive() -> None:
    a = {"amr": ["pwd", "otp"]}
    b = {"amr": ["otp", "pwd"]}
    assert differing_capability_claims(a, b) == frozenset()  # same set, different order
    c = {"amr": ["pwd"]}
    differing = differing_capability_claims(a, c)
    assert differing == frozenset({"amr"})
    assert capability_kind_for_delta(differing) == "mfa"


def test_auth_time_delta_is_a_freshness_boundary() -> None:
    a = {"auth_time": 1000}
    b = {"auth_time": 5000}
    differing = differing_capability_claims(a, b)
    assert differing == frozenset({"auth_time"})
    assert capability_kind_for_delta(differing) == "freshness"


def test_no_delta_means_no_boundary() -> None:
    a = {"sub": "u1", "scope": "read", "acr": "x", "auth_time": 10}
    b = {"sub": "u1", "scope": "read", "acr": "x", "auth_time": 10}
    assert differing_capability_claims(a, b) == frozenset()
    assert capability_kind_for_delta(differing_capability_claims(a, b)) is None


def test_claim_present_on_one_side_only_is_not_a_delta() -> None:
    # Evidence-gating: a claim one token omits is missing evidence, not an
    # observed tier difference. No boundary on that claim alone.
    a = {"sub": "u1", "scope": "read"}
    b = {"sub": "u1"}  # scope absent
    assert differing_capability_claims(a, b) == frozenset()
    assert capability_kind_for_delta(differing_capability_claims(a, b)) is None


def test_scope_outranks_mfa_outranks_freshness() -> None:
    # A delta touching several axes collapses to the single highest-precedence kind.
    differing = frozenset({"scope", "acr", "auth_time"})
    assert capability_kind_for_delta(differing) == "scope"
    assert capability_kind_for_delta(frozenset({"acr", "auth_time"})) == "mfa"
    assert capability_kind_for_delta(frozenset({"auth_time"})) == "freshness"


def test_empty_delta_yields_none() -> None:
    assert capability_kind_for_delta(frozenset()) is None


def test_non_capability_claims_are_ignored() -> None:
    # Differing `sub` / `email` / `exp` are not capability axes — no boundary.
    a = {"sub": "u1", "email": "a@x.com", "exp": 1}
    b = {"sub": "u2", "email": "b@x.com", "exp": 2}
    assert differing_capability_claims(a, b) == frozenset()


def test_capability_claim_set_is_the_documented_four() -> None:
    assert CAPABILITY_CLAIMS == frozenset({"scope", "acr", "amr", "auth_time"})
    assert TENANT_KIND == "tenant"
