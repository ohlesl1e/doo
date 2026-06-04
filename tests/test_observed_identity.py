"""Unit tests for observed-response identity extraction + choice (ADR-0029)."""

from __future__ import annotations

from doo.extraction.identity_signals import extract_observed_identity_from_headers
from doo.ontology.identity_reconcile import choose_observed_identity

# --- header extraction (M1) -------------------------------------------------


def test_identity_header_extracted() -> None:
    oi = extract_observed_identity_from_headers({"x-user-id": "alice", "content-type": "text/html"})
    assert oi is not None
    assert oi.signal == "x-user-id"
    assert oi.value == "alice"


def test_identity_header_priority_user_id_over_account_id() -> None:
    oi = extract_observed_identity_from_headers({"x-account-id": "acct-9", "x-user-id": "alice"})
    assert oi is not None
    assert (oi.signal, oi.value) == ("x-user-id", "alice")


def test_no_identity_header_returns_none() -> None:
    assert extract_observed_identity_from_headers({"content-type": "application/json"}) is None


def test_empty_identity_header_value_ignored() -> None:
    assert extract_observed_identity_from_headers({"x-user-id": "   "}) is None


# --- choice among accumulated identities ------------------------------------


def test_choose_single_identity() -> None:
    assert choose_observed_identity([("x-user-id", "alice")]) == ("x-user-id", "alice")


def test_choose_highest_priority_signal() -> None:
    # x-user-id outranks x-account-id even if both are present.
    assert choose_observed_identity(
        [("x-account-id", "acct-9"), ("x-user-id", "alice")]
    ) == ("x-user-id", "alice")


def test_choose_conflicting_top_signal_is_ambiguous() -> None:
    # Two different x-user-id values on one AuthContext -> never merge.
    assert choose_observed_identity([("x-user-id", "alice"), ("x-user-id", "bob")]) is None


def test_choose_empty_is_none() -> None:
    assert choose_observed_identity([]) is None


def test_choose_ignores_conflict_on_lower_signal_when_top_is_clean() -> None:
    # Clean top signal wins; a conflict on a lower-priority signal is irrelevant.
    assert choose_observed_identity(
        [("x-user-id", "alice"), ("x-account-id", "a1"), ("x-account-id", "a2")]
    ) == ("x-user-id", "alice")
