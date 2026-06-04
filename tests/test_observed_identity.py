"""Unit tests for observed-response identity extraction + choice (ADR-0029)."""

from __future__ import annotations

from doo.extraction.identity_signals import (
    extract_observed_identity_from_headers,
    extract_observed_identity_from_self_endpoint_body,
    is_self_endpoint,
)
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


def test_choose_header_outranks_body() -> None:
    # A header signal outranks the self-endpoint "body" signal (T-OI1 > T-OI2).
    assert choose_observed_identity(
        [("body", "from-body"), ("x-user-id", "from-header")]
    ) == ("x-user-id", "from-header")


# --- self-endpoint path matcher (M2) ----------------------------------------


def test_self_endpoint_matches_common_patterns() -> None:
    for path in ("/me", "/api/wireless/users/me", "/profile", "/whoami", "/account",
                 "/me/password", "/user/current", "/current-user"):
        assert is_self_endpoint(path), path


def test_self_endpoint_rejects_ordinary_paths() -> None:
    for path in ("/method", "/readme", "/home", "/api/items", "/accounts/123/orders",
                 "/messages"):
        assert not is_self_endpoint(path), path


# --- self-endpoint body identity (M1-body) ----------------------------------


def test_body_identity_top_level_id() -> None:
    oi = extract_observed_identity_from_self_endpoint_body(
        '{"_id": "6614a9412c25a5000df5d4d6", "role": "admin"}', "application/json"
    )
    assert oi is not None
    assert (oi.signal, oi.value) == ("body", "6614a9412c25a5000df5d4d6")


def test_body_identity_email_takes_priority() -> None:
    oi = extract_observed_identity_from_self_endpoint_body(
        '{"_id": "abc", "email": "alice@x.com"}', "application/json"
    )
    assert oi is not None
    assert oi.value == "alice@x.com"


def test_body_identity_from_wrapper_object() -> None:
    oi = extract_observed_identity_from_self_endpoint_body(
        '{"data": {"sub": "user-9", "name": "x"}}', "application/json"
    )
    assert oi is not None
    assert oi.value == "user-9"


def test_body_identity_non_json_is_none() -> None:
    assert extract_observed_identity_from_self_endpoint_body("OK", "text/plain") is None


def test_body_identity_malformed_json_is_none() -> None:
    assert extract_observed_identity_from_self_endpoint_body("{not json", "application/json") is None


def test_body_identity_no_claim_is_none() -> None:
    assert extract_observed_identity_from_self_endpoint_body(
        '{"role": "admin", "mfaEnabled": false}', "application/json"
    ) is None
