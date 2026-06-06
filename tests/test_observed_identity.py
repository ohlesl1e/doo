"""Unit tests for observed-response identity extraction + choice (ADR-0030)."""

from __future__ import annotations

from doo.extraction.identity_signals import (
    extract_observed_identities_from_headers,
    extract_observed_identities_from_self_endpoint_body,
    is_self_endpoint,
)
from doo.ontology.identity_reconcile import choose_observed_identity

# --- header extraction (claim-tagged, multi-value) --------------------------


def test_identity_header_extracted() -> None:
    ois = extract_observed_identities_from_headers(
        {"x-user-id": "alice", "content-type": "text/html"}
    )
    assert [(oi.claim, oi.value) for oi in ois] == [("x-user-id", "alice")]


def test_identity_headers_return_all_present_in_priority_order() -> None:
    ois = extract_observed_identities_from_headers(
        {"x-account-id": "acct-9", "x-user-id": "alice"}
    )
    # x-user-id ranks before x-account-id; both are returned (claim-tagged).
    assert [(oi.claim, oi.value) for oi in ois] == [
        ("x-user-id", "alice"),
        ("x-account-id", "acct-9"),
    ]


def test_no_identity_header_returns_empty() -> None:
    assert extract_observed_identities_from_headers({"content-type": "application/json"}) == ()


def test_empty_identity_header_value_ignored() -> None:
    assert extract_observed_identities_from_headers({"x-user-id": "   "}) == ()


# --- choice among accumulated identities ------------------------------------


def test_choose_single_identity() -> None:
    assert choose_observed_identity([("x-user-id", "alice")]) == ("x-user-id", "alice")


def test_choose_highest_priority_claim() -> None:
    # x-user-id outranks x-account-id even if both are present.
    assert choose_observed_identity(
        [("x-account-id", "acct-9"), ("x-user-id", "alice")]
    ) == ("x-user-id", "alice")


def test_choose_conflicting_top_claim_is_ambiguous() -> None:
    # Two different x-user-id values on one AuthContext -> never merge.
    assert choose_observed_identity([("x-user-id", "alice"), ("x-user-id", "bob")]) is None


def test_choose_empty_is_none() -> None:
    assert choose_observed_identity([]) is None


def test_choose_ignores_conflict_on_lower_claim_when_top_is_clean() -> None:
    # Clean top claim wins; a conflict on a lower-priority claim is irrelevant.
    assert choose_observed_identity(
        [("x-user-id", "alice"), ("x-account-id", "a1"), ("x-account-id", "a2")]
    ) == ("x-user-id", "alice")


def test_choose_header_outranks_body_claim() -> None:
    # A header claim outranks a body claim (T-OI1 > T-OI2).
    assert choose_observed_identity(
        [("_id", "from-body"), ("x-user-id", "from-header")]
    ) == ("x-user-id", "from-header")


def test_choose_account_unique_claim_outranks_email() -> None:
    # ADR-0030: `email` is person-level and only ever a last resort key.
    assert choose_observed_identity(
        [("email", "alice@x.com"), ("_id", "abc")]
    ) == ("_id", "abc")


def test_choose_email_keys_when_only_email_present() -> None:
    assert choose_observed_identity([("email", "alice@x.com")]) == ("email", "alice@x.com")


# --- self-endpoint path matcher ---------------------------------------------


def test_self_endpoint_matches_common_patterns() -> None:
    for path in ("/me", "/api/wireless/users/me", "/profile", "/whoami", "/account",
                 "/me/password", "/user/current", "/current-user",
                 "/userinfo", "/connect/userinfo"):  # OIDC userinfo (SSO)
        assert is_self_endpoint(path), path


def test_self_endpoint_rejects_ordinary_paths() -> None:
    for path in ("/method", "/readme", "/home", "/api/items", "/accounts/123/orders",
                 "/messages"):
        assert not is_self_endpoint(path), path


# --- self-endpoint body identity (claim-tagged, multi-value) ----------------


def test_body_identity_top_level_id() -> None:
    ois = extract_observed_identities_from_self_endpoint_body(
        '{"_id": "6614a9412c25a5000df5d4d6", "role": "admin"}', "application/json"
    )
    assert [(oi.claim, oi.value) for oi in ois] == [("_id", "6614a9412c25a5000df5d4d6")]


def test_body_identity_returns_all_claims_id_and_email() -> None:
    # ADR-0030 multi-value: a /me body with both `_id` and `email` yields BOTH,
    # claim-tagged — the account-unique `_id` keys, `email` is recorded as an alias.
    ois = extract_observed_identities_from_self_endpoint_body(
        '{"_id": "abc", "email": "Alice@X.com"}', "application/json"
    )
    pairs = {(oi.claim, oi.value) for oi in ois}
    assert pairs == {("_id", "abc"), ("email", "alice@x.com")}
    # And the keying choice prefers `_id` over the person-level email.
    assert choose_observed_identity(list(pairs)) == ("_id", "abc")


def test_body_identity_from_wrapper_object() -> None:
    ois = extract_observed_identities_from_self_endpoint_body(
        '{"data": {"sub": "user-9", "name": "x"}}', "application/json"
    )
    assert [(oi.claim, oi.value) for oi in ois] == [("sub", "user-9")]


def test_body_identity_email_is_lowercased() -> None:
    ois = extract_observed_identities_from_self_endpoint_body(
        '{"email": "Admin@Example.COM"}', "application/json"
    )
    assert [(oi.claim, oi.value) for oi in ois] == [("email", "admin@example.com")]


def test_body_identity_non_json_is_empty() -> None:
    assert extract_observed_identities_from_self_endpoint_body("OK", "text/plain") == ()


def test_body_identity_malformed_json_is_empty() -> None:
    assert (
        extract_observed_identities_from_self_endpoint_body("{not json", "application/json") == ()
    )


def test_body_identity_no_claim_is_empty() -> None:
    assert extract_observed_identities_from_self_endpoint_body(
        '{"role": "admin", "mfaEnabled": false}', "application/json"
    ) == ()
