"""Unit tests for observed-response identity extraction + choice (ADR-0030/0031)."""

from __future__ import annotations

import json

import jwt as pyjwt

from doo.extraction.identity_signals import (
    extract_observed_identities_from_headers,
    extract_observed_identities_from_self_endpoint_body,
    extract_oidc_login_identity,
    extract_saml_login_identity,
    is_self_endpoint,
)
from doo.ontology.identity_reconcile import choose_observed_identity

_OIDC_SK = "oidc-signing-key-at-least-32-bytes-long!!"


def test_oidc_login_extracts_idtoken_identities_and_issued_access_token() -> None:
    idt = pyjwt.encode(
        {"sub": "u-1", "iss": "https://idp.example", "email": "Admin@X.COM"},
        _OIDC_SK,
        algorithm="HS256",
    )
    body = json.dumps({"id_token": idt, "access_token": "opaque-at-123", "token_type": "Bearer"})
    res = extract_oidc_login_identity(body, "application/json")
    assert res is not None
    identities, access_token = res
    assert access_token == "opaque-at-123"
    claims = {i.claim: i.value for i in identities}
    assert claims["sub"] == "u-1"
    assert claims["iss"] == "https://idp.example"  # iss carrier for sub scoping
    assert claims["email"] == "admin@x.com"  # lowercased


def test_oidc_login_none_without_id_token() -> None:
    assert extract_oidc_login_identity(json.dumps({"access_token": "x"}), "application/json") is None


def test_oidc_login_none_without_access_token() -> None:
    idt = pyjwt.encode({"sub": "u"}, _OIDC_SK, algorithm="HS256")
    assert extract_oidc_login_identity(json.dumps({"id_token": idt}), "application/json") is None


def test_oidc_login_none_on_non_json_or_malformed() -> None:
    assert extract_oidc_login_identity("not json", "text/plain") is None
    assert (
        extract_oidc_login_identity(
            json.dumps({"id_token": "not-a-jwt", "access_token": "x"}), "application/json"
        )
        is None
    )

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


# --- SAML assertion extraction (ADR-0031, T-IDV3) ---------------------------

import base64 as _b64  # noqa: E402


def _saml_b64(*, name_id: str, fmt: str, issuer: str = "https://idp.example/saml",
              email_attr: str | None = None) -> str:
    attr = (
        f'<saml:AttributeStatement><saml:Attribute Name="email">'
        f"<saml:AttributeValue>{email_attr}</saml:AttributeValue>"
        f"</saml:Attribute></saml:AttributeStatement>"
        if email_attr else ""
    )
    xml = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        f"<saml:Issuer>{issuer}</saml:Issuer><saml:Assertion><saml:Subject>"
        f'<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:{fmt}">'
        f"{name_id}</saml:NameID></saml:Subject>{attr}</saml:Assertion></samlp:Response>"
    )
    return _b64.b64encode(xml.encode()).decode()


def test_saml_persistent_nameid_maps_to_issuer_scoped_sub() -> None:
    ids = {i.claim: i.value for i in extract_saml_login_identity(
        _saml_b64(name_id="persistent-abc", fmt="persistent"))}
    assert ids["sub"] == "persistent-abc"
    assert ids["iss"] == "https://idp.example/saml"  # SAML Issuer scopes the sub


def test_saml_emailaddress_nameid_maps_to_email() -> None:
    ids = {i.claim: i.value for i in extract_saml_login_identity(
        _saml_b64(name_id="Bob@Y.COM", fmt="emailAddress"))}
    assert ids == {"email": "bob@y.com"}  # lowercased, person-level; no sub/iss


def test_saml_transient_nameid_is_never_a_key() -> None:
    # transient is per-session — yields no sub/iss; only a present email attribute.
    ids = extract_saml_login_identity(
        _saml_b64(name_id="ephemeral-xyz", fmt="transient", email_attr="carol@z.com"))
    claims = {i.claim: i.value for i in ids}
    assert "sub" not in claims
    assert claims.get("email") == "carol@z.com"


def test_saml_email_attribute_extracted() -> None:
    ids = {i.claim: i.value for i in extract_saml_login_identity(
        _saml_b64(name_id="p-1", fmt="persistent", email_attr="Dave@W.com"))}
    assert ids["sub"] == "p-1"
    assert ids["email"] == "dave@w.com"


def test_saml_malformed_and_doctype_yield_empty() -> None:
    assert extract_saml_login_identity("not-base64-!!!") == ()
    assert extract_saml_login_identity(_b64.b64encode(b"<notxml").decode()) == ()
    assert extract_saml_login_identity(_b64.b64encode(b"<!DOCTYPE x><r/>").decode()) == ()
