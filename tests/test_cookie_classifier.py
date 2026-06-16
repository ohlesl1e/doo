"""Unit tests for ``doo.canonical.cookies.cookie_feeds_identity`` (ADR-0026, T-AI1).

Tests the include-biased shape classifier:
- Opaque tokens, all-hex JSESSIONID, lowercase-hex PHPSESSID → True (credential).
- Short / integer / boolean / empty values → False (app-state).
- JWT-shaped values → True (unconditional fast-path).

Also covers cue-level integration: filtering propagates through
``extract_auth_context_cue`` so that only session-credential cookies contribute
to ``cookie_session_hashes``.
"""

from __future__ import annotations

import jwt as pyjwt

from doo.canonical.cookies import (
    canonical_credential_value,
    cookie_feeds_identity,
    normalize_cookie_value,
)
from doo.canonical.identity import compute_auth_hash
from doo.extraction.har import extract_auth_context_cue

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DUMMY_NAME = "cookie"  # name is unused by the heuristic; any value is fine


def _request(cookies: list[tuple[str, str]]) -> dict[str, object]:
    return {
        "method": "GET",
        "url": "https://api.example.com/me",
        "headers": [],
        "cookies": [{"name": n, "value": v} for n, v in cookies],
    }


# ---------------------------------------------------------------------------
# Pure predicate unit tests
# ---------------------------------------------------------------------------


# --- Values that FEED identity (return True) ---------------------------------


def test_opaque_token_feeds_identity() -> None:
    """A typical opaque session token (random base64) is included."""
    assert cookie_feeds_identity(_DUMMY_NAME, "abc123XYZ9012345") is True


def test_all_hex_jsessionid_feeds_identity() -> None:
    """All-hex JSESSIONID (no mixed-case needed) is included."""
    assert cookie_feeds_identity("JSESSIONID", "4a8f2c1e7b3d9f05a2c6e8b4d1f3a7c9") is True


def test_lowercase_hex_phpsessid_feeds_identity() -> None:
    """Lowercase-hex PHPSESSID is included (not rejected by int/bool checks)."""
    assert cookie_feeds_identity("PHPSESSID", "e9a4b2d8c1f3a7e5b9c2d4f6a8b1e3c5") is True


def test_jwt_shaped_value_feeds_identity() -> None:
    """A JWT-shaped cookie value is unconditionally a session credential."""
    token = pyjwt.encode(
        {"sub": "user-uuid", "exp": 4102444800},
        "test-secret-key-at-least-32-bytes-long!!",
        algorithm="HS256",
    )
    assert cookie_feeds_identity("token", token) is True


def test_opaque_base64_feeds_identity() -> None:
    """A URL-safe base64 opaque value (long enough) is included."""
    assert cookie_feeds_identity(_DUMMY_NAME, "dGVzdC10b2tlbi12YWx1ZQ") is True


def test_mixed_alphanumeric_feeds_identity() -> None:
    """A mixed alphanumeric value ≥ 8 chars is included."""
    assert cookie_feeds_identity(_DUMMY_NAME, "Abc12345") is True


# --- Values that do NOT feed identity (return False) -------------------------


def test_empty_string_excluded() -> None:
    assert cookie_feeds_identity(_DUMMY_NAME, "") is False


def test_whitespace_only_excluded() -> None:
    assert cookie_feeds_identity(_DUMMY_NAME, "   ") is False


def test_short_value_excluded() -> None:
    """Length < 8 → excluded."""
    assert cookie_feeds_identity(_DUMMY_NAME, "ab") is False


def test_length_7_excluded() -> None:
    assert cookie_feeds_identity(_DUMMY_NAME, "abcdefg") is False


def test_length_8_feeds_identity() -> None:
    """Exactly 8 chars → included (boundary)."""
    assert cookie_feeds_identity(_DUMMY_NAME, "abcdefgh") is True


def test_integer_zero_excluded() -> None:
    assert cookie_feeds_identity(_DUMMY_NAME, "0") is False


def test_integer_positive_excluded() -> None:
    assert cookie_feeds_identity(_DUMMY_NAME, "42") is False


def test_integer_negative_excluded() -> None:
    assert cookie_feeds_identity(_DUMMY_NAME, "-99") is False


def test_large_integer_excluded() -> None:
    """A long pure-integer value (pagination offset etc.) is excluded."""
    assert cookie_feeds_identity(_DUMMY_NAME, "123456789") is False


def test_bool_true_excluded() -> None:
    assert cookie_feeds_identity(_DUMMY_NAME, "true") is False


def test_bool_false_excluded() -> None:
    assert cookie_feeds_identity(_DUMMY_NAME, "false") is False


def test_bool_yes_excluded() -> None:
    assert cookie_feeds_identity(_DUMMY_NAME, "yes") is False


def test_bool_no_excluded() -> None:
    assert cookie_feeds_identity(_DUMMY_NAME, "no") is False


def test_bool_on_excluded() -> None:
    assert cookie_feeds_identity(_DUMMY_NAME, "on") is False


def test_bool_off_excluded() -> None:
    assert cookie_feeds_identity(_DUMMY_NAME, "off") is False


def test_null_sentinel_excluded() -> None:
    assert cookie_feeds_identity(_DUMMY_NAME, "null") is False


def test_bool_case_insensitive_excluded() -> None:
    """Boolean check is case-insensitive."""
    assert cookie_feeds_identity(_DUMMY_NAME, "TRUE") is False
    assert cookie_feeds_identity(_DUMMY_NAME, "False") is False
    assert cookie_feeds_identity(_DUMMY_NAME, "NULL") is False


# ---------------------------------------------------------------------------
# Cue-level integration tests (no graph, no Docker)
# ---------------------------------------------------------------------------


_SESSION_VALUE = "4a8f2c1e7b3d9f05a2c6e8b4d1f3a7c9"  # all-hex, len=32


def test_cue_hashes_only_session_cookie() -> None:
    """Session cookie + UI-state cookies → only session cookie in hash tuple."""
    cue = extract_auth_context_cue(
        _request(
            [
                ("token", _SESSION_VALUE),          # session → included
                ("ap_page", "3"),                   # integer → excluded
                ("sidenavExpanded", "true"),         # boolean → excluded
                ("ap_offset", "0"),                 # integer → excluded
            ]
        )
    )
    assert cue.is_anonymous is False
    # Only the session cookie value contributes.
    assert cue.cookie_session_hashes == (
        compute_auth_hash("cookie", _SESSION_VALUE),
    )


def test_same_session_different_ui_state_yields_same_cue_hash() -> None:
    """Different UI-state cookies must not change the AuthContext identity.

    UI-state cookies here use integer and boolean values, which the classifier
    confidently excludes; only the session cookie value feeds the hash.
    """
    cue_a = extract_auth_context_cue(
        _request(
            [
                ("token", _SESSION_VALUE),
                ("ap_page", "1"),           # integer → excluded
                ("ap_offset", "0"),         # integer → excluded
            ]
        )
    )
    cue_b = extract_auth_context_cue(
        _request(
            [
                ("token", _SESSION_VALUE),
                ("ap_page", "99"),          # integer → excluded
                ("ap_offset", "200"),       # integer → excluded
            ]
        )
    )
    # Both cues have the same session hash, regardless of UI state.
    assert cue_a.cookie_session_hashes == cue_b.cookie_session_hashes


def test_only_app_state_cookies_yields_anonymous() -> None:
    """A request bearing only app-state cookies (no real credential) → anonymous."""
    cue = extract_auth_context_cue(
        _request(
            [
                ("ap_page", "2"),           # integer
                ("sidenavExpanded", "false"),  # boolean
                ("view", "list"),           # short (4 chars)
            ]
        )
    )
    assert cue.is_anonymous is True
    assert cue.cookie_session_hashes == ()


def test_ui_state_filtering_does_not_affect_bearer_detection() -> None:
    """Bearer token path is unaffected by cookie filtering."""
    token = pyjwt.encode(
        {"sub": "alice"},
        "another-secret-key-at-least-32-chars!!",
        algorithm="HS256",
    )
    cue = extract_auth_context_cue(
        {
            "method": "GET",
            "url": "https://api.example.com/me",
            "headers": [{"name": "Authorization", "value": f"Bearer {token}"}],
            "cookies": [{"name": "ap_page", "value": "1"}],  # excluded app-state
        }
    )
    assert cue.is_anonymous is False
    assert cue.bearer_token_hash is not None
    assert cue.cookie_session_hashes == ()


# ---------------------------------------------------------------------------
# Authoritative allowlist (ADR-0026 #28)
# ---------------------------------------------------------------------------


def test_allowlist_authoritative_includes_only_listed_names() -> None:
    allow = frozenset({"token"})
    # Listed name → included regardless of value shape.
    assert cookie_feeds_identity("token", "0", allowlist=allow) is True
    # Unlisted name → excluded even when the value is opaque/credential-shaped.
    assert cookie_feeds_identity("sess", _SESSION_VALUE, allowlist=allow) is False


def test_empty_allowlist_falls_back_to_heuristic() -> None:
    # Empty/None allowlist → heuristic (no regression vs #26).
    assert cookie_feeds_identity("anything", _SESSION_VALUE, allowlist=frozenset()) is True
    assert cookie_feeds_identity("ap_page", "0", allowlist=frozenset()) is False


def test_cue_allowlist_overrides_heuristic() -> None:
    """With an allowlist, ONLY listed cookies feed identity — an opaque cookie not
    on the list is excluded, and a listed cookie is kept even if short."""
    req = _request(
        [
            ("token", "42"),                 # listed, would be excluded by heuristic (int)
            ("other_opaque", _SESSION_VALUE),  # opaque but NOT listed → excluded
            ("ap_page", "3"),
        ]
    )
    cue = extract_auth_context_cue(req, session_cookie_names=("token",))
    assert cue.is_anonymous is False
    assert cue.cookie_session_hashes == (compute_auth_hash("cookie", "42"),)


def test_cue_no_allowlist_matches_heuristic() -> None:
    """No allowlist passed → identical to the #26 heuristic path."""
    req = _request([("token", _SESSION_VALUE), ("ap_page", "1")])
    assert (
        extract_auth_context_cue(req).cookie_session_hashes
        == extract_auth_context_cue(req, session_cookie_names=()).cookie_session_hashes
        == (compute_auth_hash("cookie", _SESSION_VALUE),)
    )


def test_cue_allowlist_none_present_yields_anonymous() -> None:
    """A request with none of the allowlisted cookies (and no other cred) → anonymous."""
    cue = extract_auth_context_cue(
        _request([("ap_page", "2"), ("other", _SESSION_VALUE)]),
        session_cookie_names=("token",),
    )
    assert cue.is_anonymous is True
    assert cue.cookie_session_hashes == ()


def test_two_session_cookies_both_hashed() -> None:
    """Two session-credential cookies → two hashes (sorted by name)."""
    val_a = "aaaaaaaaaaaaaaaa"  # len=16, not int, not bool
    val_b = "bbbbbbbbbbbbbbbb"
    cue = extract_auth_context_cue(
        _request(
            [
                ("zsess", val_a),
                ("asess", val_b),
                ("flag", "true"),   # excluded
            ]
        )
    )
    # Sorted by cookie name: asess < zsess
    assert cue.cookie_session_hashes == (
        compute_auth_hash("cookie", val_b),
        compute_auth_hash("cookie", val_a),
    )


# ---------------------------------------------------------------------------
# normalize_cookie_value / canonical_credential_value (#103)
# ---------------------------------------------------------------------------


def test_normalize_cookie_value_strips_dquote_and_percent_decode() -> None:
    """`%22…%22` → bare value; one matching DQUOTE pair stripped after decode."""
    assert normalize_cookie_value("%22eyJxxx%22") == "eyJxxx"
    assert normalize_cookie_value('"eyJxxx"') == "eyJxxx"
    # An unbalanced quote is credential material, not a wrapper.
    assert normalize_cookie_value('"eyJxxx') == '"eyJxxx'
    # No wrapper → unchanged (after percent-decode).
    assert normalize_cookie_value("plain%2Fvalue") == "plain/value"


def test_canonical_credential_value_only_normalises_cookie_kind() -> None:
    """Bearer/api_key/basic_auth have no DQUOTE convention; `"` is material there."""
    assert canonical_credential_value("cookie", '"eyJxxx"') == "eyJxxx"
    for kind in ("bearer", "api_key", "basic_auth", "anonymous"):
        assert canonical_credential_value(kind, '"eyJxxx"') == '"eyJxxx"'


def test_l2_cue_hashes_quoted_cookie_jwt_on_bare_form() -> None:
    """L2 ingestion's per-cookie hash is over the *normalised* value (#103).

    A `%22<jwt>%22` cookie hashes as the bare `<jwt>` — the form the declared
    side now also produces, so both converge to one `AuthContext`.
    """
    bare = pyjwt.encode({"_id": "u-42"}, "k" * 32, algorithm="HS256")
    cue = extract_auth_context_cue(_request([("token", f"%22{bare}%22")]))
    assert cue.cookie_session_hashes == (compute_auth_hash("cookie", bare),)
    assert cue.identity_claims.get("_id") == "u-42"
