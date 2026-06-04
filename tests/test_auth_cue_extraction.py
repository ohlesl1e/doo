"""HAR `AuthContextCue` extraction tests (T4: ADR-0015 L2 secrets boundary).

The parser hashes every credential at the L2 boundary; raw tokens never appear
on the emitted cue. Covers bearer (+JWT claim peek), cookie, api-key, basic
(username-only), and anonymous.
"""

from __future__ import annotations

import base64

import jwt

from doo.canonical.identity import compute_auth_hash
from doo.extraction.har import extract_auth_context_cue

BEARER_JWT = jwt.encode(
    {"sub": "uuid-aaa", "email": "a@example.com", "exp": 4102444800},
    "irrelevant-signing-key-at-least-32-bytes-long!",
    algorithm="HS256",
)


COOKIE_JWT = jwt.encode(
    {"sub": "uuid-cookie", "email": "c@example.com", "exp": 4102444800},
    "irrelevant-signing-key-at-least-32-bytes-long!",
    algorithm="HS256",
)


def _request(headers=None, cookies=None):
    return {
        "method": "GET",
        "url": "https://api.example.com/me",
        "headers": [{"name": n, "value": v} for n, v in (headers or [])],
        "cookies": [{"name": n, "value": v} for n, v in (cookies or [])],
    }


def test_jwt_session_cookie_populates_identity_claims() -> None:
    # No bearer header; the session cookie is a JWT → its claims become identity_claims (ADR-0027).
    cue = extract_auth_context_cue(_request(cookies=[("session", COOKIE_JWT)]))
    assert cue.is_anonymous is False
    assert cue.identity_claims["sub"] == "uuid-cookie"
    assert cue.identity_claims["email"] == "c@example.com"
    # Raw token bytes never on the cue.
    assert COOKIE_JWT not in repr(cue.model_dump())


def test_bearer_jwt_takes_precedence_over_cookie_jwt() -> None:
    cue = extract_auth_context_cue(
        _request(
            headers=[("Authorization", f"Bearer {BEARER_JWT}")],
            cookies=[("session", COOKIE_JWT)],
        )
    )
    # Bearer wins: claims come from the bearer JWT, not the cookie.
    assert cue.identity_claims["sub"] == "uuid-aaa"


def test_opaque_session_cookie_yields_no_identity_claims() -> None:
    # A non-JWT session cookie is hashed but yields no claims, and never crashes.
    cue = extract_auth_context_cue(_request(cookies=[("session", "opaque-session-value-1234")]))
    assert cue.is_anonymous is False
    assert cue.identity_claims == {}


def test_quoted_jwt_session_cookie_is_decoded() -> None:
    # RFC 6265 DQUOTE-wrapped credential cookie (e.g. `"eyJ…"`) — the wrapper must
    # be stripped so the JWT decodes (the real-capture `_id` case).
    cue = extract_auth_context_cue(_request(cookies=[("token", f'"{COOKIE_JWT}"')]))
    assert cue.identity_claims["sub"] == "uuid-cookie"


def test_percent_encoded_quoted_jwt_cookie_is_decoded() -> None:
    # The real-capture form: a percent-encoded, quote-wrapped JWT (`%22eyJ…%22`).
    # cookie-octet forbids a literal DQUOTE, so apps encode it; we must decode then
    # unwrap before the JWT parses.
    cue = extract_auth_context_cue(_request(cookies=[("token", f"%22{COOKIE_JWT}%22")]))
    assert cue.identity_claims["sub"] == "uuid-cookie"


def test_quoted_and_unquoted_cookie_hash_identically() -> None:
    # The DQUOTE wrapper is transport syntax, not credential material, so a quoted
    # and unquoted same value collapse to one AuthContext identity.
    quoted = extract_auth_context_cue(_request(cookies=[("session", '"abc123XYZ9012345"')]))
    bare = extract_auth_context_cue(_request(cookies=[("session", "abc123XYZ9012345")]))
    assert quoted.cookie_session_hashes == bare.cookie_session_hashes


def test_bearer_jwt_hash_and_unverified_claims() -> None:
    cue = extract_auth_context_cue(_request(headers=[("Authorization", f"Bearer {BEARER_JWT}")]))
    assert cue.is_anonymous is False
    assert cue.bearer_token_hash == compute_auth_hash("bearer", BEARER_JWT)
    assert cue.identity_claims["sub"] == "uuid-aaa"
    assert cue.identity_claims["email"] == "a@example.com"
    # Raw token bytes never on the cue.
    assert BEARER_JWT not in repr(cue.model_dump())


def test_opaque_bearer_token_has_empty_claims() -> None:
    cue = extract_auth_context_cue(_request(headers=[("Authorization", "Bearer opaque-abc123")]))
    assert cue.bearer_token_hash == compute_auth_hash("bearer", "opaque-abc123")
    assert cue.identity_claims == {}


def test_basic_auth_hashes_username_only_never_password() -> None:
    cred = base64.b64encode(b"alice:supersecret").decode()
    cue = extract_auth_context_cue(_request(headers=[("Authorization", f"Basic {cred}")]))
    assert cue.basic_auth_user_hash == compute_auth_hash("basic_auth", "alice")
    dump = repr(cue.model_dump())
    assert "supersecret" not in dump
    assert "alice" not in dump  # the username is hashed too


def test_cookie_per_name_hashes() -> None:
    cue = extract_auth_context_cue(
        _request(cookies=[("session", "sess-val-1"), ("csrf", "csrf-val-2")])
    )
    assert cue.is_anonymous is False
    # Two cookies -> two hashes; sorted by name (csrf, session).
    assert cue.cookie_session_hashes == (
        compute_auth_hash("cookie", "csrf-val-2"),
        compute_auth_hash("cookie", "sess-val-1"),
    )


def test_api_key_header_hash() -> None:
    cue = extract_auth_context_cue(_request(headers=[("X-API-Key", "key-abc")]))
    assert cue.api_key_headers == {"x-api-key": compute_auth_hash("api_key", "key-abc")}


def test_anonymous_when_no_auth_material() -> None:
    cue = extract_auth_context_cue(_request())
    assert cue.is_anonymous is True
    assert cue.bearer_token_hash is None
    assert cue.cookie_session_hashes == ()
