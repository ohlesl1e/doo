"""Unit tests for the canonicalisation / identity helpers (T2 deep module A)."""

from __future__ import annotations

import pytest

from doo.canonical.identity import (
    canonicalize_host,
    canonicalize_path,
    compute_anonymous_auth_hash,
    compute_auth_hash,
    derive_har_source_id,
    discovered_principal_identity_key,
    endpoint_id,
    host_id,
)
from doo.ids import EngagementId, Sha256Hex

ENG = EngagementId("eng-1")


def test_canonicalize_host_strips_default_https_port() -> None:
    h = canonicalize_host("https", "Shop.Example.com", 443)
    assert h.scheme == "https"
    assert h.canonical_hostname == "shop.example.com"
    assert h.port is None
    assert h.is_ip_literal is False


def test_canonicalize_host_keeps_non_default_port() -> None:
    h = canonicalize_host("https", "example.com", 8443)
    assert h.port == 8443


def test_canonicalize_host_strips_default_http_port_and_trailing_dot() -> None:
    h = canonicalize_host("http", "Example.COM.", 80)
    assert h.canonical_hostname == "example.com"
    assert h.port is None


def test_canonicalize_host_idn_to_ascii() -> None:
    h = canonicalize_host("https", "münchen.de", None)
    assert h.canonical_hostname == "xn--mnchen-3ya.de"


def test_canonicalize_host_ip_literal_is_flagged_and_distinct() -> None:
    h = canonicalize_host("http", "10.0.0.1", None)
    assert h.is_ip_literal is True
    assert h.canonical_hostname == "10.0.0.1"


def test_canonicalize_host_rejects_unknown_scheme() -> None:
    with pytest.raises(ValueError):
        canonicalize_host("ftp", "example.com", None)


def test_canonicalize_path_strips_trailing_slash_but_keeps_root() -> None:
    assert canonicalize_path("/products/") == "/products"
    assert canonicalize_path("/") == "/"


def test_canonicalize_path_preserves_case() -> None:
    # Backends may be case-sensitive; case is NOT folded.
    assert canonicalize_path("/Products/Detail") == "/Products/Detail"


def test_canonicalize_path_normalises_percent_encoding() -> None:
    # %2F-decoded segments and over-encoded reserved chars collapse to one form.
    assert canonicalize_path("/a%2Db") == canonicalize_path("/a-b")


def test_canonicalize_path_forces_absolute() -> None:
    assert canonicalize_path("products").startswith("/")


def test_products_and_products_slash_collapse_to_same_endpoint() -> None:
    p1 = canonicalize_path("/products")
    p2 = canonicalize_path("/products/")
    assert p1 == p2
    h = host_id(ENG, canonicalize_host("https", "shop.example.com", None))
    assert endpoint_id(ENG, "GET", h, p1) == endpoint_id(ENG, "GET", h, p2)


def test_auth_hash_is_stable_sha256_hex() -> None:
    a = compute_auth_hash("bearer", "tokenvalue")
    b = compute_auth_hash("bearer", "tokenvalue")
    assert a == b
    assert len(a) == 64


def test_anonymous_auth_hash_is_constant() -> None:
    assert compute_anonymous_auth_hash() == compute_anonymous_auth_hash()


def test_host_id_is_engagement_scoped() -> None:
    host = canonicalize_host("https", "shop.example.com", None)
    assert host_id(EngagementId("a"), host) != host_id(EngagementId("b"), host)


def test_derive_har_source_id_shape() -> None:
    assert derive_har_source_id(3, "2026-05-01T10:00:00.000Z") == "3|2026-05-01T10:00:00.000Z"


# --- discovered Principal identity key (ADR-0027 claim-priority) -------------

_AUTH_HASH = Sha256Hex("a" * 64)


def test_discovered_principal_key_falls_back_to_auth_hash_without_claims() -> None:
    # No claims (opaque / non-JWT credential) → per-credential key, unchanged.
    assert discovered_principal_identity_key(_AUTH_HASH) == f"discovered:{_AUTH_HASH}"
    assert (
        discovered_principal_identity_key(_AUTH_HASH, identity_claims={})
        == f"discovered:{_AUTH_HASH}"
    )
    # Claims present but none in the priority list → still synthetic.
    assert (
        discovered_principal_identity_key(_AUTH_HASH, identity_claims={"iat": 1, "scope": "x"})
        == f"discovered:{_AUTH_HASH}"
    )


def test_discovered_principal_key_namespaces_first_priority_claim() -> None:
    assert (
        discovered_principal_identity_key(_AUTH_HASH, identity_claims={"sub": "uuid-aaa"})
        == "discovered:jwt:sub:uuid-aaa"
    )


def test_discovered_principal_key_falls_through_priority_to_uid() -> None:
    # `sub` absent → next present claim (`uid`) keys it, namespaced by claim.
    assert (
        discovered_principal_identity_key(
            _AUTH_HASH, identity_claims={"uid": "u-7", "email": "a@x.com"}
        )
        == "discovered:jwt:uid:u-7"
    )


def test_discovered_principal_key_prefers_sub_over_lower_claims() -> None:
    # All present → highest-priority (`sub`) wins deterministically.
    assert (
        discovered_principal_identity_key(
            _AUTH_HASH, identity_claims={"email": "a@x.com", "uid": "u-7", "sub": "s-1"}
        )
        == "discovered:jwt:sub:s-1"
    )


def test_discovered_principal_key_lowercases_email_only() -> None:
    assert (
        discovered_principal_identity_key(_AUTH_HASH, identity_claims={"email": "Alice@X.COM"})
        == "discovered:jwt:email:alice@x.com"
    )
    # A non-email claim keeps its case.
    assert (
        discovered_principal_identity_key(_AUTH_HASH, identity_claims={"username": "Alice"})
        == "discovered:jwt:username:Alice"
    )


def test_discovered_principal_key_converges_across_reissued_tokens() -> None:
    # Same user (same top claim), two reissued tokens → two auth_hashes, one key.
    key1 = discovered_principal_identity_key(Sha256Hex("b" * 64), identity_claims={"sub": "uuid-aaa"})
    key2 = discovered_principal_identity_key(Sha256Hex("c" * 64), identity_claims={"sub": "uuid-aaa"})
    assert key1 == key2 == "discovered:jwt:sub:uuid-aaa"


def test_discovered_principal_key_fragments_honestly_on_differing_claims() -> None:
    # Same user but tokens expose different claims → different (honest) keys, never
    # a wrong merge.
    k_sub = discovered_principal_identity_key(_AUTH_HASH, identity_claims={"sub": "x"})
    k_uid = discovered_principal_identity_key(_AUTH_HASH, identity_claims={"uid": "x"})
    assert k_sub != k_uid


def test_discovered_principal_key_ignores_bool_claim() -> None:
    # bool is an int subclass but is never an identifier.
    assert (
        discovered_principal_identity_key(_AUTH_HASH, identity_claims={"sub": True, "uid": "u-9"})
        == "discovered:jwt:uid:u-9"
    )
