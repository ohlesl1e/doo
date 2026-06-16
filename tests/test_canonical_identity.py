"""Unit tests for the canonicalisation / identity helpers (T2 deep module A)."""

from __future__ import annotations

import pytest

from doo.canonical.identity import (
    DISAGREE,
    _strip_source_prefix,
    canonicalize_host,
    canonicalize_path,
    compute_anonymous_auth_hash,
    compute_auth_hash,
    derive_har_source_id,
    discovered_principal_identity_key,
    endpoint_id,
    host_id,
    is_synthetic_discovered_key,
    match_identity_claims,
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


# --- discovered Principal identity key (ADR-0030 unified claim-keyed model) ---

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
        == "discovered:sub:uuid-aaa"
    )


def test_discovered_principal_key_issuer_scopes_sub() -> None:
    # OIDC sub is unique only within its issuer.
    assert (
        discovered_principal_identity_key(
            _AUTH_HASH, identity_claims={"sub": "12345", "iss": "https://idp.example"}
        )
        == "discovered:sub:https://idp.example:12345"
    )


def test_discovered_principal_key_same_sub_different_iss_do_not_merge() -> None:
    # Two IdPs minting the same sub for different people → distinct keys.
    a = discovered_principal_identity_key(_AUTH_HASH, identity_claims={"sub": "1", "iss": "idp-a"})
    b = discovered_principal_identity_key(_AUTH_HASH, identity_claims={"sub": "1", "iss": "idp-b"})
    assert a != b


def test_discovered_principal_key_bare_sub_without_iss_unchanged() -> None:
    # No iss → bare sub key (backward-compatible with single-issuer tokens).
    assert (
        discovered_principal_identity_key(_AUTH_HASH, identity_claims={"sub": "uuid-aaa"})
        == "discovered:sub:uuid-aaa"
    )


def test_discovered_principal_key_falls_through_priority_to_uid() -> None:
    # `sub` absent → next present claim (`uid`) keys it, namespaced by claim.
    assert (
        discovered_principal_identity_key(
            _AUTH_HASH, identity_claims={"uid": "u-7", "email": "a@x.com"}
        )
        == "discovered:uid:u-7"
    )


def test_discovered_principal_key_prefers_sub_over_lower_claims() -> None:
    # All present → highest-priority (`sub`) wins deterministically.
    assert (
        discovered_principal_identity_key(
            _AUTH_HASH, identity_claims={"email": "a@x.com", "uid": "u-7", "sub": "s-1"}
        )
        == "discovered:sub:s-1"
    )


def test_discovered_principal_key_lowercases_email_only() -> None:
    assert (
        discovered_principal_identity_key(_AUTH_HASH, identity_claims={"email": "Alice@X.COM"})
        == "discovered:email:alice@x.com"
    )
    # A non-email claim keeps its case.
    assert (
        discovered_principal_identity_key(_AUTH_HASH, identity_claims={"username": "Alice"})
        == "discovered:username:Alice"
    )


def test_discovered_principal_key_converges_across_reissued_tokens() -> None:
    # Same user (same top claim), two reissued tokens → two auth_hashes, one key.
    key1 = discovered_principal_identity_key(Sha256Hex("b" * 64), identity_claims={"sub": "uuid-aaa"})
    key2 = discovered_principal_identity_key(Sha256Hex("c" * 64), identity_claims={"sub": "uuid-aaa"})
    assert key1 == key2 == "discovered:sub:uuid-aaa"


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
        == "discovered:uid:u-9"
    )


def test_discovered_principal_key_email_is_last_resort() -> None:
    # ADR-0030: `email` is person-level → keys ONLY when no account-unique claim is
    # present, but is never beaten by anything lower (it is the last in the list).
    assert (
        discovered_principal_identity_key(_AUTH_HASH, identity_claims={"email": "alice@x.com"})
        == "discovered:email:alice@x.com"
    )
    # Any account-unique claim outranks email.
    for stronger in ("sub", "uid", "user_id", "uuid", "_id", "username", "preferred_username"):
        assert discovered_principal_identity_key(
            _AUTH_HASH, identity_claims={stronger: "v", "email": "alice@x.com"}
        ) == f"discovered:{stronger}:v"


def test_discovered_principal_key_unified_scheme_drops_jwt_observed_namespaces() -> None:
    # ADR-0030: the key is source-agnostic — no `jwt`/`observed` namespace segment.
    key = discovered_principal_identity_key(_AUTH_HASH, identity_claims={"sub": "s-1"})
    assert key == "discovered:sub:s-1"
    assert ":jwt:" not in key and ":observed:" not in key


def test_cue_and_observed_paths_converge_on_one_key() -> None:
    # ADR-0030 M3: a bearer JWT `sub` (resolve path) and the same actor's /me `sub`
    # (observed path) produce the SAME discovered key, so they MERGE to one Principal.
    cue_key = discovered_principal_identity_key(
        Sha256Hex("d" * 64), identity_claims={"sub": "actor-1"}
    )
    observed_key = discovered_principal_identity_key(
        Sha256Hex("e" * 64), identity_claims={"sub": "actor-1"}
    )
    assert cue_key == observed_key == "discovered:sub:actor-1"


def test_is_synthetic_discovered_key() -> None:
    # The per-credential fallback is synthetic (safe to re-key); claim keys are not.
    assert is_synthetic_discovered_key(f"discovered:{_AUTH_HASH}")
    assert not is_synthetic_discovered_key("discovered:sub:actor-1")
    assert not is_synthetic_discovered_key("discovered:sub:https://idp:1")
    assert not is_synthetic_discovered_key("discovered:email:alice@x.com")
    assert not is_synthetic_discovered_key("discovered:x-user-id:alice")
    assert not is_synthetic_discovered_key("declared:test-user")
    assert not is_synthetic_discovered_key("anonymous")


# --- ADR-0032: preferred_claim override ---


def test_preferred_claim_overrides_priority_when_present() -> None:
    """When preferred_claim is set and the claim is present, it wins over priority."""
    # `sub` would normally rank first, but tester declared `_id` as the key.
    key = discovered_principal_identity_key(
        _AUTH_HASH,
        identity_claims={"sub": "s-1", "_id": "mongo-id-42"},
        preferred_claim="_id",
    )
    assert key == "discovered:_id:mongo-id-42"


def test_preferred_claim_falls_back_to_heuristic_when_absent() -> None:
    """When the preferred_claim is not in the claim set, fall back to heuristic."""
    key = discovered_principal_identity_key(
        _AUTH_HASH,
        identity_claims={"sub": "s-1", "uid": "u-7"},
        preferred_claim="username",  # not present
    )
    # Heuristic: sub beats uid
    assert key == "discovered:sub:s-1"


def test_preferred_claim_falls_back_to_synthetic_when_no_claims() -> None:
    """Preferred claim absent and no other claims → synthetic fallback."""
    key = discovered_principal_identity_key(
        _AUTH_HASH,
        identity_claims={},
        preferred_claim="_id",
    )
    assert key == f"discovered:{_AUTH_HASH}"


def test_preferred_claim_strips_source_qualifier_prefix() -> None:
    """Source-qualifier prefixes (claim:, header:, body:) are stripped."""
    claims = {"_id": "mongo-42", "sub": "s-1"}
    assert (
        discovered_principal_identity_key(_AUTH_HASH, identity_claims=claims, preferred_claim="claim:_id")
        == "discovered:_id:mongo-42"
    )
    assert (
        discovered_principal_identity_key(_AUTH_HASH, identity_claims=claims, preferred_claim="header:_id")
        == "discovered:_id:mongo-42"
    )
    assert (
        discovered_principal_identity_key(_AUTH_HASH, identity_claims=claims, preferred_claim="body:_id")
        == "discovered:_id:mongo-42"
    )


def test_preferred_claim_sub_still_iss_scoped() -> None:
    """preferred_claim='sub' still applies issuer scoping (same rules as heuristic)."""
    key = discovered_principal_identity_key(
        _AUTH_HASH,
        identity_claims={"sub": "u-1", "iss": "https://idp.example", "_id": "mongo-99"},
        preferred_claim="sub",
    )
    assert key == "discovered:sub:https://idp.example:u-1"


def test_preferred_claim_email_lowercased() -> None:
    """preferred_claim='email' still lowercases the value."""
    key = discovered_principal_identity_key(
        _AUTH_HASH,
        identity_claims={"email": "Alice@Example.COM", "sub": "s-1"},
        preferred_claim="email",
    )
    assert key == "discovered:email:alice@example.com"


def test_preferred_claim_none_behaves_as_before() -> None:
    """No preferred_claim → identical to calling without the argument."""
    claims = {"sub": "s-1", "_id": "m-42"}
    assert discovered_principal_identity_key(
        _AUTH_HASH, identity_claims=claims
    ) == discovered_principal_identity_key(
        _AUTH_HASH, identity_claims=claims, preferred_claim=None
    )


def test_strip_source_prefix_removes_known_prefixes() -> None:
    """_strip_source_prefix strips claim:, header:, body: and leaves bare names."""
    assert _strip_source_prefix("claim:_id") == "_id"
    assert _strip_source_prefix("header:x-user-id") == "x-user-id"
    assert _strip_source_prefix("body:accountRef") == "accountRef"
    assert _strip_source_prefix("_id") == "_id"
    assert _strip_source_prefix("sub") == "sub"


# ---------------------------------------------------------------------------
# match_identity_claims (ADR-0048 priority-0 walk-and-intersect)
# ---------------------------------------------------------------------------


def test_match_agrees_on_first_shared_claim() -> None:
    """Both carry `_id` (no higher-priority claim shared) → match on `_id`."""
    a = {"_id": "u_42", "iat": 1}
    b = {"_id": "u_42", "exp": 99}
    assert match_identity_claims(a, b) == ("_id", "u_42")


def test_match_full_list_walk_no_identity_key() -> None:
    """No `sub`/`email`, both carry `uid` → matches via the full ADR-0030 list
    even with no `preferred_claim` set (the #104 gap)."""
    assert match_identity_claims({"uid": 42}, {"uid": "42"}) == ("uid", "42")


def test_match_disagree_stops_on_first_both_present_mismatch() -> None:
    """`sub` present on both and disagrees → DISAGREE even though `_id` agrees.
    Stop-on-first-disagreement: a weaker coincidental match must not override
    a stronger proven mismatch (merge-safety, ADR-0048)."""
    a = {"sub": "X", "_id": "u_42"}
    b = {"sub": "Y", "_id": "u_42"}
    assert match_identity_claims(a, b) == DISAGREE


def test_match_one_side_only_continues() -> None:
    """`sub` only on one side → continue past it to the next shared claim."""
    a = {"sub": "X", "_id": "u_42"}
    b = {"_id": "u_42"}
    assert match_identity_claims(a, b) == ("_id", "u_42")


def test_match_no_shared_claim_returns_none() -> None:
    assert match_identity_claims({"sub": "X"}, {"uid": "Y"}) is None
    assert match_identity_claims({}, {"sub": "X"}) is None
    assert match_identity_claims({"iat": 1}, {"exp": 2}) is None


def test_match_preferred_claim_overrides_priority() -> None:
    """`auth.identity_key` (ADR-0032) is walked first, source-prefix stripped."""
    a = {"sub": "X", "accountRef": "ar-1"}
    b = {"sub": "Y", "accountRef": "ar-1"}
    # Without preferred_claim, `sub` (highest priority) disagrees → DISAGREE.
    assert match_identity_claims(a, b) == DISAGREE
    # With preferred_claim, `accountRef` is checked first → match.
    assert match_identity_claims(a, b, preferred_claim="claim:accountRef") == (
        "accountRef", "ar-1",
    )


def test_match_email_compared_case_insensitive() -> None:
    assert match_identity_claims(
        {"email": "Alice@Example.COM"}, {"email": "alice@example.com"}
    ) == ("email", "alice@example.com")


def test_match_sub_issuer_scoped() -> None:
    """Same `sub`, different `iss` → DISAGREE (OIDC `sub` is per-issuer)."""
    a = {"sub": "u-1", "iss": "https://idp-a"}
    b = {"sub": "u-1", "iss": "https://idp-b"}
    assert match_identity_claims(a, b) == DISAGREE
    # Missing `iss` on one side → compatible (single-issuer engagement).
    assert match_identity_claims({"sub": "u-1"}, b) == ("sub", "u-1")


def test_match_ignores_non_scalar_and_bool_claims() -> None:
    """List/dict/bool claim values are not identity material."""
    assert match_identity_claims({"sub": ["x"]}, {"sub": ["x"]}) is None
    assert match_identity_claims({"sub": True}, {"sub": True}) is None
