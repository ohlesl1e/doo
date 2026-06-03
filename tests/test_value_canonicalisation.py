"""Unit tests for value canonicalisation (ADR-0023 / ADR-0009 ObservedValue identity).

Pure, no containers. Covers: normalization equivalence (two spellings of one value
collapse), hash stability, the closed kind vocabulary, and the secret discipline
(secrets are never normalised into a recoverable form; their hash is over the raw
bytes).
"""

from __future__ import annotations

import hashlib

import pytest

from doo.canonical.values import (
    CANDIDATE_KINDS,
    hash_for,
    is_secret_kind,
    normalize_value,
    secret_value_hash,
    value_hash,
)


def test_hash_is_sha256_over_normalized_form() -> None:
    norm = normalize_value("internal_hostname", "Internal-Billing.CORP.example")
    assert norm == "internal-billing.corp.example"
    assert value_hash(norm) == hashlib.sha256(norm.encode()).hexdigest()


def test_hostname_case_and_trailing_dot_collapse() -> None:
    a = hash_for("internal_hostname", "Internal-Billing.Corp.Example.")
    b = hash_for("internal_hostname", "internal-billing.corp.example")
    assert a == b  # case + trailing dot do not split the value


def test_email_domain_lowercased_local_part_preserved() -> None:
    # Domain is case-insensitive; local part is preserved verbatim.
    assert normalize_value("email", "Alice.P@Example.COM") == "Alice.P@example.com"
    a = hash_for("email", "Alice.P@EXAMPLE.com")
    b = hash_for("email", "Alice.P@example.com")
    assert a == b


def test_url_and_identifier_preserve_case() -> None:
    # URLs / identifiers are retained verbatim (case can be load-bearing).
    assert normalize_value("url", "https://Admin.Internal.example/X") == (
        "https://Admin.Internal.example/X"
    )
    assert normalize_value("identifier", "AbC123") == "AbC123"


def test_whitespace_stripped_for_all_nonsecret_kinds() -> None:
    assert normalize_value("identifier", "  42  ") == "42"
    assert normalize_value("email", "  a@b.com ") == "a@b.com"


def test_hash_is_stable_across_calls() -> None:
    h1 = hash_for("internal_hostname", "host.corp.example")
    h2 = hash_for("internal_hostname", "host.corp.example")
    assert h1 == h2 and len(h1) == 64


def test_secret_kinds_flagged() -> None:
    assert is_secret_kind("secret")
    assert is_secret_kind("token")
    # opaque_token is secret-for-storage (ADR-0024): hash-only, raw never carried.
    assert is_secret_kind("opaque_token")
    assert not is_secret_kind("email")
    assert not is_secret_kind("internal_hostname")
    assert not is_secret_kind("identifier")


def test_normalize_value_refuses_secret_kinds() -> None:
    # A secret must never be normalised into a recoverable form (ADR-0015).
    with pytest.raises(ValueError, match="secret"):
        normalize_value("secret", "AKIAIOSFODNN7EXAMPLE")
    with pytest.raises(ValueError, match="secret"):
        normalize_value("token", "eyJ.a.b")
    # opaque_token is hash-only too: normalising it would recover the raw value.
    with pytest.raises(ValueError, match="secret"):
        normalize_value("opaque_token", "Ab3Cd9Ef2Gh5Ij8Kl1Mn4Op7Qr0St6Uv")


def test_secret_value_hash_is_over_raw_bytes() -> None:
    raw = "AKIAIOSFODNN7EXAMPLE"
    assert secret_value_hash(raw) == hashlib.sha256(raw.encode()).hexdigest()
    assert hash_for("secret", raw) == secret_value_hash(raw)


def test_same_secret_dedups_across_kind_tags() -> None:
    # The same raw secret hashes identically whether tagged secret or token, so a
    # value seen as both still dedups to one ObservedValue.
    raw = "eyJabc.def.ghi"
    assert hash_for("secret", raw) == hash_for("token", raw)


def test_candidate_kinds_vocabulary_closed() -> None:
    assert set(CANDIDATE_KINDS) == {
        "internal_hostname",
        "email",
        "ip_address",
        "url",
        "identifier",
        "secret",
        "token",
        "opaque_token",
    }
