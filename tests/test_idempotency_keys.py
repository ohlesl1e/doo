"""Unit tests for the two idempotency keys (L1 blob-level, L3 semantic-key)."""

from __future__ import annotations

import hashlib

from doo.ids import EngagementId, Sha256Hex
from doo.ingestion.intake import compute_idempotency_key
from doo.ontology.commit import semantic_key

ENG = EngagementId("eng-1")
SHA = Sha256Hex("a" * 64)


def test_l1_idempotency_key_matches_adr_0016_formula() -> None:
    key = compute_idempotency_key("har", SHA, ENG)
    expected = hashlib.sha256(f"har|{SHA}|{ENG}".encode()).hexdigest()
    assert key == expected
    assert len(key) == 64


def test_l1_idempotency_key_collapses_same_blob_in_same_engagement() -> None:
    assert compute_idempotency_key("har", SHA, ENG) == compute_idempotency_key("har", SHA, ENG)


def test_l1_idempotency_key_differs_across_engagements() -> None:
    a = compute_idempotency_key("har", SHA, EngagementId("a"))
    b = compute_idempotency_key("har", SHA, EngagementId("b"))
    assert a != b  # same blob, different engagement -> distinct observation set


def test_l3_semantic_key_shape() -> None:
    key = semantic_key(ENG, "request_observation", "har", "0|2026-05-01T10:00:00.000Z")
    assert key == "commit:eng-1:request_observation:har:0|2026-05-01T10:00:00.000Z"


def test_l3_semantic_key_differs_by_kind_source_and_source_id() -> None:
    base = semantic_key(ENG, "request_observation", "har", "0|t")
    assert base != semantic_key(ENG, "parse_failure", "har", "0|t")
    assert base != semantic_key(ENG, "request_observation", "burp-streamed", "0|t")
    assert base != semantic_key(ENG, "request_observation", "har", "1|t")
