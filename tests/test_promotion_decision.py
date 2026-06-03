"""Unit tests for the pure promotion decision (ADR-0023 shape-allowlist branch).

Pure, no containers. The truth table: allowlisted kinds promote on shape alone
(even at a single occurrence); high-cardinality identifiers / URLs / IPs do not
promote in #14 (the 277k collapse). Multiplicity / leak-to-input are out of scope.
"""

from __future__ import annotations

import pytest

from doo.canonical.promotion import (
    SHAPE_ALLOWLIST,
    kind_is_allowlisted,
    should_promote,
)
from doo.canonical.values import CANDIDATE_KINDS, CandidateKind


@pytest.mark.parametrize(
    "kind",
    ["secret", "token", "internal_hostname", "email"],
)
def test_allowlisted_kinds_promote_on_single_occurrence(kind: CandidateKind) -> None:
    assert kind_is_allowlisted(kind)
    assert should_promote([kind])


@pytest.mark.parametrize("kind", ["identifier", "url", "ip_address"])
def test_high_cardinality_kinds_do_not_promote(kind: CandidateKind) -> None:
    assert not kind_is_allowlisted(kind)
    assert not should_promote([kind])


def test_hundred_distinct_identifiers_none_promote() -> None:
    # Each list-item UUID is its own value_hash -> a single-element non-allowlisted
    # `kinds` -> no promotion (this is exactly the 277k collapse).
    for _ in range(100):
        assert not should_promote(["identifier"])


def test_empty_occurrences_do_not_promote() -> None:
    assert not should_promote([])


def test_mixed_occurrences_promote_if_any_allowlisted() -> None:
    # If any occurrence's kind is allowlisted, the value promotes.
    assert should_promote(["identifier", "internal_hostname"])
    assert should_promote(["url", "secret"])
    assert not should_promote(["identifier", "url", "ip_address"])


def test_allowlist_is_exactly_the_four_shape_kinds() -> None:
    assert SHAPE_ALLOWLIST == frozenset(
        {"secret", "token", "internal_hostname", "email"}
    )


def test_every_candidate_kind_has_a_defined_decision() -> None:
    # Exhaustive over the closed vocabulary: each kind is either allowlisted or not.
    for kind in CANDIDATE_KINDS:
        assert kind_is_allowlisted(kind) == (kind in SHAPE_ALLOWLIST)
        assert should_promote([kind]) == (kind in SHAPE_ALLOWLIST)
