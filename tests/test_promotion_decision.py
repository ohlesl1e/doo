"""Unit tests for the pure promotion decision (ADR-0023).

Pure, no containers. The truth table: allowlisted kinds promote on shape alone
(even at a single occurrence); a non-allowlisted value promotes once it is seen in
≥2 *distinct* observations (multiplicity, #15); a single-occurrence non-allowlisted
value does not promote (the 277k collapse). Leak-to-input is still out of scope.
"""

from __future__ import annotations

import pytest

from doo.canonical.promotion import (
    MULTIPLICITY_THRESHOLD,
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
def test_high_cardinality_kinds_do_not_promote_at_single_occurrence(
    kind: CandidateKind,
) -> None:
    assert not kind_is_allowlisted(kind)
    assert not should_promote([kind])
    assert not should_promote([kind], distinct_observations=1)


def test_hundred_distinct_identifiers_none_promote() -> None:
    # Each list-item UUID is its own value_hash -> a single-element non-allowlisted
    # `kinds` at one observation -> no promotion (this is exactly the 277k collapse).
    for _ in range(100):
        assert not should_promote(["identifier"], distinct_observations=1)


def test_empty_occurrences_do_not_promote() -> None:
    assert not should_promote([])
    assert not should_promote([], distinct_observations=1)


def test_mixed_occurrences_promote_if_any_allowlisted() -> None:
    # If any occurrence's kind is allowlisted, the value promotes.
    assert should_promote(["identifier", "internal_hostname"])
    assert should_promote(["url", "secret"])
    assert not should_promote(["identifier", "url", "ip_address"])


# --- Multiplicity branch (#15) -------------------------------------------------


@pytest.mark.parametrize("kind", ["identifier", "url", "ip_address"])
def test_non_allowlisted_value_in_two_observations_promotes(
    kind: CandidateKind,
) -> None:
    # The multiplicity signal: a non-allowlisted value seen across 2 distinct
    # observations promotes, even though it would not promote on shape.
    assert not kind_is_allowlisted(kind)
    assert should_promote([kind, kind], distinct_observations=2)


@pytest.mark.parametrize("kind", ["identifier", "url", "ip_address"])
def test_non_allowlisted_value_twice_in_one_observation_does_not_promote(
    kind: CandidateKind,
) -> None:
    # Two occurrences but only ONE distinct observation -> multiplicity 1 -> no
    # promotion. The count is over distinct observations, not raw occurrences.
    assert should_promote([kind, kind], distinct_observations=1) is False


def test_multiplicity_threshold_is_two() -> None:
    assert MULTIPLICITY_THRESHOLD == 2
    assert not should_promote(["identifier"], distinct_observations=1)
    assert should_promote(["identifier"], distinct_observations=2)
    assert should_promote(["identifier"], distinct_observations=5)


def test_multiplicity_truth_table() -> None:
    # single non-allowlisted -> no
    assert not should_promote(["identifier"], distinct_observations=1)
    # same value in 2 observations -> yes
    assert should_promote(["identifier", "identifier"], distinct_observations=2)
    # same value twice in one observation -> no (distinct-observation count is 1)
    assert not should_promote(["identifier", "identifier"], distinct_observations=1)


def test_allowlist_is_exactly_the_four_shape_kinds() -> None:
    assert SHAPE_ALLOWLIST == frozenset(
        {"secret", "token", "internal_hostname", "email"}
    )


def test_every_candidate_kind_has_a_defined_decision() -> None:
    # Exhaustive over the closed vocabulary: each kind is either allowlisted or not.
    for kind in CANDIDATE_KINDS:
        assert kind_is_allowlisted(kind) == (kind in SHAPE_ALLOWLIST)
        assert should_promote([kind]) == (kind in SHAPE_ALLOWLIST)
