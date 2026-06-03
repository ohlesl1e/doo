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
    is_leak_to_input,
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


# --- Leak-to-input branch (#16) ------------------------------------------------


def test_is_leak_to_input_requires_both_roles() -> None:
    assert is_leak_to_input(["output", "input"])
    assert is_leak_to_input(["input", "output"])
    assert not is_leak_to_input(["output"])
    assert not is_leak_to_input(["input"])
    assert not is_leak_to_input(["output", "output"])
    assert not is_leak_to_input(["input", "input"])
    assert not is_leak_to_input([])


def test_leak_to_input_promotes_non_allowlisted_value() -> None:
    # A high-cardinality identifier (would NOT promote on shape, and only ONE
    # distinct observation each side) promotes once it is seen as both an output
    # and an input — the leak-to-input pivot (#16).
    assert not kind_is_allowlisted("identifier")
    assert should_promote(
        ["identifier", "identifier"],
        distinct_observations=2,
        roles=["output", "input"],
    )


def test_output_only_does_not_promote_without_other_signal() -> None:
    # Seen only as an output, single observation, non-allowlisted -> no promotion.
    assert not should_promote(
        ["identifier"], distinct_observations=1, roles=["output"]
    )


def test_input_only_does_not_promote_by_leak_to_input_alone() -> None:
    # Seen only as an input, single observation -> leak-to-input does NOT fire; no
    # other signal either -> no promotion (the issue's explicit case).
    assert not should_promote(
        ["identifier"], distinct_observations=1, roles=["input"]
    )


def test_input_only_still_promotes_on_multiplicity() -> None:
    # An input-only value seen across 2 distinct observations still promotes on
    # multiplicity (#15) even without an output occurrence.
    assert should_promote(
        ["identifier", "identifier"],
        distinct_observations=2,
        roles=["input", "input"],
    )


def test_leak_to_input_truth_table() -> None:
    # output + input -> promote
    assert should_promote(["identifier", "identifier"], roles=["output", "input"])
    # output-only -> not (no other signal)
    assert not should_promote(["identifier"], roles=["output"])
    # input-only -> not (no other signal)
    assert not should_promote(["identifier"], roles=["input"])
    # leak-to-input overrides the 277k collapse regardless of distinct_observations.
    assert should_promote(
        ["identifier", "identifier"], distinct_observations=1, roles=["output", "input"]
    )


def test_roles_default_empty_keeps_kinds_only_behaviour() -> None:
    # A caller that does not pass roles gets the pre-#16 behaviour: leak-to-input
    # simply cannot fire, so the shape-allowlist / multiplicity decision stands.
    assert not should_promote(["identifier"])
    assert should_promote(["internal_hostname"])


def test_allowlist_is_exactly_the_four_shape_kinds() -> None:
    assert SHAPE_ALLOWLIST == frozenset(
        {"secret", "token", "internal_hostname", "email"}
    )


def test_every_candidate_kind_has_a_defined_decision() -> None:
    # Exhaustive over the closed vocabulary: each kind is either allowlisted or not.
    for kind in CANDIDATE_KINDS:
        assert kind_is_allowlisted(kind) == (kind in SHAPE_ALLOWLIST)
        assert should_promote([kind]) == (kind in SHAPE_ALLOWLIST)
