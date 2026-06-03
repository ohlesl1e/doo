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
from doo.canonical.values import (
    CANDIDATE_KINDS,
    SECRET_CANDIDATE_KINDS,
    CandidateKind,
    is_secret_kind,
)


@pytest.mark.parametrize(
    "kind",
    ["secret", "internal_hostname", "email"],
)
def test_allowlisted_kinds_promote_on_single_occurrence(kind: CandidateKind) -> None:
    assert kind_is_allowlisted(kind)
    assert should_promote([kind])


@pytest.mark.parametrize("kind", ["identifier", "url", "ip_address", "opaque_token"])
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


@pytest.mark.parametrize("kind", ["identifier", "url", "ip_address", "opaque_token"])
def test_non_allowlisted_value_in_two_observations_promotes(
    kind: CandidateKind,
) -> None:
    # The multiplicity signal: a non-allowlisted value seen across 2 distinct
    # observations promotes, even though it would not promote on shape.
    assert not kind_is_allowlisted(kind)
    assert should_promote([kind, kind], distinct_observations=2)


@pytest.mark.parametrize("kind", ["identifier", "url", "ip_address", "opaque_token"])
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


def test_allowlist_is_exactly_the_three_shape_kinds() -> None:
    # ADR-0024 narrowed the allowlist: `token` and `opaque_token` are out, so a
    # generic high-entropy blob no longer promotes on shape alone.
    assert SHAPE_ALLOWLIST == frozenset({"secret", "internal_hostname", "email"})


def test_every_candidate_kind_has_a_defined_decision() -> None:
    # Exhaustive over the closed vocabulary: each kind is either allowlisted or not.
    for kind in CANDIDATE_KINDS:
        assert kind_is_allowlisted(kind) == (kind in SHAPE_ALLOWLIST)
        assert should_promote([kind]) == (kind in SHAPE_ALLOWLIST)


# --- ADR-0024: storage and promotion are independent predicates ----------------


def test_storage_and_promotion_sets_are_the_adr0024_split() -> None:
    # secret-for-storage (hash-only, ADR-0015) and always-promote (shape) are now
    # two distinct sets that overlap only on `secret`.
    assert SECRET_CANDIDATE_KINDS == frozenset({"secret", "token", "opaque_token"})
    assert SHAPE_ALLOWLIST == frozenset({"secret", "internal_hostname", "email"})
    # The only kind that is BOTH secret-for-storage and always-promoted is `secret`.
    assert SECRET_CANDIDATE_KINDS & SHAPE_ALLOWLIST == frozenset({"secret"})


def test_opaque_token_is_secret_for_storage_but_not_promoted_on_shape() -> None:
    # The decoupling, concretely: an opaque_token is hash-only for storage yet does
    # NOT promote on shape — only on a cross-context signal.
    assert is_secret_kind("opaque_token")
    assert not kind_is_allowlisted("opaque_token")
    assert not should_promote(["opaque_token"])  # single occurrence -> no node
    assert should_promote(["opaque_token", "opaque_token"], distinct_observations=2)
    assert should_promote(["opaque_token"], roles=["output", "input"])


def test_secret_is_both_secret_for_storage_and_always_promoted() -> None:
    # A structured secret (JWT / AWS / Stripe) promotes on shape alone, at one
    # occurrence, AND is hash-only for storage.
    assert is_secret_kind("secret")
    assert kind_is_allowlisted("secret")
    assert should_promote(["secret"])


def test_token_is_secret_for_storage_but_no_longer_promoted_on_shape() -> None:
    # `token` stays hash-only for storage but ADR-0024 removed it from the
    # always-promote allowlist.
    assert is_secret_kind("token")
    assert not kind_is_allowlisted("token")
    assert not should_promote(["token"])
