"""Pure promotion decision: which candidate values become `ObservedValue`s.

The graph-touching promotion *applier* lives in `ontology/commit.py`; this is its
pure decision counterpart, mirroring the `canonical/templating.py` ↔
`ontology/templating.py` split. `should_promote` answers, for one value's set of
candidate occurrences (already grouped by `value_hash`, engagement-scoped),
whether it clears a promotion signal (ADR-0023).

Two promotion signals are active after #15:

- **Shape-allowlist** (#14): a value whose `kind ∈ {secret, token,
  internal_hostname, email}` promotes on shape alone, even at a single
  occurrence — these are rare and inherently interesting.
- **Multiplicity ≥2** (#15): a value occurring across **≥2 distinct
  observations** promotes regardless of kind — a recurring identifier (a tenant
  / account id seen in several responses) is tractable context even though its
  shape is high-cardinality. Multiplicity counts *distinct observations*: the
  same value twice within one response is multiplicity 1, not 2.

A single-occurrence non-allowlisted value still does **not** promote (the 277k
collapse) — it stays an inline candidate occurrence. The leak-to-input branch
named by ADR-0023 is still out of scope.

No I/O, no LLM (CLAUDE.md hard rule). Deterministic on its inputs.
"""

from __future__ import annotations

from collections.abc import Sequence

from doo.canonical.values import CandidateKind

# Kinds that promote on shape alone (ADR-0023 shape-allowlist), even at a single
# occurrence. Everything else needs a cross-context signal — multiplicity (#15)
# or, later, leak-to-input.
SHAPE_ALLOWLIST: frozenset[CandidateKind] = frozenset(
    ("secret", "token", "internal_hostname", "email")
)

# The multiplicity signal fires at this many distinct observations (ADR-0023).
MULTIPLICITY_THRESHOLD = 2


def kind_is_allowlisted(kind: CandidateKind) -> bool:
    """True if `kind` promotes on shape alone (ADR-0023 shape-allowlist)."""

    return kind in SHAPE_ALLOWLIST


def should_promote(
    kinds: Sequence[CandidateKind], *, distinct_observations: int = 1
) -> bool:
    """Decide whether a value promotes to an `ObservedValue` (ADR-0023).

    `kinds` is every candidate occurrence's `kind` for one `value_hash`;
    `distinct_observations` is the number of distinct `RequestObservation`s that
    surfaced the value (defaulting to 1 so a kinds-only caller gets the
    shape-allowlist behaviour). A value promotes iff *any* signal fires:

    - **shape-allowlist** — any occurrence's kind is allowlisted; or
    - **multiplicity ≥2** — it appears in `MULTIPLICITY_THRESHOLD`+ distinct
      observations.

    A non-allowlisted value seen in a single observation does not promote (the
    277k collapse): 100 distinct list-item identifiers are 100 separate
    `value_hash`es, each a single-occurrence non-allowlisted value here.
    """

    if any(kind_is_allowlisted(k) for k in kinds):
        return True
    return distinct_observations >= MULTIPLICITY_THRESHOLD
