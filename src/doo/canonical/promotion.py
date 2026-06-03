"""Pure promotion decision: which candidate values become `ObservedValue`s.

The graph-touching promotion *applier* lives in `ontology/commit.py`; this is its
pure decision counterpart, mirroring the `canonical/templating.py` ↔
`ontology/templating.py` split. `should_promote` answers, for one value's set of
candidate occurrences (already grouped by `value_hash`, engagement-scoped),
whether it clears a promotion signal (ADR-0023).

Three promotion signals are active after #16:

- **Shape-allowlist** (#14, narrowed by ADR-0024): a value whose `kind ∈
  {secret, internal_hostname, email}` promotes on shape alone, even at a single
  occurrence — these are rare and inherently interesting. `secret` is reserved
  for the high-precision structured detectors (JWT / AWS / Stripe). A generic
  high-entropy blob is `opaque_token` — secret-for-storage (hash-only) but
  **not** on this allowlist, so it promotes only on a cross-context signal
  (multiplicity ≥2 or leak-to-input), not on shape. This decouples
  secrecy-for-storage from promotion-worthiness (one flag once conflated both).
- **Multiplicity ≥2** (#15): a value occurring across **≥2 distinct
  observations** promotes regardless of kind — a recurring identifier (a tenant
  / account id seen in several responses) is tractable context even though its
  shape is high-cardinality. Multiplicity counts *distinct observations*: the
  same value twice within one response is multiplicity 1, not 2.
- **Leak-to-input** (#16): a value whose occurrences include **both an `output`
  role (surfaced in a response) and an `input` role (sent as a request
  parameter)** promotes regardless of kind or multiplicity — this is ADR-0009's
  "what to test next" signal: a value the target *emitted* and elsewhere
  *accepts* as input. A value seen *only* as an input (never an output) does not
  promote on this signal alone — it still needs multiplicity / allowlist.

A single-occurrence non-allowlisted value with no leak-to-input still does
**not** promote (the 277k collapse) — it stays an inline candidate occurrence.

No I/O, no LLM (CLAUDE.md hard rule). Deterministic on its inputs.
"""

from __future__ import annotations

from collections.abc import Sequence

from doo.canonical.values import CandidateKind

# Kinds that promote on shape alone (ADR-0023 shape-allowlist, narrowed by
# ADR-0024), even at a single occurrence. Everything else — including
# `opaque_token` (hash-only for storage but not always-promoted) — needs a
# cross-context signal: multiplicity (#15) or leak-to-input (#16). `token` and
# `opaque_token` are deliberately absent: only the high-precision structured
# `secret` detectors warrant a node on shape alone.
SHAPE_ALLOWLIST: frozenset[CandidateKind] = frozenset(
    ("secret", "internal_hostname", "email")
)

# The multiplicity signal fires at this many distinct observations (ADR-0023).
MULTIPLICITY_THRESHOLD = 2


def kind_is_allowlisted(kind: CandidateKind) -> bool:
    """True if `kind` promotes on shape alone (ADR-0023 shape-allowlist)."""

    return kind in SHAPE_ALLOWLIST


def is_leak_to_input(roles: Sequence[str]) -> bool:
    """True if a value's occurrences include **both** an `output` and an `input` role.

    The leak-to-input pivot (ADR-0009 / #16): a value the target emitted in a
    response *and* accepts as a request parameter elsewhere. A value seen only as
    an input (or only as an output) is not a pivot.
    """

    return "output" in roles and "input" in roles


def should_promote(
    kinds: Sequence[CandidateKind],
    *,
    distinct_observations: int = 1,
    roles: Sequence[str] = (),
) -> bool:
    """Decide whether a value promotes to an `ObservedValue` (ADR-0023).

    `kinds` is every candidate occurrence's `kind` for one `value_hash`;
    `distinct_observations` is the number of distinct `RequestObservation`s that
    surfaced the value (defaulting to 1 so a kinds-only caller gets the
    shape-allowlist behaviour); `roles` is every occurrence's role (`output` /
    `input`) — empty when a caller does not track roles (then leak-to-input simply
    cannot fire). A value promotes iff *any* signal fires:

    - **shape-allowlist** — any occurrence's kind is allowlisted; or
    - **multiplicity ≥2** — it appears in `MULTIPLICITY_THRESHOLD`+ distinct
      observations; or
    - **leak-to-input** — its roles include both `output` and `input` (#16).

    A non-allowlisted, single-observation, non-pivot value does not promote (the
    277k collapse): 100 distinct list-item identifiers are 100 separate
    `value_hash`es, each a single-occurrence non-allowlisted value here. A value
    seen *only* as an input is likewise not promoted by leak-to-input alone.
    """

    if any(kind_is_allowlisted(k) for k in kinds):
        return True
    if is_leak_to_input(roles):
        return True
    return distinct_observations >= MULTIPLICITY_THRESHOLD
