"""Pure promotion decision: which candidate values become `ObservedValue`s.

The graph-touching promotion *applier* lives in `ontology/commit.py`; this is its
pure decision counterpart, mirroring the `canonical/templating.py` ↔
`ontology/templating.py` split. `should_promote` answers, for one value's set of
candidate occurrences (already grouped by `value_hash`, engagement-scoped),
whether it clears a promotion signal (ADR-0023).

Slice-1 / #14 implements **only the shape-allowlist branch**: a value whose
`kind ∈ {secret, token, internal_hostname, email}` promotes on shape alone, even
at a single occurrence — these are rare and inherently interesting. The
multiplicity (≥2 occurrences) and leak-to-input branches named by ADR-0023 are
deliberately out of #14's scope; high-cardinality identifiers / URLs do **not**
promote here (the 277k collapse) — they stay inline candidate occurrences.

No I/O, no LLM (CLAUDE.md hard rule). Deterministic on its inputs.
"""

from __future__ import annotations

from collections.abc import Sequence

from doo.canonical.values import CandidateKind

# Kinds that promote on shape alone (ADR-0023 shape-allowlist), even at a single
# occurrence. Everything else needs a cross-context signal not yet wired in #14.
SHAPE_ALLOWLIST: frozenset[CandidateKind] = frozenset(
    ("secret", "token", "internal_hostname", "email")
)


def kind_is_allowlisted(kind: CandidateKind) -> bool:
    """True if `kind` promotes on shape alone (ADR-0023 shape-allowlist)."""

    return kind in SHAPE_ALLOWLIST


def should_promote(kinds: Sequence[CandidateKind]) -> bool:
    """Decide whether a value (its occurrences' kinds) promotes to an `ObservedValue`.

    `kinds` is every candidate occurrence's `kind` for one `value_hash`. In #14 the
    only active signal is the shape-allowlist: promote iff *any* occurrence's kind
    is allowlisted. (Multiplicity / leak-to-input are future branches; a list of
    100 distinct identifier occurrences — each its own `value_hash` — yields
    single-element non-allowlisted `kinds` here and does not promote.)
    """

    return any(kind_is_allowlisted(k) for k in kinds)
