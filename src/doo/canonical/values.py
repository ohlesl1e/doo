"""Deterministic value canonicalisation (ObservedValue identity; ADR-0023 / ADR-0009).

Pure functions — no I/O, no graph, no LLM (CLAUDE.md hard rule). The promotion
pass (`ontology/commit.py`) and candidate extraction (`canonical/value_candidates.py`)
share one canonical representation of an extracted value, so the same value seen
in two places collapses to one `ObservedValue` (identity `(engagement_id,
value_hash)`; ADR-0009). This mirrors `canonical/identity.py`: `normalize_value`
is the per-kind canonical form, `value_hash` is the sha256 over it.

`CandidateKind` is the closed vocabulary of extracted-value kinds. It supersedes
the retired `ResponseArtifactKind` (ADR-0023): the response *diagnostics*
(fingerprint, error excerpt) are no longer values — they are inline observation
properties — so they leave the vocabulary.

Secret discipline (ADR-0015): for `secret` / `token` kinds the canonical form is
*not* a recoverable transform of the raw value — `normalize_value` raises if
handed a secret raw value, because the raw secret must never flow through a value
that could be persisted. Secret candidates carry a `value_hash` computed at the
extractor edge from the raw matched bytes (`secret_value_hash`), plus length +
preview; the raw value lives only in the object-storage blob.
"""

from __future__ import annotations

import hashlib
from typing import Literal, get_args

from doo.ids import Sha256Hex

# The closed vocabulary of candidate-value kinds (ADR-0023). `identifier`,
# `ip_address`, and `url` are high-cardinality / low-signal: they are retained as
# inline candidate occurrences and do NOT promote on shape alone in slice 1 (the
# 277k collapse). The shape-allowlist kinds below promote even at one occurrence.
CandidateKind = Literal[
    "internal_hostname",
    "email",
    "ip_address",
    "url",
    "identifier",
    "secret",
    "token",
]

CANDIDATE_KINDS: tuple[CandidateKind, ...] = get_args(CandidateKind)

# Kinds whose raw value must never enter the graph (ADR-0015): only the
# `value_hash` + length + preview are carried. The raw bytes live only in the
# response-body blob.
SECRET_CANDIDATE_KINDS: frozenset[CandidateKind] = frozenset(("secret", "token"))


def is_secret_kind(kind: CandidateKind) -> bool:
    """True if `kind`'s raw value must be hashed, never carried (ADR-0015)."""

    return kind in SECRET_CANDIDATE_KINDS


def normalize_value(kind: CandidateKind, raw: str) -> str:
    """Canonical form of a non-secret extracted value, for `value_hash` identity.

    Determinism is what matters (so two spellings of one value collapse), not
    linguistic correctness. Per kind:

    - `internal_hostname` — lowercased, trailing dot stripped (host identity is
      case-insensitive; CONTEXT.md Host identity rules).
    - `email` — local part kept verbatim (RFC: case-sensitive in principle), the
      domain lowercased; surrounding whitespace stripped.
    - `ip_address` — stripped (already a literal).
    - `url`, `identifier` — stripped only; these are retained verbatim (case and
      structure can be load-bearing; they do not promote on shape in #14 anyway).

    Raises `ValueError` for a secret kind: a secret must never be normalised into
    a recoverable form (ADR-0015) — use `secret_value_hash` on the raw bytes.
    """

    if is_secret_kind(kind):
        raise ValueError(
            f"normalize_value refuses secret kind {kind!r}: secrets are never "
            "normalised into a recoverable form (ADR-0015); use secret_value_hash"
        )
    stripped = raw.strip()
    if kind == "internal_hostname":
        return stripped.rstrip(".").lower()
    if kind == "email":
        local, sep, domain = stripped.partition("@")
        return f"{local}{sep}{domain.lower()}" if sep else stripped.lower()
    return stripped


def value_hash(normalized: str) -> Sha256Hex:
    """`sha256` over a normalised (non-secret) value — the `ObservedValue` identity.

    The hash is over the *normalised* form so equivalent spellings of one value
    converge to the same `ObservedValue` (ADR-0009 dedup).
    """

    return Sha256Hex(hashlib.sha256(normalized.encode("utf-8")).hexdigest())


def secret_value_hash(raw: str) -> Sha256Hex:
    """`sha256` over a secret's raw matched bytes (ADR-0015 secret-shape identity).

    Computed at the extractor edge from the raw bytes and then the raw value is
    dropped; the hash (never the value) is what dedups secret `ObservedValue`s and
    flows through every downstream property and key.
    """

    return Sha256Hex(hashlib.sha256(raw.encode("utf-8")).hexdigest())


def hash_for(kind: CandidateKind, raw: str) -> Sha256Hex:
    """The `value_hash` for any kind: normalised for non-secrets, raw-bytes for secrets.

    A single helper so callers do not branch on `is_secret_kind` themselves: secret
    kinds hash the raw bytes (ADR-0015), non-secret kinds hash the normalised form.
    """

    if is_secret_kind(kind):
        return secret_value_hash(raw)
    return value_hash(normalize_value(kind, raw))
