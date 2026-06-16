"""Pure `TrustBoundary` inference decisions (ADR-0039).

The graph-touching boundary *applier* lives in `ontology/trust_boundary.py`; this
is its pure decision counterpart, mirroring the `canonical/promotion.py` ↔
`ontology/promotion.py` split. No I/O, no graph, no LLM (CLAUDE.md hard rule);
deterministic on its inputs.

Two boundary kinds are inferred (ADR-0039); both are **evidence-gated** — a
boundary is drawn only when the observed evidence actually distinguishes the two
sides, never synthesised:

- **capability** (`scope` / `mfa` / `freshness`) — between two `AuthContext`s of
  the *same* `Principal` that show a **claim delta** in the decoded
  `identity_claims` (ADR-0025). The distinguishing claims are JWT `scope` (→
  `scope`), `acr` / `amr` (→ `mfa`), and `auth_time` (→ `freshness`). Absent any
  distinguishing claim → no boundary (no synthesised tiers).
- **tenant** — between two `Tenant`s that share ≥1 `Endpoint`. The pairing /
  shared-endpoint test is a graph traversal and lives in the applier; this module
  only carries the kind constants.

`capability_kind_for_delta` maps a set of differing capability claims to the
boundary `kind` (the most security-significant axis the delta touches), so a pair
that differs in `scope` *and* `acr` is one `scope` boundary, not two.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

# The boundary kinds this slice infers (ADR-0039). `role` / `ownership` are
# modelled in the ontology but deliberately not inferred yet (deferred until a
# node-level consumer needs them).
CapabilityKind = Literal["scope", "mfa", "freshness"]
TENANT_KIND = "tenant"

# JWT claims that distinguish a capability tier (ADR-0025 / ADR-0039), mapped to
# the capability axis (boundary `kind`) each one signals. Order is significant:
# it is the precedence used to pick a single `kind` when a delta touches several
# axes — `scope` (what you may do) outranks `mfa` (how strongly you authenticated)
# outranks `freshness` (how recently).
_CLAIM_TO_KIND: tuple[tuple[str, CapabilityKind], ...] = (
    ("scope", "scope"),
    ("acr", "mfa"),
    ("amr", "mfa"),
    ("auth_time", "freshness"),
)

# The capability-distinguishing claim names (the keys of `_CLAIM_TO_KIND`).
CAPABILITY_CLAIMS: frozenset[str] = frozenset(name for name, _ in _CLAIM_TO_KIND)


def _claim_value(claims: Mapping[str, object], name: str) -> object | None:
    """Read one claim's value, normalising list-valued claims to a stable form.

    JWT `amr` (and sometimes `scope`) can be array-valued; compare order-
    insensitively for `amr` (a set of methods) and as a normalised string for
    space-delimited `scope`. Everything else compares by raw value.
    """

    value = claims.get(name)
    if value is None:
        return None
    if name == "amr" and isinstance(value, list):
        # A set of auth methods — order-insensitive.
        return tuple(sorted(str(v) for v in value))
    if name == "scope" and isinstance(value, str):
        # Space-delimited scope string — order-insensitive set of scopes.
        return tuple(sorted(value.split()))
    if name == "scope" and isinstance(value, list):
        return tuple(sorted(str(v) for v in value))
    return value


def differing_capability_claims(
    claims_a: Mapping[str, object], claims_b: Mapping[str, object]
) -> frozenset[str]:
    """Return the capability claims whose values differ between two AuthContexts.

    A claim counts as differing only when **both** sides carry it and the values
    differ (evidence-gating: a claim present on one side and absent on the other
    is not, on its own, a distinguishing capability delta — it is missing
    evidence, not an observed tier difference). This keeps the boundary set honest
    when one token simply omits a claim the other includes.
    """

    differing: set[str] = set()
    for name in CAPABILITY_CLAIMS:
        a = _claim_value(claims_a, name)
        b = _claim_value(claims_b, name)
        if a is None or b is None:
            continue
        if a != b:
            differing.add(name)
    return frozenset(differing)


def capability_kind_for_delta(differing_claims: frozenset[str]) -> CapabilityKind | None:
    """Pick the single capability boundary `kind` for a set of differing claims.

    Returns the highest-precedence axis (`scope` > `mfa` > `freshness`) touched by
    the delta, or `None` when the delta is empty (no distinguishing claim → no
    boundary, per ADR-0039's evidence-gating).
    """

    for claim_name, kind in _CLAIM_TO_KIND:
        if claim_name in differing_claims:
            return kind
    return None


def _scope_set(claims: Mapping[str, object]) -> frozenset[str]:
    """The set of scopes a claims map carries (space-delimited or list), or empty."""

    norm = _claim_value(claims, "scope")
    if isinstance(norm, tuple):
        return frozenset(norm)
    return frozenset()


def stronger_capability_side(
    claims_a: Mapping[str, object],
    claims_b: Mapping[str, object],
    kind: CapabilityKind,
) -> Literal["a", "b"] | None:
    """Which side is the STRONGER capability tier on `kind` — `"a"`, `"b"`, or None.

    The direction C4 turns on (the *strong* AuthContext reached an endpoint the
    *weak* one did not). Evidence-gated like the rest of capability inference: an
    ordering that cannot be observed cleanly returns None (C4 does not invent a tier).

    - `scope`: the side whose scope set is a strict SUPERSET is stronger; disjoint
      or equal sets are ambiguous (None).
    - `mfa`: higher `acr` wins; failing a clear `acr` order, a strict-superset `amr`
      (more auth methods) wins; otherwise None.
    - `freshness`: the larger (more recent) `auth_time` is stronger; equal or
      unparseable is None.
    """

    if kind == "scope":
        a, b = _scope_set(claims_a), _scope_set(claims_b)
        if a > b:
            return "a"
        if b > a:
            return "b"
        return None
    if kind == "mfa":
        acr_a, acr_b = claims_a.get("acr"), claims_b.get("acr")
        if acr_a is not None and acr_b is not None and acr_a != acr_b:
            try:
                return "a" if float(str(acr_a)) > float(str(acr_b)) else "b"
            except ValueError:
                return "a" if str(acr_a) > str(acr_b) else "b"
        amr_a = _claim_value(claims_a, "amr")
        amr_b = _claim_value(claims_b, "amr")
        sa = frozenset(amr_a) if isinstance(amr_a, tuple) else frozenset()
        sb = frozenset(amr_b) if isinstance(amr_b, tuple) else frozenset()
        if sa > sb:
            return "a"
        if sb > sa:
            return "b"
        return None
    if kind == "freshness":
        try:
            fa = float(str(claims_a.get("auth_time")))
            fb = float(str(claims_b.get("auth_time")))
        except (TypeError, ValueError):
            return None
        if fa > fb:
            return "a"
        if fb > fa:
            return "b"
        return None
    return None
