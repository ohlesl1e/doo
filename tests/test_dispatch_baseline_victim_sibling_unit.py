"""ADR-0052 pure-selector unit tests for the baseline_victim Principal-sibling walk.

`_resolve_baseline_victim_sibling(observed_carrier, siblings)` is a pure function:
it picks the live declared `AuthContext` to send `baseline_victim` under, by
matching the observed discovered session's carrier (`token_kind`) against each
declared sibling's carrier, then disambiguating on the sibling's `slot` (the
ADR-0049 dedup key). These cover EVERY row of the brief's selection matrix (no
containers). The walk is strictly additive — it never flips an existing outcome —
so every "decline" row returns `None`, leaving the existing un-armable path.
"""

from __future__ import annotations

from doo.dispatch.executor.evidence import (
    _DeclaredSibling,
    _resolve_baseline_victim_sibling,
)
from doo.ids import AuthContextId


def _sib(
    ac_id: str,
    slot: str | None,
    carrier: str | None = None,
    principal_id: str = "p-1",
) -> _DeclaredSibling:
    # carrier defaults to slot, mirroring ADR-0049 (slot defaults to token_kind).
    return _DeclaredSibling(
        principal_id=principal_id,
        id=AuthContextId(ac_id),
        slot=slot,
        carrier=carrier if carrier is not None else slot,
    )


def test_one_sibling_carrier_matches_resolves() -> None:
    # Discovered (carrier=cookie); one declared sibling on slot=cookie → the win.
    out = _resolve_baseline_victim_sibling("cookie", [_sib("ac-decl", "cookie")])
    assert out == AuthContextId("ac-decl")


def test_multiple_siblings_exactly_one_carrier_match_resolves() -> None:
    # Two declared siblings, only one shares the carrier → use it.
    out = _resolve_baseline_victim_sibling(
        "cookie",
        [_sib("ac-bearer", "bearer"), _sib("ac-cookie", "cookie")],
    )
    assert out == AuthContextId("ac-cookie")


def test_no_carrier_match_declines() -> None:
    # Siblings exist but none share the carrier → never replay over a different
    # carrier (false-negative risk) → un-armable (unchanged).
    out = _resolve_baseline_victim_sibling(
        "cookie",
        [_sib("ac-bearer", "bearer"), _sib("ac-apikey", "api_key")],
    )
    assert out is None


def test_two_distinct_slots_share_carrier_is_ambiguous() -> None:
    # ≥2 *distinct slots* share the same carrier (a session cookie + a step-up
    # cookie, both token_kind=cookie) → ambiguous, don't guess → None.
    out = _resolve_baseline_victim_sibling(
        "cookie",
        [
            _sib("ac-session", "session", carrier="cookie"),
            _sib("ac-stepup", "stepup", carrier="cookie"),
        ],
    )
    assert out is None


def test_multiple_generations_of_one_slot_resolves() -> None:
    # Multiple declared generations of ONE slot (same slot string, distinct ids):
    # one distinct slot → resolve; SlotResolvingSecretStore's rotation overlay
    # picks the latest generation (dedup key is ADR-0049 (principal_label, slot)).
    out = _resolve_baseline_victim_sibling(
        "cookie",
        [_sib("ac-gen1", "cookie"), _sib("ac-gen2", "cookie")],
    )
    # First matching id is returned; generation selection is deferred to the store.
    assert out == AuthContextId("ac-gen1")


def test_no_sibling_declines() -> None:
    assert _resolve_baseline_victim_sibling("cookie", []) is None


def test_no_carrier_declines() -> None:
    # Observed AC had no token_kind to match on → un-armable (unchanged).
    assert _resolve_baseline_victim_sibling(None, [_sib("ac-decl", "cookie")]) is None


def test_custom_slot_label_matches_on_carrier() -> None:
    # A lone declared cookie credential carrying a custom slot label (session)
    # still matches a discovered cookie session, because the match is on carrier.
    out = _resolve_baseline_victim_sibling(
        "cookie", [_sib("ac-session", "session", carrier="cookie")]
    )
    assert out == AuthContextId("ac-session")
