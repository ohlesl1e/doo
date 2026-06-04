"""Observed-response identity extraction (ADR-0029).

Pure, deterministic detection of an actor's identity from a *response* — the
fallback ADR-0010 names for credentials that carry no decodable claim (opaque,
non-JWT tokens). No I/O, no graph, no LLM.

This slice (T-OI1) detects **identity response headers** only; self-endpoint body
identity (T-OI2) is a separate, later layer that reuses `ObservedIdentity`.

The extracted identity is correlated at flush back to the request's `AuthContext`
to upgrade a synthetic discovered `Principal` (`ontology/identity_reconcile.py`).
"""

from __future__ import annotations

from collections.abc import Mapping

from doo.canonical.value_objects import ObservedIdentity

# Conventional identity response headers, highest-precision first. Generic
# conventions (not target-specific seeding) — the same standing we give to
# recognising JWT structure. The header name doubles as the discovered-identity
# key namespace token (`discovered:observed:{header-name}:{value}`), so two id
# spaces (a user id vs an account id) never collide on a shared value.
IDENTITY_RESPONSE_HEADERS: tuple[str, ...] = (
    "x-user-id",
    "x-user",
    "x-username",
    "x-authenticated-user",
    "x-account-id",
)


def extract_observed_identity_from_headers(
    response_headers: Mapping[str, str],
) -> ObservedIdentity | None:
    """The actor identity asserted by a response header, or `None`.

    `response_headers` is a name-lowercased map. Returns the first present,
    non-empty identity header in `IDENTITY_RESPONSE_HEADERS` priority order; the
    header name is the `signal`, its value the `value`.
    """

    for name in IDENTITY_RESPONSE_HEADERS:
        value = response_headers.get(name, "").strip()
        if value:
            return ObservedIdentity(signal=name, value=value)
    return None
