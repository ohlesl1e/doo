"""Observed-response identity extraction (ADR-0029).

Pure, deterministic detection of an actor's identity from a *response* — the
fallback ADR-0010 names for credentials that carry no decodable claim (opaque,
non-JWT tokens). No I/O, no graph, no LLM.

Detects **identity response headers** (T-OI1) and **self-endpoint body** claims
(T-OI2). The extracted identity is correlated at flush back to the request's
`AuthContext` to upgrade a synthetic discovered `Principal`
(`ontology/identity_reconcile.py`).
"""

from __future__ import annotations

import json
import re
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


# Generic self-endpoint path patterns (T-OI2): a request that asks "who am I?".
# Each segment is anchored (`/me`, not `/method`) so ordinary paths don't match.
_SELF_ENDPOINT_RE = re.compile(
    r"/(?:me|whoami|profile|account|session|userinfo|current[-_]?user|user/current)(?:/|$)",
    re.IGNORECASE,
)

# Identity claim keys read from a self-endpoint body, highest-precision first.
# All are globally unique per user (the merge-safety requirement); `email` leads
# as the most stable cross-system identifier. No bare positional `id` guessing.
_BODY_IDENTITY_CLAIMS: tuple[str, ...] = ("email", "sub", "_id", "uid", "user_id")

# Body wrappers a self-endpoint commonly nests the actor under (one level only,
# so a deep walk can't pick up an unrelated nested document's id).
_BODY_IDENTITY_WRAPPERS: tuple[str, ...] = ("user", "data", "profile", "account", "result")


def is_self_endpoint(path: str) -> bool:
    """True if `path` matches a generic self-endpoint pattern (`/me`, `/profile`, …).

    Black-box convention, not target seeding. Segment-anchored so `/method` /
    `/readme` / `/home` do not match.
    """

    return _SELF_ENDPOINT_RE.search(path) is not None


def _first_identity_claim(obj: dict[str, object]) -> tuple[str, str] | None:
    """The highest-priority `(claim, value)` present on a JSON object, or `None`."""

    for claim in _BODY_IDENTITY_CLAIMS:
        raw = obj.get(claim)
        if isinstance(raw, str | int) and not isinstance(raw, bool):
            value = str(raw).strip()
            if value:
                return claim, value
    return None


def extract_observed_identity_from_self_endpoint_body(
    body_text: str, content_type: str
) -> ObservedIdentity | None:
    """Actor identity from a self-endpoint JSON response body, or `None` (T-OI2).

    Reads the top-level object and one level of common wrappers (`user`/`data`/…)
    for the highest-priority globally-unique identity claim. The caller gates this
    on `is_self_endpoint(path)`; identity is never guessed on an ordinary endpoint.
    A non-JSON / malformed / claim-less body yields `None` and never raises. The
    `signal` is `body` (so the discovered key is `discovered:observed:body:{value}`).
    """

    base_mime = content_type.split(";", 1)[0].strip().lower()
    if base_mime != "application/json" and not base_mime.endswith("+json"):
        return None
    try:
        doc = json.loads(body_text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None

    found = _first_identity_claim(doc)
    if found is None:
        for wrapper in _BODY_IDENTITY_WRAPPERS:
            nested = doc.get(wrapper)
            if isinstance(nested, dict):
                found = _first_identity_claim(nested)
                if found is not None:
                    break
    if found is None:
        return None
    claim, value = found
    # Email is case-insensitive — lowercase it so two casings of one account don't
    # split into two identities (consistent with the JWT-claim path, ADR-0027).
    if claim == "email":
        value = value.lower()
    return ObservedIdentity(signal="body", value=value)
