"""Observed-response identity extraction (ADR-0029, unified by ADR-0030).

Pure, deterministic detection of an actor's identity from a *response* — the
fallback ADR-0010 names for credentials that carry no decodable claim (opaque,
non-JWT tokens). No I/O, no graph, no LLM.

Detects **identity response headers** (T-OI1) and **self-endpoint body** claims
(T-OI2). Each detected identity is a **claim-tagged** `ObservedIdentity(claim,
value)` (ADR-0030): a response can surface *several* simultaneous identities
(e.g. a `/me` body carrying both `_id` and `email`), and the source is provenance
only — the unified key resolver turns each `(claim, value)` into the
source-agnostic `discovered:{claim}:{value}` key. The extracted identities are
correlated at flush back to the request's `AuthContext` to upgrade a synthetic
discovered `Principal` (`ontology/identity_reconcile.py`).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping

from doo.canonical.value_objects import ObservedIdentity

# Conventional identity response headers, highest-precision first. Generic
# conventions (not target-specific seeding) — the same standing we give to
# recognising JWT structure. The header name doubles as the identity `claim`
# (the unified key becomes `discovered:{header-name}:{value}`, ADR-0030), so two
# id spaces (a user id vs an account id) never collide on a shared value.
IDENTITY_RESPONSE_HEADERS: tuple[str, ...] = (
    "x-user-id",
    "x-user",
    "x-username",
    "x-authenticated-user",
    "x-account-id",
)


def extract_observed_identities_from_headers(
    response_headers: Mapping[str, str],
) -> tuple[ObservedIdentity, ...]:
    """All actor identities asserted by response headers, claim-tagged (ADR-0030).

    `response_headers` is a name-lowercased map. Returns one `ObservedIdentity`
    per present, non-empty identity header in `IDENTITY_RESPONSE_HEADERS` priority
    order; the header name is the `claim`, its value the `value`. Empty when none
    are present.
    """

    out: list[ObservedIdentity] = []
    for name in IDENTITY_RESPONSE_HEADERS:
        value = response_headers.get(name, "").strip()
        if value:
            out.append(ObservedIdentity(claim=name, value=value))
    return tuple(out)


# Generic self-endpoint path patterns (T-OI2): a request that asks "who am I?".
# Each segment is anchored (`/me`, not `/method`) so ordinary paths don't match.
_SELF_ENDPOINT_RE = re.compile(
    r"/(?:me|whoami|profile|account|session|userinfo|current[-_]?user|user/current)(?:/|$)",
    re.IGNORECASE,
)

# Identity claim keys read from a self-endpoint body, account-unique first; `email`
# LAST (person-level, ADR-0030). All are globally unique per user for keying; no
# bare positional `id` guessing. The unified key resolver re-applies the canonical
# claim-priority — this list just bounds which keys we *read* from a body.
_BODY_IDENTITY_CLAIMS: tuple[str, ...] = (
    "sub",
    "uid",
    "user_id",
    "uuid",
    "_id",
    "username",
    "uname",
    "preferred_username",
    "email",
)

# Body wrappers a self-endpoint commonly nests the actor under (one level only,
# so a deep walk can't pick up an unrelated nested document's id).
_BODY_IDENTITY_WRAPPERS: tuple[str, ...] = ("user", "data", "profile", "account", "result")


def is_self_endpoint(path: str) -> bool:
    """True if `path` matches a generic self-endpoint pattern (`/me`, `/profile`, …).

    Black-box convention, not target seeding. Segment-anchored so `/method` /
    `/readme` / `/home` do not match.
    """

    return _SELF_ENDPOINT_RE.search(path) is not None


def _identity_claims_of(obj: dict[str, object]) -> list[ObservedIdentity]:
    """All present `_BODY_IDENTITY_CLAIMS` on a JSON object, claim-tagged (ADR-0030).

    Email is lowercased (case-insensitive — two casings of one account must not
    split into two identities, consistent with the JWT-claim path).
    """

    out: list[ObservedIdentity] = []
    for claim in _BODY_IDENTITY_CLAIMS:
        raw = obj.get(claim)
        if isinstance(raw, str | int) and not isinstance(raw, bool):
            value = str(raw).strip()
            if not value:
                continue
            if claim == "email":
                value = value.lower()
            out.append(ObservedIdentity(claim=claim, value=value))
    return out


def extract_observed_identities_from_self_endpoint_body(
    body_text: str, content_type: str
) -> tuple[ObservedIdentity, ...]:
    """All actor identities from a self-endpoint JSON response body (T-OI2, ADR-0030).

    Reads the top-level object and one level of common wrappers (`user`/`data`/…)
    for every present, account-unique identity claim (plus `email` last), each
    claim-tagged so a `_id` and an `email` are distinct identities. The caller
    gates this on `is_self_endpoint(path)`; identity is never guessed on an
    ordinary endpoint. A non-JSON / malformed / claim-less body yields an empty
    tuple and never raises.
    """

    base_mime = content_type.split(";", 1)[0].strip().lower()
    if base_mime != "application/json" and not base_mime.endswith("+json"):
        return ()
    try:
        doc = json.loads(body_text)
    except (json.JSONDecodeError, ValueError):
        return ()
    if not isinstance(doc, dict):
        return ()

    found = _identity_claims_of(doc)
    if not found:
        for wrapper in _BODY_IDENTITY_WRAPPERS:
            nested = doc.get(wrapper)
            if isinstance(nested, dict):
                found = _identity_claims_of(nested)
                if found:
                    break
    return tuple(found)
