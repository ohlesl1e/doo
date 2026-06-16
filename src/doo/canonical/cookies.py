"""Cookie identity classifier (ADR-0026).

Determines whether a cookie contributes to `AuthContext` identity (i.e. is a
session credential). Pure — no I/O, no graph.

Two modes:
- **Authoritative allowlist** (engagement `session_cookie_names`, ADR-0026 #28):
  when a non-empty allowlist is supplied, ONLY cookies whose name is listed feed
  identity; the shape heuristic is bypassed entirely (names matched exactly).
- **Shape heuristic** (no allowlist): **include-biased** — a cookie feeds
  identity *unless* its value is *confidently app/UI state*.

Exclusion conditions (``cookie_feeds_identity`` returns ``False``):
- value is empty or whitespace-only
- value length < 8
- value is a pure integer (``^-?\\d+$``)
- value is a boolean/sentinel (``true|false|yes|no|on|off|null``, case-insensitive)

In all other cases the cookie is included (feeds identity).

JWT-shaped values (three base64url segments separated by dots matching
``\\beyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}\\b``)
are *unconditionally* a session credential — bypassing even the exclusion
checks (none of which would fire for a well-formed JWT anyway, but the
explicit fast-path makes intent clear and is tested directly).

Note: this predicate is intentionally **looser** than ``artifacts._high_entropy``
(which requires mixed upper+lower+digit).  All-hex ``JSESSIONID`` and
lowercase-hex ``PHPSESSID`` values are kept — they pass the length check and
are not integers or booleans.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

# Matches a JWT: header begins with 'eyJ' ({"  base64url-encoded), followed by
# two more base64url segments of at least 6 chars each.
_JWT_RE: re.Pattern[str] = re.compile(
    r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"
)

# Pure integer: optional leading minus, then only digits.
_INT_RE: re.Pattern[str] = re.compile(r"^-?\d+$")

# Boolean / sentinel values (case-insensitive).
_BOOL_RE: re.Pattern[str] = re.compile(
    r"^(true|false|yes|no|on|off|null)$", re.IGNORECASE
)

_MIN_SESSION_LEN = 8


def cookie_feeds_identity(
    name: str, value: str, *, allowlist: frozenset[str] | None = None
) -> bool:
    """Return ``True`` if this cookie should contribute to ``AuthContext`` identity.

    Parameters
    ----------
    name:
        Cookie name.
    value:
        Cookie value as a plain string (URL-decoded or as-is from the HAR).
    allowlist:
        Authoritative engagement `session_cookie_names` (ADR-0026 #28). When
        non-empty, identity is computed over ONLY these cookie names and the shape
        heuristic below is bypassed entirely. ``None``/empty → use the heuristic.

    Returns
    -------
    bool
        ``True``  — cookie is (or may be) a session credential; include in hash.
        ``False`` — cookie is confidently app/UI state; exclude from hash.
    """
    # Authoritative allowlist: only listed names feed identity, heuristic bypassed.
    if allowlist:
        return name in allowlist

    # Fast path: JWT-shaped value is unconditionally a credential.
    if _JWT_RE.search(value):
        return True

    # Exclusion checks — confident app-state signals.
    if not value or not value.strip():
        return False
    if len(value) < _MIN_SESSION_LEN:
        return False
    if _INT_RE.fullmatch(value):
        return False
    if _BOOL_RE.fullmatch(value):
        return False

    # Default: include (include-biased).
    return True


def normalize_cookie_value(value: str) -> str:
    """Normalise a cookie value: percent-decode, then strip the RFC 6265 ``DQUOTE``
    wrapper.

    RFC 6265's ``cookie-octet`` excludes ``DQUOTE``/comma/semicolon, so an app that
    needs to send such content (e.g. a *quoted* JWT) percent-encodes it — a real
    capture carried its session JWT as ``%22eyJ…%22``. Both the encoding and the
    surrounding quotes are transport syntax, not credential material: leaving them
    on breaks JWT claim decoding (ADR-0027) and splits an otherwise-identical
    credential into distinct ``auth_hash``es. Decode, then remove one matching
    leading+trailing ``"`` pair.

    This is the **canonical credential form** of a cookie value (#103). Every
    ``compute_auth_hash("cookie", …)`` caller — L2 ingestion (``extraction/har.py``)
    *and* the declared side (``setup/loader.py``, ``dispatch/auth_helper.py``,
    ``dispatch/secrets.py``, ``dispatch/executor/liveness.py``) — passes the value
    through here first, so a quoted/encoded credential hashes identically wherever
    it is seen. The wire-form value (``material.raw`` / the rotation file) is **not**
    normalised; the request constructor's job is to send what the server expects.
    """

    decoded = unquote(value)
    if len(decoded) >= 2 and decoded[0] == '"' and decoded[-1] == '"':
        return decoded[1:-1]
    return decoded


def canonical_credential_value(kind: str, raw: str) -> str:
    """The canonical (hash-input) form of a credential value, by ``kind`` (#103).

    For ``kind == "cookie"`` returns :func:`normalize_cookie_value` (percent-decode
    + DQUOTE-strip). For every other kind (``bearer`` / ``api_key`` / ``basic_auth``
    / ``anonymous``) returns ``raw`` unchanged — those carriers have no
    DQUOTE-wrapping convention and a literal ``"`` is credential material there.

    Pure; never mutates its input. Callers feed the result to
    ``compute_auth_hash(kind, …)`` and to JWT claim decoding, but persist / send the
    untouched ``raw`` (``AuthMaterial.raw``, ``write_rotation_entry(..., raw=...)``).
    """

    if kind == "cookie":
        return normalize_cookie_value(raw)
    return raw
