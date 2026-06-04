"""Cookie identity classifier — pure heuristic (ADR-0026, slice T-AI1).

Determines whether a cookie contributes to `AuthContext` identity (i.e. is a
session credential) based on its *value shape* alone.  No I/O, no graph, no
config — this is the heuristic path only; the engagement-config allowlist
(issue #28) is a separate, later layer.

Rule: **include-biased**.  A cookie feeds identity *unless* its value is
*confidently app/UI state*.

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


def cookie_feeds_identity(name: str, value: str) -> bool:  # noqa: ARG001
    """Return ``True`` if this cookie should contribute to ``AuthContext`` identity.

    Parameters
    ----------
    name:
        Cookie name (carried for future allowlist use; not used by this heuristic).
    value:
        Cookie value as a plain string (URL-decoded or as-is from the HAR).

    Returns
    -------
    bool
        ``True``  — cookie is (or may be) a session credential; include in hash.
        ``False`` — cookie is confidently app/UI state; exclude from hash.
    """
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
