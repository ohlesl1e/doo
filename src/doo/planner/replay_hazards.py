"""Deterministic replay-hazard detection (ADR-0041) — NO LLM, pure heuristics.

A slice-3 authz test is a **replay of an evidencing observation under a swapped
identity** (ADR-0037/0041). A verbatim replay trips a *replay-breaker* — a CSRF
token, nonce, signature, or timestamp bound to the original session — and the app
answers 401/403 for a *non-authz* reason. That looks like "boundary enforced" but
is a **false negative** (the worst outcome for a security tool). Slice 3 does not
*solve* refresh (that is slice 4); it *flags* that a naive replay would
false-negative, by annotating the proposal with the detected `ReplayHazardRole`s.

This module is the detector. It is **deterministic** (CLAUDE.md hard rule: no LLM
in any parsing path): name + shape/entropy/short-lived heuristics over the fields
the evidencing observation sent. The LLM never sees this — it selects handles and
classifies; *code* sets `PlannerProposal.replay_hazards` from this detector's
output.

Input shape (deliberately graph-free so the heuristics are unit-testable in
isolation): a `HazardField` carries the field `name` (a request-param name OR, for
a header-borne field, the `header_name` such as `X-CSRF-Token`), an optional
`value` (often `None` — secret-shaped values arrive hash-only, ADR-0015, so the
name carries most of the signal), and a `header_name` flag-ish slot. `value` is
used only for *corroboration* / for the roles (nonce / signature / timestamp) whose
name alone is ambiguous.

`detect_replay_hazards` returns the sorted, de-duplicated tuple of detected roles
(`REPLAY_HAZARD_ROLES` order). `hazards_for_value_candidates` adapts the parsed
`value_candidates` of a `RequestObservation` (the graph's stored form) into the
detector input — including header-borne fields (`section == "header"`).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from doo.events.observation import ValueCandidate
from doo.planner.models import REPLAY_HAZARD_ROLES, ReplayHazardRole


@dataclass(frozen=True, slots=True)
class HazardField:
    """One request field the detector classifies (graph-free, unit-testable).

    `name` is the param name (query key / body-leaf name) or, for a header-borne
    field, the header name (`X-CSRF-Token`). `value` is the sent value when known
    (often `None`: secret-shaped values are stored hash-only, ADR-0015, so the
    detector leans on the name). `is_header` records that the field came from a
    request header — it broadens the csrf-token name match to header conventions
    (`x-csrf-token`, `x-xsrf-token`).
    """

    name: str
    value: str | None = None
    is_header: bool = False


# ---------------------------------------------------------------------------
# Name normalisation. Replay-breaker names vary by separator/case
# (`X-CSRF-Token`, `csrf_token`, `authenticityToken`); fold to a comparable form.
# ---------------------------------------------------------------------------

_SEP_RE = re.compile(r"[-_.\s]+")


def _normalize_name(name: str) -> str:
    """Lowercase + strip separators so `X-CSRF-Token` == `csrf_token` == `csrftoken`."""

    return _SEP_RE.sub("", name.strip().lower())


# ---------------------------------------------------------------------------
# Value-shape helpers. Deterministic, conservative. Used only as corroboration
# (csrf/nonce/signature) or as the decisive check (timestamp), never the LLM.
# ---------------------------------------------------------------------------

# A high-entropy token-shaped value: a single run of base64url/hex chars, long
# enough that it is plainly an opaque session-bound blob rather than an ordinary
# identifier. Mirrors the extraction-layer `_HIGH_ENTROPY_RE` intent (>= ~20 chars).
_TOKEN_SHAPE_RE = re.compile(r"\A[A-Za-z0-9_\-+/=]{16,}\Z")
_HEX_RE = re.compile(r"\A[0-9a-fA-F]{16,}\Z")
_BASE64ISH_RE = re.compile(r"\A[A-Za-z0-9_\-+/=]{12,}\Z")

# Shannon entropy (bits/char) above which a value reads as random rather than a
# word. ~3.0 separates "deadbeefcafe..." / random tokens from "true"/"profile".
_MIN_ENTROPY_BITS = 3.0

# Epoch-second / epoch-millisecond ranges. A 10-digit int in ~2001..2033 (epoch
# seconds) or a 13-digit int (epoch millis) reads as a timestamp; a small int
# (`page=2`, `id=42`) does not.
_EPOCH_SECONDS_MIN = 1_000_000_000  # 2001-09-09
_EPOCH_SECONDS_MAX = 2_000_000_000  # 2033-05-18
_EPOCH_MILLIS_MIN = 1_000_000_000_000
_EPOCH_MILLIS_MAX = 2_000_000_000_000

# ISO-8601-ish datetime (date with optional time / offset / `Z`). Deliberately
# narrow: a bare `2024-01-01` date counts, a free-form string does not.
_ISO8601_RE = re.compile(
    r"\A\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?\Z"
)


def _shannon_entropy_bits(value: str) -> float:
    """Per-character Shannon entropy (bits). 0.0 for the empty string."""

    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_high_entropy(value: str | None) -> bool:
    """A long, token-shaped, high-entropy value (csrf/nonce/signature corroboration)."""

    if not value:
        return False
    if not _TOKEN_SHAPE_RE.match(value):
        return False
    return _shannon_entropy_bits(value) >= _MIN_ENTROPY_BITS


def _looks_signature(value: str | None) -> bool:
    """A base64/hex MAC-shaped value (signature corroboration)."""

    if not value:
        return False
    return bool(_HEX_RE.match(value) or _BASE64ISH_RE.match(value))


def _looks_timestamp(value: str | None) -> bool:
    """An epoch (s/ms) integer or an ISO-8601 datetime — the decisive timestamp check.

    A timestamp NAME (`ts`, `expires`, `exp`) is ambiguous (could be an opaque id),
    so the value must actually look temporal. A small integer (`page`, `limit`) is
    NOT a timestamp.
    """

    if not value:
        return False
    v = value.strip()
    if v.isdigit():
        n = int(v)
        if _EPOCH_SECONDS_MIN <= n <= _EPOCH_SECONDS_MAX:
            return True
        if _EPOCH_MILLIS_MIN <= n <= _EPOCH_MILLIS_MAX:
            return True
        return False
    return bool(_ISO8601_RE.match(v))


# ---------------------------------------------------------------------------
# Name heuristics, per role. Sep/case-insensitive (operate on `_normalize_name`).
# ---------------------------------------------------------------------------

# CSRF / XSRF / anti-forgery token names (Django, Rails, ASP.NET, Spring, ...).
_CSRF_NAMES: frozenset[str] = frozenset(
    {
        "csrf",
        "csrftoken",
        "xsrf",
        "xsrftoken",
        "_csrf",
        "csrfmiddlewaretoken",
        "authenticitytoken",
        "antiforgerytoken",
        "requestverificationtoken",
        "xcsrftoken",
        "xxsrftoken",
    }
)
# Header conventions an app uses to carry the CSRF token.
_CSRF_HEADER_NAMES: frozenset[str] = frozenset(
    {"xcsrftoken", "xxsrftoken", "csrftoken", "xcsrf", "xxsrf"}
)

# Exact signature names; plus a `sign` substring catch (`sign`, `signed_request`).
_SIGNATURE_NAMES: frozenset[str] = frozenset(
    {"sig", "signature", "hmac", "mac", "sign"}
)

# Timestamp names — name is necessary but NOT sufficient (value must look temporal).
_TIMESTAMP_NAMES: frozenset[str] = frozenset(
    {"timestamp", "ts", "_ts", "time", "expires", "exp", "date", "expiry", "expiresat"}
)


def _is_csrf(field: HazardField, norm: str) -> bool:
    if norm in _CSRF_NAMES:
        return True
    if "csrf" in norm or "xsrf" in norm:
        return True
    if "authenticitytoken" in norm or "antiforgery" in norm:
        return True
    if field.is_header and norm in _CSRF_HEADER_NAMES:
        return True
    return False


def _is_nonce(field: HazardField, norm: str) -> bool:
    # `nonce` is high-signal by name; corroborate with a high-entropy value when
    # present, but accept name-only (the value is frequently hash-only / absent).
    if "nonce" not in norm:
        return False
    if field.value is None:
        return True
    return _looks_high_entropy(field.value) or len(field.value) >= 8


# `sign`-substring false friends: names that contain "sign" / end in "sign" but
# are not request signatures (so a MAC-shaped value does not rescue them either).
_SIGNATURE_FALSE_FRIENDS: frozenset[str] = frozenset(
    {"assignee", "design", "designation", "assigned", "assign", "redesign"}
)


def _is_signature(field: HazardField, norm: str) -> bool:
    if norm in _SIGNATURE_NAMES:
        return True
    if norm in _SIGNATURE_FALSE_FRIENDS:
        return False
    # `sign` substring is broad, so beyond the exact name set it only matches when
    # the value is actually MAC-shaped (base64/hex) — keeping `assignee` / `design`
    # and other incidental "sign" names from tripping.
    if "signature" in norm or "hmac" in norm or norm.endswith("sign"):
        return _looks_signature(field.value)
    return False


def _is_timestamp(field: HazardField, norm: str) -> bool:
    # Name is necessary but not sufficient: the value must actually look temporal,
    # so an opaque `ts` cookie or `exp`-named uuid does not false-positive.
    if norm not in _TIMESTAMP_NAMES:
        return False
    return _looks_timestamp(field.value)


def _classify(field: HazardField) -> ReplayHazardRole | None:
    """Classify one field into a single replay-hazard role, or None (ordinary).

    Checked in priority order; the first match wins. CSRF is most specific (a
    dedicated token name), then signature, then nonce, then timestamp.
    """

    norm = _normalize_name(field.name)
    if not norm:
        return None
    if _is_csrf(field, norm):
        return "csrf_token"
    if _is_signature(field, norm):
        return "signature"
    if _is_nonce(field, norm):
        return "nonce"
    if _is_timestamp(field, norm):
        return "timestamp"
    return None


_ROLE_ORDER = {role: i for i, role in enumerate(REPLAY_HAZARD_ROLES)}


def detect_replay_hazards(fields: tuple[HazardField, ...]) -> tuple[ReplayHazardRole, ...]:
    """The sorted, de-duplicated replay-hazard roles across a request's fields.

    Pure deterministic heuristics over `fields` (ADR-0041) — no graph, no LLM, so
    it is unit-testable in isolation. Ordinary params (`id`, `page`, `q`, `name`)
    classify to no role. Returns the roles in `REPLAY_HAZARD_ROLES` order.
    """

    found: set[ReplayHazardRole] = set()
    for field in fields:
        role = _classify(field)
        if role is not None:
            found.add(role)
    return tuple(sorted(found, key=lambda r: _ROLE_ORDER[r]))


def hazards_for_value_candidates(
    candidates: tuple[ValueCandidate, ...],
) -> tuple[ReplayHazardRole, ...]:
    """Detect replay hazards from an observation's parsed `value_candidates`.

    Adapts the graph's stored input fields into `HazardField`s and runs the
    detector. Only `input`-role candidates are request fields (the replay-relevant
    side); `output` candidates are response values and are ignored. A header-borne
    candidate (`section == "header"`) is adapted with its `header_name` and the
    header flag set so the CSRF header conventions (`X-CSRF-Token`) match.

    A secret-shaped candidate carries `value = None` (ADR-0015); the name still
    drives detection (CSRF / nonce by name), which is exactly the design intent.
    """

    fields: list[HazardField] = []
    for vc in candidates:
        if vc.role != "input":
            continue
        is_header = vc.section == "header"
        name = vc.header_name if is_header else vc.parameter_name
        if not name:
            continue
        fields.append(HazardField(name=name, value=vc.value, is_header=is_header))
    return detect_replay_hazards(tuple(fields))


def source_hints_for_value_candidates(
    candidates: tuple[ValueCandidate, ...],
) -> tuple[str, ...]:
    """`source_hint`s (`"<kind>=<url>"`) for hazards a refresh can resolve (ADR-0041).

    For `csrf_token`, the hint is the page the token was carried *from* — the
    request's `Referer` header (the form/page that minted the token). Slice-4's
    resolver fetches it under the test's auth to splice a fresh token. Returns an
    empty tuple when there is no CSRF hazard or no observed `Referer`. Other kinds
    (`nonce` strip / `timestamp` now) need no hint, so none is emitted for them.
    """

    if "csrf_token" not in hazards_for_value_candidates(candidates):
        return ()
    referer = next(
        (
            vc.value
            for vc in candidates
            if vc.role == "input"
            and vc.section == "header"
            and (vc.header_name or "").lower() == "referer"
            and vc.value
        ),
        None,
    )
    return (f"csrf_token={referer}",) if referer else ()
