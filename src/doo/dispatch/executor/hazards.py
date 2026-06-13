"""Replay-hazard resolvers (ADR-0041/0043): make a verbatim authz replay valid.

A slice-3 authz test replays an evidencing observation under swapped auth. If the
original request carried a **replay-breaker** — a CSRF token, nonce, signature, or
timestamp bound to the original session — a verbatim replay trips it and the app
answers 4xx for a *non-authz* reason: a false "boundary held" (the worst outcome).
Slice 3 only *flagged* these (`replay_hazards` on the TestCase, ADR-0041); slice 4
*resolves* them here, per `kind`:

- `csrf_token` → fetch a `source_hint` page under the test's auth (a real
  `hazard_warmup` send), extract the fresh token by its param name, splice it in.
- `nonce` → strip the param (a fresh request gets a fresh nonce server-side).
- `timestamp` → set it to now.
- `signature` → **no resolver** (cannot recompute a server-side MAC) → unresolved.

Resolvers are **pure** given an injected `fetch` (so they are network-free in
tests); the run driver supplies a `fetch` backed by the Dispatcher gate. A failed
resolve (`signature`, missing `source_hint`, extraction miss) returns `Unresolved`
and the run driver refuses the `primary` send (`RunOutcome = hazard_unresolved`),
surfacing it in `doo dispatch review` for the tester to supply a hint, mark the
hazard ignorable, or reject the test.

Locating WHICH field carries the hazard reuses the slice-3 detector's name
heuristics (`planner.replay_hazards`) against the evidence — only the hazard
*kinds* are persisted on the TestCase, not the field names.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from doo.dispatch.executor.evidence import EvidenceObservation
from doo.dispatch.executor.send import HttpResponse
from doo.observability.logging import get_logger
from doo.planner.models import ReplayHazardRole
from doo.planner.replay_hazards import HazardField, _classify

log = get_logger(__name__)

# Where in the request a hazard field lives (mirrors the evidence projection).
FieldSection = Literal["query", "header", "cookie"]

# A `fetch` is `(method, path) → response | None`; the run driver backs it with a
# `hazard_warmup` Dispatcher send. `None` ⇒ the warmup did not reach the wire
# (gate-blocked / transport error) — treated as an extraction failure.
FetchFn = Callable[[str, str], HttpResponse | None]


@dataclass(frozen=True, slots=True)
class HazardSplice:
    """A deterministic edit applied to the evidence before constructing `primary`.

    `value is None` ⇒ **strip** the named field (the `nonce` case); otherwise set
    it to `value` (a fresh CSRF token / current timestamp).
    """

    section: FieldSection
    name: str
    value: str | None


@dataclass(frozen=True, slots=True)
class Resolved:
    """The hazard was resolved: apply these splices to the evidence."""

    splices: tuple[HazardSplice, ...]


@dataclass(frozen=True, slots=True)
class Unresolved:
    """The hazard could not be resolved — the run refuses the `primary` send."""

    kind: str
    param: str
    reason: str


HazardResolution = Resolved | Unresolved


@dataclass(frozen=True, slots=True)
class LocatedHazard:
    """A hazard kind matched to a concrete evidence field."""

    kind: ReplayHazardRole
    section: FieldSection
    name: str


def locate_hazard(
    kind: ReplayHazardRole, evidence: EvidenceObservation
) -> LocatedHazard | None:
    """Find the evidence field carrying `kind` via the slice-3 name heuristics.

    Scans query → header → cookie, returning the first field the detector
    classifies as `kind`. `None` when no field matches (the hazard was detected on
    a different observation than the one resolved here).
    """

    sections: tuple[tuple[FieldSection, dict[str, str]], ...] = (
        ("query", evidence.query),
        ("header", evidence.headers),
        ("cookie", evidence.cookies),
    )
    for section, fields in sections:
        for name, value in fields.items():
            field = HazardField(name=name, value=value, is_header=(section == "header"))
            if _classify(field) == kind:
                return LocatedHazard(kind=kind, section=section, name=name)
    return None


# ---------------------------------------------------------------------------
# CSRF token extraction from a fetched page (HTML form / meta tag / JSON).
# ---------------------------------------------------------------------------


def extract_csrf_token(body: bytes, param_name: str) -> str | None:
    """Pull a fresh CSRF token named `param_name` out of a fetched page body.

    Tries, in order: a hidden form input (`name`/`value` either order), a
    `<meta name="…-token" content="…">` tag, and a JSON `"name": "value"` pair.
    Deterministic regex (no LLM, no full DOM parse) — conservative, returns the
    first match or `None`.
    """

    text = body.decode("utf-8", errors="replace")
    n = re.escape(param_name)
    patterns = (
        # <input ... name="_csrf" ... value="TOKEN" ...>
        rf'<input[^>]*\bname=["\']?{n}["\']?[^>]*\bvalue=["\']([^"\']+)["\']',
        # <input ... value="TOKEN" ... name="_csrf" ...> (reverse order)
        rf'<input[^>]*\bvalue=["\']([^"\']+)["\'][^>]*\bname=["\']?{n}["\']?',
        # <meta name="csrf-token" content="TOKEN"> (param name OR csrf-token)
        rf'<meta[^>]*\bname=["\'](?:{n}|csrf-token)["\'][^>]*\bcontent=["\']([^"\']+)["\']',
        # "_csrf": "TOKEN"  (JSON / inline JS)
        rf'["\']{n}["\']\s*:\s*["\']([^"\']+)["\']',
    )
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Per-kind resolvers.
# ---------------------------------------------------------------------------


def _resolve_csrf(
    located: LocatedHazard, *, source_hint: str | None, fetch: FetchFn
) -> HazardResolution:
    if not source_hint:
        return Unresolved(
            kind="csrf_token",
            param=located.name,
            reason=(
                "no source_hint to fetch a fresh CSRF token from; supply one via "
                "`doo dispatch review --set-hint <key_hash> csrf_token <url>`"
            ),
        )
    method, path = _split_hint(source_hint)
    response = fetch(method, path)
    if response is None:
        return Unresolved(
            kind="csrf_token",
            param=located.name,
            reason=f"warmup fetch of {source_hint!r} did not reach the wire "
            "(gate-blocked or transport error)",
        )
    token = extract_csrf_token(response.body, located.name)
    if token is None:
        return Unresolved(
            kind="csrf_token",
            param=located.name,
            reason=f"no token named {located.name!r} found in the {source_hint!r} "
            f"page body (HTTP {response.status})",
        )
    return Resolved((HazardSplice(section=located.section, name=located.name, value=token),))


def _resolve_nonce(located: LocatedHazard) -> HazardResolution:
    # A fresh request mints a fresh nonce server-side; strip the stale one.
    return Resolved((HazardSplice(section=located.section, name=located.name, value=None),))


def _resolve_timestamp(located: LocatedHazard) -> HazardResolution:
    now_epoch = str(int(datetime.now(UTC).timestamp()))
    return Resolved(
        (HazardSplice(section=located.section, name=located.name, value=now_epoch),)
    )


def _resolve_signature(located: LocatedHazard) -> HazardResolution:
    return Unresolved(
        kind="signature",
        param=located.name,
        reason="request signatures are a server-side MAC over the request and "
        "cannot be recomputed black-box; mark ignorable to send anyway "
        "(accept replay_invalid risk) or reject the test",
    )


def resolve_hazard(
    located: LocatedHazard, *, source_hint: str | None, fetch: FetchFn
) -> HazardResolution:
    """Resolve one located hazard to splices (or an `Unresolved` reason)."""

    if located.kind == "csrf_token":
        return _resolve_csrf(located, source_hint=source_hint, fetch=fetch)
    if located.kind == "nonce":
        return _resolve_nonce(located)
    if located.kind == "timestamp":
        return _resolve_timestamp(located)
    return _resolve_signature(located)


def _split_hint(source_hint: str) -> tuple[str, str]:
    """Parse a `source_hint` into `(method, path)`.

    Accepts `"GET /orders/new"`, a bare path `"/orders/new"` (defaults GET), or an
    absolute URL (the path component is taken; the warmup reuses the evidence host).
    """

    hint = source_hint.strip()
    parts = hint.split(None, 1)
    if len(parts) == 2 and parts[0].isalpha() and parts[0].isupper():
        method, rest = parts[0], parts[1].strip()
    else:
        method, rest = "GET", hint
    if "://" in rest:
        # Absolute URL → take the path (+ query); the warmup uses the evidence host.
        rest = "/" + rest.split("://", 1)[1].split("/", 1)[1] if "/" in rest.split("://", 1)[1] else "/"
    if not rest.startswith("/"):
        rest = "/" + rest
    return method, rest


def apply_splices(
    evidence: EvidenceObservation, splices: tuple[HazardSplice, ...]
) -> EvidenceObservation:
    """Return a copy of `evidence` with the resolved hazard splices applied."""

    import dataclasses

    query = dict(evidence.query)
    headers = dict(evidence.headers)
    cookies = dict(evidence.cookies)
    bucket = {"query": query, "header": headers, "cookie": cookies}
    for sp in splices:
        target = bucket[sp.section]
        if sp.value is None:
            target.pop(sp.name, None)
        else:
            target[sp.name] = sp.value
    return dataclasses.replace(evidence, query=query, headers=headers, cookies=cookies)


__all__ = [
    "FieldSection",
    "FetchFn",
    "HazardSplice",
    "Resolved",
    "Unresolved",
    "HazardResolution",
    "LocatedHazard",
    "locate_hazard",
    "extract_csrf_token",
    "resolve_hazard",
    "apply_splices",
]
