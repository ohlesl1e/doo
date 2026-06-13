"""Replay-hazard resolver unit tests (S5/#90, ADR-0041).

Per-kind `resolve_hazard` with a stubbed `fetch` (network-free): csrf
fetch+extract+splice, nonce strip, timestamp now, signature unresolved; plus
`locate_hazard`, `extract_csrf_token`, and `apply_splices`.
"""

from __future__ import annotations

from doo.canonical.value_objects import HostRef
from doo.dispatch.executor.evidence import EvidenceObservation
from doo.dispatch.executor.hazards import (
    LocatedHazard,
    Resolved,
    Unresolved,
    apply_splices,
    extract_csrf_token,
    locate_hazard,
    resolve_hazard,
)
from doo.dispatch.executor.send import HttpResponse

HOST = HostRef(scheme="https", canonical_hostname="shop.example.com", port=None, is_ip_literal=False)


def _evidence(**kw: object) -> EvidenceObservation:
    base: dict[str, object] = dict(
        observation_id="obs-1",
        method="POST",
        host=HOST,
        concrete_path="/orders",
        path_template="/orders",
    )
    base.update(kw)
    return EvidenceObservation(**base)  # type: ignore[arg-type]


# --- locate_hazard ---------------------------------------------------------


def test_locate_csrf_in_query() -> None:
    ev = _evidence(query={"_csrf": "stale-tok", "page": "1"})
    located = locate_hazard("csrf_token", ev)
    assert located == LocatedHazard(kind="csrf_token", section="query", name="_csrf")


def test_locate_csrf_in_header() -> None:
    ev = _evidence(headers={"X-CSRF-Token": "stale", "Accept": "*/*"})
    located = locate_hazard("csrf_token", ev)
    assert located is not None
    assert located.section == "header" and located.name == "X-CSRF-Token"


def test_locate_returns_none_when_absent() -> None:
    assert locate_hazard("csrf_token", _evidence(query={"page": "1"})) is None


# --- extract_csrf_token ----------------------------------------------------


def test_extract_from_hidden_input_both_orders() -> None:
    body_a = b'<form><input type="hidden" name="_csrf" value="TOKEN-A"></form>'
    body_b = b'<form><input value="TOKEN-B" name="_csrf" type="hidden"></form>'
    assert extract_csrf_token(body_a, "_csrf") == "TOKEN-A"
    assert extract_csrf_token(body_b, "_csrf") == "TOKEN-B"


def test_extract_from_meta_tag() -> None:
    body = b'<head><meta name="csrf-token" content="META-TOK"></head>'
    assert extract_csrf_token(body, "_csrf") == "META-TOK"


def test_extract_from_json() -> None:
    body = b'{"_csrf":"JSON-TOK","other":1}'
    assert extract_csrf_token(body, "_csrf") == "JSON-TOK"


def test_extract_miss_returns_none() -> None:
    assert extract_csrf_token(b"<html>nothing here</html>", "_csrf") is None


# --- resolve_hazard --------------------------------------------------------


def _located(kind: str, *, section: str = "query", name: str = "_csrf") -> LocatedHazard:
    return LocatedHazard(kind=kind, section=section, name=name)  # type: ignore[arg-type]


def test_resolve_csrf_fetches_and_splices() -> None:
    page = HttpResponse(status=200, body=b'<input name="_csrf" value="FRESH">')
    calls: list[tuple[str, str]] = []

    def fetch(method: str, path: str) -> HttpResponse:
        calls.append((method, path))
        return page

    res = resolve_hazard(_located("csrf_token"), source_hint="GET /orders/new", fetch=fetch)
    assert isinstance(res, Resolved)
    assert calls == [("GET", "/orders/new")]
    sp = res.splices[0]
    assert (sp.section, sp.name, sp.value) == ("query", "_csrf", "FRESH")


def test_resolve_csrf_no_hint_unresolved() -> None:
    res = resolve_hazard(_located("csrf_token"), source_hint=None, fetch=lambda m, p: None)
    assert isinstance(res, Unresolved) and "source_hint" in res.reason


def test_resolve_csrf_fetch_none_unresolved() -> None:
    res = resolve_hazard(_located("csrf_token"), source_hint="/x", fetch=lambda m, p: None)
    assert isinstance(res, Unresolved) and "did not reach" in res.reason


def test_resolve_csrf_extraction_miss_unresolved() -> None:
    page = HttpResponse(status=200, body=b"<html>no token</html>")
    res = resolve_hazard(_located("csrf_token"), source_hint="/x", fetch=lambda m, p: page)
    assert isinstance(res, Unresolved) and "no token named" in res.reason


def test_resolve_nonce_strips() -> None:
    res = resolve_hazard(_located("nonce", name="nonce"), source_hint=None, fetch=lambda m, p: None)
    assert isinstance(res, Resolved)
    assert res.splices[0].value is None and res.splices[0].name == "nonce"


def test_resolve_timestamp_sets_now() -> None:
    res = resolve_hazard(_located("timestamp", name="ts"), source_hint=None, fetch=lambda m, p: None)
    assert isinstance(res, Resolved)
    assert res.splices[0].value is not None and res.splices[0].value.isdigit()


def test_resolve_signature_unresolved() -> None:
    res = resolve_hazard(_located("signature", name="sig"), source_hint=None, fetch=lambda m, p: None)
    assert isinstance(res, Unresolved) and res.kind == "signature"


# --- apply_splices ---------------------------------------------------------


def test_apply_splices_set_and_strip() -> None:
    from doo.dispatch.executor.hazards import HazardSplice

    ev = _evidence(
        query={"_csrf": "old", "nonce": "n", "page": "1"},
        headers={"X-CSRF-Token": "h-old"},
    )
    adjusted = apply_splices(
        ev,
        (
            HazardSplice(section="query", name="_csrf", value="NEW"),
            HazardSplice(section="query", name="nonce", value=None),
            HazardSplice(section="header", name="X-CSRF-Token", value="H-NEW"),
        ),
    )
    assert adjusted.query == {"_csrf": "NEW", "page": "1"}  # nonce stripped
    assert adjusted.headers == {"X-CSRF-Token": "H-NEW"}
    # original untouched (pure copy)
    assert ev.query["_csrf"] == "old" and "nonce" in ev.query
