"""Coverage warns when an engagement scope matches zero in-scope nodes (#55, ADR-0035).

Defense in depth behind the loader's regex rejection: even if a misconfigured
scope slips through (a host/path that names nothing real), a coverage query that
matches zero of a non-empty graph emits a structured `coverage.scope_matched_nothing`
warning instead of silently returning an empty result with exit 0.

Driven against a fake Neo4j client (no containers), mirroring
`test_coverage_c1_unit.py`. Logs are captured with `structlog.testing.capture_logs`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import structlog

from doo.coverage.queries import run_c1, run_c2, run_c2b, run_c3
from doo.ids import EngagementId

_NOW = datetime(2026, 6, 1, tzinfo=UTC)

# A scope whose single host matches NOTHING in the graph below (the graph only
# has shop.example.com endpoints).
_SCOPE_MATCHES_NOTHING = {
    "host_patterns": ["unrelated.example.org"],
    "allowed_methods": ["GET"],
    "allowed_path_patterns": ["/**"],
    "payload_class_denylist": [],
    "rate_limit": None,
    "time_window": None,
    "required_headers": [],
}

# A scope that DOES match the graph endpoints — no warning expected.
_SCOPE_MATCHES = {
    **_SCOPE_MATCHES_NOTHING,
    "host_patterns": ["shop.example.com"],
}


def _endpoint_row(
    *, endpoint_id: str, path_template: str, has_hit: bool = False
) -> dict[str, Any]:
    return {
        "endpoint_id": endpoint_id,
        "method": "GET",
        "path_template": path_template,
        "confidence": 1.0,
        "last_seen": _NOW,
        "scheme": "https",
        "canonical_hostname": "shop.example.com",
        "port": None,
        "is_ip_literal": False,
        "has_hit": has_hit,
    }


class _FakeClient:
    """Returns scope rows on the scope query, endpoint rows on endpoint queries,
    and empty for everything else (principals, reached, C3 traversal)."""

    def __init__(self, *, scope: dict[str, Any], endpoint_rows: list[dict[str, Any]]) -> None:
        self._scope = scope
        self._endpoint_rows = endpoint_rows

    def execute_read(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
        if "UNDER_SCOPE" in cypher:
            return [{"rules": json.dumps(self._scope)}]
        if ":Endpoint" in cypher and "ON_HOST" in cypher and "ObservedValue" not in cypher:
            return self._endpoint_rows
        if ":ObservedValue" in cypher:
            # C3 traversal: one pivot whose target endpoint is shop.example.com.
            return [
                {
                    "value_hash": "h",
                    "kind": "identifier",
                    "value": "42",
                    "value_preview": None,
                    "confidence": 1.0,
                    "last_seen": _NOW,
                    "target_endpoint_id": "ep-1",
                    "target_method": "GET",
                    "target_path_template": "/orders/{id}",
                    "scheme": "https",
                    "canonical_hostname": "shop.example.com",
                    "port": None,
                    "is_ip_literal": False,
                    "parameter_name": "id",
                    "source_endpoints": [
                        {
                            "endpoint_id": "ep-src",
                            "method": "GET",
                            "path_template": "/me",
                            "scheme": "https",
                            "canonical_hostname": "shop.example.com",
                            "port": None,
                            "is_ip_literal": False,
                        }
                    ],
                }
            ]
        # principals / reached / anything else.
        return []


def _warned(events: list[dict[str, Any]]) -> bool:
    return any(e.get("event") == "coverage.scope_matched_nothing" for e in events)


def _eid() -> EngagementId:
    return EngagementId("eng-warn")


def test_c1_warns_when_scope_matches_nothing() -> None:
    rows = [_endpoint_row(endpoint_id="ep-1", path_template="/orders/{id}")]
    client = _FakeClient(scope=_SCOPE_MATCHES_NOTHING, endpoint_rows=rows)
    with structlog.testing.capture_logs() as caplog:
        out = run_c1(client, _eid(), now=_NOW)  # type: ignore[arg-type]
    assert out == []  # the silent-empty-result shape we are surfacing
    assert _warned(caplog)


def test_c1_does_not_warn_when_scope_matches() -> None:
    rows = [_endpoint_row(endpoint_id="ep-1", path_template="/orders/{id}")]
    client = _FakeClient(scope=_SCOPE_MATCHES, endpoint_rows=rows)
    with structlog.testing.capture_logs() as caplog:
        run_c1(client, _eid(), now=_NOW)  # type: ignore[arg-type]
    assert not _warned(caplog)


def test_c1_does_not_warn_on_empty_graph() -> None:
    # No endpoints at all: zero in-scope is expected, not a misconfiguration.
    client = _FakeClient(scope=_SCOPE_MATCHES_NOTHING, endpoint_rows=[])
    with structlog.testing.capture_logs() as caplog:
        run_c1(client, _eid(), now=_NOW)  # type: ignore[arg-type]
    assert not _warned(caplog)


def test_c2_warns_when_scope_matches_nothing() -> None:
    rows = [_endpoint_row(endpoint_id="ep-1", path_template="/orders/{id}")]
    client = _FakeClient(scope=_SCOPE_MATCHES_NOTHING, endpoint_rows=rows)
    with structlog.testing.capture_logs() as caplog:
        run_c2(client, _eid(), now=_NOW)  # type: ignore[arg-type]
    assert _warned(caplog)


def test_c2b_warns_when_scope_matches_nothing() -> None:
    rows = [_endpoint_row(endpoint_id="ep-1", path_template="/orders/{id}")]
    client = _FakeClient(scope=_SCOPE_MATCHES_NOTHING, endpoint_rows=rows)
    with structlog.testing.capture_logs() as caplog:
        run_c2b(client, _eid(), now=_NOW)  # type: ignore[arg-type]
    assert _warned(caplog)


def test_c3_warns_when_scope_matches_nothing() -> None:
    # C3 now derives the warning from the full active-endpoint set (merged_bug_002),
    # so it fires even with zero pivots as long as the graph has endpoints.
    rows = [_endpoint_row(endpoint_id="ep-1", path_template="/orders/{id}")]
    client = _FakeClient(scope=_SCOPE_MATCHES_NOTHING, endpoint_rows=rows)
    with structlog.testing.capture_logs() as caplog:
        out = run_c3(client, _eid(), now=_NOW)  # type: ignore[arg-type]
    assert out == []  # target out of scope → no pivots surface
    assert _warned(caplog)


def test_c3_does_not_warn_when_target_in_scope() -> None:
    rows = [_endpoint_row(endpoint_id="ep-1", path_template="/orders/{id}")]
    client = _FakeClient(scope=_SCOPE_MATCHES, endpoint_rows=rows)
    with structlog.testing.capture_logs() as caplog:
        run_c3(client, _eid(), now=_NOW)  # type: ignore[arg-type]
    assert not _warned(caplog)
