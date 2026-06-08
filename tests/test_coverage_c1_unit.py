"""Unit tests for C1 (`run_c1`) — no containers.

Drives `run_c1` against a fake Neo4j client that returns canned traversal rows,
so the Python-side judgement (scope filter, any-HIT asymmetry per ADR-0033,
confidence decay per ADR-0005, `--min-confidence` filtering) is tested in
isolation from a live graph. The golden e2e (`test_coverage_c1_e2e.py`) covers
the real pipeline + Cypher.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from doo.coverage.queries import run_c1
from doo.ids import EngagementId

_NOW = datetime(2026, 6, 1, tzinfo=UTC)

# A scope that includes shop.example.com over GET on any path; everything else
# (e.g. sso.evil.test) is out of scope.
_SCOPE_RULES = {
    "host_patterns": ["shop.example.com"],
    "allowed_methods": ["GET"],
    "allowed_path_patterns": ["/**"],
    "payload_class_denylist": [],
    "rate_limit": None,
    "time_window": None,
    "required_headers": [],
}


def _endpoint_row(
    *,
    endpoint_id: str,
    path_template: str,
    has_hit: bool,
    host: str = "shop.example.com",
    method: str = "GET",
    confidence: float = 1.0,
    last_seen: datetime = _NOW,
) -> dict[str, Any]:
    return {
        "endpoint_id": endpoint_id,
        "method": method,
        "path_template": path_template,
        "confidence": confidence,
        "last_seen": last_seen,
        "scheme": "https",
        "canonical_hostname": host,
        "port": None,
        "is_ip_literal": False,
        "has_hit": has_hit,
    }


class _FakeClient:
    """Returns the scope rows on the scope query and endpoint rows otherwise."""

    def __init__(self, endpoint_rows: list[dict[str, Any]]) -> None:
        self._endpoint_rows = endpoint_rows

    def execute_read(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
        if "UNDER_SCOPE" in cypher:
            return [{"rules": json.dumps(_SCOPE_RULES)}]
        return self._endpoint_rows


def _run(rows: list[dict[str, Any]], **kw: Any) -> list:
    client = _FakeClient(rows)
    return run_c1(client, EngagementId("eng-unit"), now=_NOW, **kw)  # type: ignore[arg-type]


def test_in_scope_never_hit_endpoint_is_dead() -> None:
    rows = [_endpoint_row(endpoint_id="ep-dead", path_template="/admin", has_hit=False)]
    out = _run(rows)
    assert [r.endpoint_id for r in out] == ["ep-dead"]
    assert out[0].method == "GET"
    assert out[0].host == "shop.example.com"
    assert out[0].path_template == "/admin"
    assert out[0].query_id == "C1"


def test_any_hit_means_not_dead_even_a_401() -> None:
    # ADR-0033: C1's "hit" counts ANY HIT edge regardless of response status.
    # The traversal already collapses that to a boolean `has_hit`; a 401-touched
    # endpoint arrives as has_hit=True and must NOT be reported.
    rows = [_endpoint_row(endpoint_id="ep-401", path_template="/touched", has_hit=True)]
    assert _run(rows) == []


def test_out_of_scope_never_hit_endpoint_is_excluded() -> None:
    rows = [
        _endpoint_row(
            endpoint_id="ep-oos",
            path_template="/login",
            has_hit=False,
            host="sso.evil.test",
        )
    ]
    assert _run(rows) == []


def test_min_confidence_filters_decayed_rows() -> None:
    # last_seen 60 days ago + 30-day half-life => effective ~= 0.25 of stored.
    old = _NOW - timedelta(days=60)
    rows = [
        _endpoint_row(
            endpoint_id="ep-stale",
            path_template="/stale",
            has_hit=False,
            confidence=1.0,
            last_seen=old,
        )
    ]
    # Default min_confidence=0 surfaces it (never silently hidden).
    surfaced = _run(rows)
    assert len(surfaced) == 1
    assert abs(surfaced[0].effective_confidence - 0.25) < 1e-9

    # A threshold above the decayed value drops it.
    assert _run(rows, min_confidence=0.5) == []
    # A threshold below it keeps it.
    assert len(_run(rows, min_confidence=0.2)) == 1


def test_mixed_set_returns_only_in_scope_dead_endpoints() -> None:
    rows = [
        _endpoint_row(endpoint_id="ep-hit", path_template="/products", has_hit=True),
        _endpoint_row(endpoint_id="ep-dead", path_template="/admin", has_hit=False),
        _endpoint_row(
            endpoint_id="ep-oos",
            path_template="/x",
            has_hit=False,
            host="other.test",
        ),
    ]
    out = _run(rows)
    assert [r.endpoint_id for r in out] == ["ep-dead"]


def test_json_round_trips_the_typed_model() -> None:
    from doo.coverage.models import C1Result

    rows = [_endpoint_row(endpoint_id="ep-dead", path_template="/admin", has_hit=False)]
    out = _run(rows)
    dumped = out[0].model_dump_json()
    restored = C1Result.model_validate_json(dumped)
    assert restored == out[0]
