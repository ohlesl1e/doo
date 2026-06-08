"""Unit tests for C3 (`run_c3`) — no containers.

Drives `run_c3` against a fake Neo4j client that answers the two reads
(`Scope.rules`, the `ObservedValue` leak-to-input traversal) with canned rows, so
the Python-side pivot logic — cross-endpoint default, `--include-same-endpoint`,
target-in-scope filtering (source need not be), secret-shaped hash+preview-only
surfacing, shape-rank ordering, decay / `--min-confidence`, JSON round-trip — is
tested in isolation. The golden e2e (`test_coverage_c3_e2e.py`) covers the real
pipeline + Cypher.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from doo.coverage.queries import run_c3
from doo.ids import EngagementId

_EID = EngagementId("eng-c3-unit")
_NOW = datetime(2026, 6, 1, tzinfo=UTC)

_SCOPE_RULES = {
    "host_patterns": ["shop.example.com"],
    "allowed_methods": ["*"],
    "allowed_path_patterns": ["/**"],
    "payload_class_denylist": [],
    "rate_limit": None,
    "time_window": None,
    "required_headers": [],
}


def _src(
    endpoint_id: str, *, method: str = "GET", path: str, host: str = "shop.example.com"
) -> dict[str, Any]:
    return {
        "endpoint_id": endpoint_id,
        "method": method,
        "path_template": path,
        "scheme": "https",
        "canonical_hostname": host,
        "port": None,
        "is_ip_literal": False,
    }


def _pivot_row(
    *,
    value_hash: str = "h-uuid",
    kind: str = "identifier",
    value: str | None = "11111111-2222-3333-4444-555555555555",
    value_preview: str | None = "11111111",
    confidence: float = 1.0,
    last_seen: datetime = _NOW,
    target_endpoint_id: str = "eTarget",
    target_method: str = "GET",
    target_path: str = "/widget-detail",
    host: str = "shop.example.com",
    parameter_name: str | None = "widget_id",
    source_endpoints: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "value_hash": value_hash,
        "kind": kind,
        "value": value,
        "value_preview": value_preview,
        "confidence": confidence,
        "last_seen": last_seen,
        "target_endpoint_id": target_endpoint_id,
        "target_method": target_method,
        "target_path_template": target_path,
        "scheme": "https",
        "canonical_hostname": host,
        "port": None,
        "is_ip_literal": False,
        "parameter_name": parameter_name,
        "source_endpoints": source_endpoints
        if source_endpoints is not None
        else [_src("eSource", path="/widgets")],
    }


class _FakeClient:
    """Routes each coverage read to its canned rows by query content."""

    def __init__(self, *, pivots: list[dict[str, Any]]) -> None:
        self._pivots = pivots

    def execute_read(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
        if "UNDER_SCOPE" in cypher:
            return [{"rules": json.dumps(_SCOPE_RULES)}]
        if "YIELDED_VALUE" in cypher and "SENT_VALUE" in cypher:
            return self._pivots
        # `_load_in_scope_endpoints` (the zero-match-warning side-channel) — these
        # unit tests don't exercise the warning, so an empty endpoint set is fine.
        if "Endpoint)-[:ON_HOST]" in cypher:
            return []
        raise AssertionError(f"unexpected query: {cypher[:80]!r}")


def _run(**kw: Any):  # type: ignore[no-untyped-def]
    client = _FakeClient(pivots=kw.pop("pivots"))
    return run_c3(client, _EID, now=_NOW, **kw)  # type: ignore[arg-type]


def test_cross_endpoint_pivot_is_surfaced() -> None:
    out = _run(pivots=[_pivot_row()])
    assert len(out) == 1
    row = out[0]
    assert row.value_hash == "h-uuid"
    assert row.target_path_template == "/widget-detail"
    assert row.parameter_name == "widget_id"
    assert row.source_endpoints == ("GET shop.example.com /widgets",)
    assert row.same_endpoint is False


def test_same_endpoint_reuse_excluded_by_default_included_with_flag() -> None:
    # The value's only source endpoint IS the target endpoint -> same-endpoint reuse.
    pivot = _pivot_row(
        source_endpoints=[_src("eTarget", path="/widget-detail")],
    )
    assert _run(pivots=[pivot]) == []  # excluded by default
    out = _run(pivots=[pivot], include_same_endpoint=True)
    assert len(out) == 1
    assert out[0].same_endpoint is True
    assert out[0].source_endpoints == ("GET shop.example.com /widget-detail",)


def test_mixed_sources_keep_cross_endpoint_only() -> None:
    # One cross-endpoint source + one same-endpoint source -> cross-endpoint kept,
    # same-endpoint source dropped, even without the flag.
    pivot = _pivot_row(
        source_endpoints=[
            _src("eSource", path="/widgets"),
            _src("eTarget", path="/widget-detail"),
        ],
    )
    out = _run(pivots=[pivot])
    assert len(out) == 1
    assert out[0].source_endpoints == ("GET shop.example.com /widgets",)
    assert out[0].same_endpoint is False


def test_target_out_of_scope_excluded() -> None:
    out = _run(pivots=[_pivot_row(host="evil.test")])
    assert out == []


def test_source_out_of_scope_still_surfaces() -> None:
    # The source host need not be in scope (ADR-0020): the target stays in scope,
    # so the pivot is a valid lead. The source label carries its own host.
    out = _run(
        pivots=[
            _pivot_row(
                source_endpoints=[
                    _src(
                        "eSso", method="POST", path="/sso/callback",
                        host="idp.external.example",
                    )
                ]
            )
        ]
    )
    assert len(out) == 1
    assert out[0].source_endpoints == ("POST idp.external.example /sso/callback",)


def test_source_endpoints_distinguish_distinct_hosts() -> None:
    # Same method+path on two different hosts must NOT collapse — the host is the
    # actionable signal (internal-leak vs federated-SSO). Two distinct labels.
    pivot = _pivot_row(
        source_endpoints=[
            _src("eInt", method="GET", path="/me", host="internal-billing.corp.example"),
            _src("ePub", method="GET", path="/me", host="api.public.example"),
        ],
    )
    out = _run(pivots=[pivot])
    assert len(out) == 1
    assert out[0].source_endpoints == (
        "GET api.public.example /me",
        "GET internal-billing.corp.example /me",
    )


def test_secret_shaped_value_surfaces_hash_and_preview_only() -> None:
    # A secret kind carries no raw value (ADR-0015): value is None upstream; the
    # row exposes hash + preview only, never a raw secret.
    out = _run(
        pivots=[
            _pivot_row(
                value_hash="deadbeef",
                kind="secret",
                value=None,
                value_preview="eyJhbGci",
            )
        ]
    )
    assert len(out) == 1
    row = out[0]
    assert row.value_hash == "deadbeef"
    assert row.value_preview == "eyJhbGci"
    # No raw-value field exists on the model; round-trip never exposes one
    # (ADR-0015 secret invariant — fails loudly if a `value` field is ever added).
    assert "value" not in row.model_dump()


def test_shape_rank_orders_uuid_email_jwt_above_opaque_above_integer() -> None:
    pivots = [
        _pivot_row(
            value_hash="h-int", kind="identifier", value="42", value_preview="42",
            target_endpoint_id="eInt", target_path="/by-int", parameter_name="n",
        ),
        _pivot_row(
            value_hash="h-opaque", kind="opaque_token", value=None,
            value_preview="Rec0pAqU",
            target_endpoint_id="eOp", target_path="/by-opaque", parameter_name="sig",
        ),
        _pivot_row(
            value_hash="h-uuid", kind="identifier",
            value="11111111-2222-3333-4444-555555555555", value_preview="11111111",
            target_endpoint_id="eUuid", target_path="/by-uuid", parameter_name="id",
        ),
        _pivot_row(
            value_hash="h-email", kind="email",
            value="leak@corp.example.com", value_preview="leak@cor",
            target_endpoint_id="eEmail", target_path="/by-email", parameter_name="e",
        ),
        _pivot_row(
            value_hash="h-jwt", kind="secret", value=None, value_preview="eyJhbGci",
            target_endpoint_id="eJwt", target_path="/by-jwt", parameter_name="t",
        ),
    ]
    out = _run(pivots=pivots)
    ranks = [r.shape_rank for r in out]
    # Sorted ascending: specific(0) cluster first, then opaque(1), then integer(2).
    assert ranks == sorted(ranks)
    assert {r.value_hash for r in out if r.shape_rank == 0} == {
        "h-uuid",
        "h-email",
        "h-jwt",
    }
    assert [r.value_hash for r in out if r.shape_rank == 1] == ["h-opaque"]
    assert [r.value_hash for r in out if r.shape_rank == 2] == ["h-int"]


def test_within_shape_rank_higher_confidence_sorts_first() -> None:
    old = _NOW - timedelta(days=30)  # decays to ~0.5
    pivots = [
        _pivot_row(
            value_hash="h-low", value="aaaaaaaa-2222-3333-4444-555555555555",
            value_preview="aaaaaaaa", last_seen=old,
            target_endpoint_id="eLow", target_path="/low", parameter_name="id",
        ),
        _pivot_row(
            value_hash="h-high", value="bbbbbbbb-2222-3333-4444-555555555555",
            value_preview="bbbbbbbb", last_seen=_NOW,
            target_endpoint_id="eHigh", target_path="/high", parameter_name="id",
        ),
    ]
    out = _run(pivots=pivots)
    assert [r.value_hash for r in out] == ["h-high", "h-low"]


def test_min_confidence_filters_decayed_rows() -> None:
    old = _NOW - timedelta(days=60)  # ~0.25 of stored at 30-day half-life
    kw: dict[str, Any] = dict(pivots=[_pivot_row(confidence=1.0, last_seen=old)])
    out = _run(**kw)
    assert len(out) == 1
    assert abs(out[0].effective_confidence - 0.25) < 1e-9
    out2 = _run(**kw, min_confidence=0.5)
    assert out2 == []


def test_json_round_trips_the_typed_model() -> None:
    from doo.coverage.models import C3Result

    out = _run(pivots=[_pivot_row()])
    restored = C3Result.model_validate_json(out[0].model_dump_json())
    assert restored == out[0]
    assert restored.query_id == "C3"
