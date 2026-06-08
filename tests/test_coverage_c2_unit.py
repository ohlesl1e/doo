"""Unit tests for C2 (`run_c2`) — no containers.

Drives `run_c2` against a fake Neo4j client that answers each of the four reads
(`Scope.rules`, active `Principal`s, in-scope `Endpoint`s, the 2xx `reached`
traversal) with canned rows, so the Python-side pairing logic — ordered pairs,
the A-reached-∧-not-B-reached differential, `--as` / `--not-as` pinning, in-scope
filtering, evidence shaping, decay/`--min-confidence` — is tested in isolation.
The golden e2e (`test_coverage_c2_e2e.py`) covers the real pipeline + Cypher.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from doo.coverage.queries import run_c2
from doo.ids import EngagementId

_EID = EngagementId("eng-c2-unit")
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


def _principal(pid: str, *, label: object = None, is_anon: bool = False, key: str) -> dict[str, Any]:
    return {"principal_id": pid, "is_anonymous": is_anon, "label": label, "identity_key": key}


def _endpoint(
    eid: str,
    *,
    path: str = "/admin",
    method: str = "GET",
    host: str = "shop.example.com",
    confidence: float = 1.0,
    last_seen: datetime = _NOW,
) -> dict[str, Any]:
    return {
        "endpoint_id": eid,
        "method": method,
        "path_template": path,
        "confidence": confidence,
        "last_seen": last_seen,
        "scheme": "https",
        "canonical_hostname": host,
        "port": None,
        "is_ip_literal": False,
    }


def _reached(eid: str, pid: str, *, status: int = 200, size: int | None = 10) -> dict[str, Any]:
    return {
        "endpoint_id": eid,
        "principal_id": pid,
        "status": status,
        "response_size_bytes": size,
        "response_body_sha256": None,
    }


class _FakeClient:
    """Routes each coverage read to its canned rows by query content."""

    def __init__(
        self,
        *,
        principals: list[dict[str, Any]],
        endpoints: list[dict[str, Any]],
        reached: list[dict[str, Any]],
    ) -> None:
        self._principals = principals
        self._endpoints = endpoints
        self._reached = reached

    def execute_read(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
        if "UNDER_SCOPE" in cypher:
            return [{"rules": json.dumps(_SCOPE_RULES)}]
        if "MATCH (p:Principal)" in cypher and "OF_PRINCIPAL" not in cypher:
            return self._principals
        if "MATCH (e:Endpoint)-[:ON_HOST]" in cypher:
            return self._endpoints
        if "response_status >= 200" in cypher:
            return self._reached
        raise AssertionError(f"unexpected query: {cypher[:80]!r}")


def _run(**kw: Any):  # type: ignore[no-untyped-def]
    client = _FakeClient(
        principals=kw.pop("principals"),
        endpoints=kw.pop("endpoints"),
        reached=kw.pop("reached"),
    )
    return run_c2(client, _EID, now=_NOW, **kw)  # type: ignore[arg-type]


_ADMIN = _principal("pAdmin", label="admin", key="declared:admin")
_USER = _principal("pUser", label="user", key="declared:user")
_ANON = _principal("pAnon", is_anon=True, key="anonymous")


def test_a_reached_not_b_is_surfaced() -> None:
    out = _run(
        principals=[_ADMIN, _USER],
        endpoints=[_endpoint("e1")],
        reached=[_reached("e1", "pAdmin", status=200)],  # only admin reached e1
    )
    # admin->user surfaces e1; user->admin does not (user never reached e1).
    pairs = [(r.principal_a_label, r.principal_b_label, r.endpoint_id) for r in out]
    assert ("admin", "user", "e1") in pairs
    assert ("user", "admin", "e1") not in pairs
    assert len(out) == 1


def test_evidence_a_real_b_null() -> None:
    out = _run(
        principals=[_ADMIN, _USER],
        endpoints=[_endpoint("e1")],
        reached=[_reached("e1", "pAdmin", status=200, size=42)],
    )
    row = out[0]
    assert row.evidence_a.status == 200
    assert row.evidence_a.response_size_bytes == 42
    assert row.evidence_a.label == "admin"
    assert row.evidence_b is None  # user never reached -> bypass candidate


def test_b_blocked_401_still_counts_as_not_reached() -> None:
    # ADR-0033: B's 401 never enters `reached` (the Cypher filters to 2xx), so
    # the boundary still surfaces as a gap rather than being suppressed.
    out = _run(
        principals=[_ADMIN, _USER],
        endpoints=[_endpoint("e1")],
        reached=[_reached("e1", "pAdmin", status=200)],  # user's 401 absent by 2xx filter
    )
    assert [(r.principal_a_label, r.principal_b_label) for r in out] == [("admin", "user")]


def test_both_reached_is_not_a_gap() -> None:
    out = _run(
        principals=[_ADMIN, _USER],
        endpoints=[_endpoint("e1")],
        reached=[_reached("e1", "pAdmin"), _reached("e1", "pUser")],
    )
    assert out == []


def test_anonymous_participates_in_pairing() -> None:
    out = _run(
        principals=[_ADMIN, _ANON],
        endpoints=[_endpoint("e1")],
        reached=[_reached("e1", "pAdmin")],
    )
    labels = {(r.principal_a_label, r.principal_b_label) for r in out}
    assert labels == {("admin", "anon")}  # anon reads as "anon"


def test_pin_as_and_not_as() -> None:
    eps = [_endpoint("e1"), _endpoint("e2", path="/reports")]
    reached = [
        _reached("e1", "pAdmin"),
        _reached("e2", "pAdmin"),
        _reached("e2", "pUser"),
    ]
    # Pin A=admin, B=user: only e1 (admin reached, user did not).
    out = _run(
        principals=[_ADMIN, _USER, _ANON],
        endpoints=eps,
        reached=reached,
        as_label="admin",
        not_as_label="user",
    )
    assert [(r.principal_a_label, r.principal_b_label, r.endpoint_id) for r in out] == [
        ("admin", "user", "e1")
    ]


def test_out_of_scope_endpoint_excluded() -> None:
    out = _run(
        principals=[_ADMIN, _USER],
        endpoints=[_endpoint("e1", host="evil.test")],  # not in scope
        reached=[_reached("e1", "pAdmin")],
    )
    assert out == []


def test_no_self_pairs() -> None:
    out = _run(
        principals=[_ADMIN],
        endpoints=[_endpoint("e1")],
        reached=[_reached("e1", "pAdmin")],
    )
    assert out == []  # only one principal -> no ordered pair


def test_min_confidence_filters_decayed_rows() -> None:
    old = _NOW - timedelta(days=60)  # ~0.25 of stored at 30-day half-life
    out = _run(
        principals=[_ADMIN, _USER],
        endpoints=[_endpoint("e1", confidence=1.0, last_seen=old)],
        reached=[_reached("e1", "pAdmin")],
    )
    assert len(out) == 1
    assert abs(out[0].effective_confidence - 0.25) < 1e-9
    # Raising the threshold above the decayed value drops it.
    out2 = _run(
        principals=[_ADMIN, _USER],
        endpoints=[_endpoint("e1", confidence=1.0, last_seen=old)],
        reached=[_reached("e1", "pAdmin")],
        min_confidence=0.5,
    )
    assert out2 == []


def test_json_round_trips_the_typed_model() -> None:
    from doo.coverage.models import C2Result

    out = _run(
        principals=[_ADMIN, _USER],
        endpoints=[_endpoint("e1")],
        reached=[_reached("e1", "pAdmin")],
    )
    restored = C2Result.model_validate_json(out[0].model_dump_json())
    assert restored == out[0]
    assert restored.query_id == "C2"
