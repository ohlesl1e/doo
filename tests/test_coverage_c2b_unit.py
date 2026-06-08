"""Unit tests for C2b (`run_c2b`) — no containers.

Drives `run_c2b` against a fake Neo4j client that answers each of the four reads
(`Scope.rules`, active `Principal`s, in-scope `Endpoint`s, the 2xx `reached`
traversal) with canned rows, so the Python-side differential logic — group by
endpoint, ≥2-principal threshold, identical-hash-and-size excluded, differing
hash OR size included, in-scope filtering, evidence shaping, decay /
`--min-confidence` — is tested in isolation. The golden e2e
(`test_coverage_c2b_e2e.py`) covers the real pipeline + Cypher.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from doo.coverage.queries import run_c2b
from doo.ids import EngagementId

_EID = EngagementId("eng-c2b-unit")
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
    path: str = "/orders/1",
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


def _reached(
    eid: str,
    pid: str,
    *,
    status: int = 200,
    size: int | None = 10,
    sha: str | None = None,
) -> dict[str, Any]:
    return {
        "endpoint_id": eid,
        "principal_id": pid,
        "status": status,
        "response_size_bytes": size,
        "response_body_sha256": sha,
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
    return run_c2b(client, _EID, now=_NOW, **kw)  # type: ignore[arg-type]


_ADMIN = _principal("pAdmin", label="admin", key="declared:admin")
_USER = _principal("pUser", label="user", key="declared:user")
_ANON = _principal("pAnon", is_anon=True, key="anonymous")


def test_differing_body_hash_is_surfaced() -> None:
    # Same status + same size, but different body sha256 -> divergence.
    out = _run(
        principals=[_ADMIN, _USER],
        endpoints=[_endpoint("e1")],
        reached=[
            _reached("e1", "pAdmin", size=100, sha="aaa"),
            _reached("e1", "pUser", size=100, sha="bbb"),
        ],
    )
    assert len(out) == 1
    assert out[0].endpoint_id == "e1"
    labels = {ev.label for ev in out[0].evidence}
    assert labels == {"admin", "user"}


def test_differing_size_is_surfaced() -> None:
    # Same sha (both null), but different size -> divergence.
    out = _run(
        principals=[_ADMIN, _USER],
        endpoints=[_endpoint("e1")],
        reached=[
            _reached("e1", "pAdmin", size=100, sha=None),
            _reached("e1", "pUser", size=250, sha=None),
        ],
    )
    assert len(out) == 1
    assert out[0].endpoint_id == "e1"


def test_identical_hash_and_size_is_not_surfaced() -> None:
    # Both principals reached with the SAME hash AND size -> not a divergence.
    out = _run(
        principals=[_ADMIN, _USER],
        endpoints=[_endpoint("e1")],
        reached=[
            _reached("e1", "pAdmin", size=100, sha="same"),
            _reached("e1", "pUser", size=100, sha="same"),
        ],
    )
    assert out == []


def test_single_principal_is_not_surfaced() -> None:
    # Only one principal reached -> can never diverge.
    out = _run(
        principals=[_ADMIN, _USER],
        endpoints=[_endpoint("e1")],
        reached=[_reached("e1", "pAdmin", size=100, sha="aaa")],
    )
    assert out == []


def test_evidence_carries_per_principal_tuple() -> None:
    out = _run(
        principals=[_ADMIN, _USER],
        endpoints=[_endpoint("e1")],
        reached=[
            _reached("e1", "pAdmin", status=200, size=100, sha="aaa"),
            _reached("e1", "pUser", status=200, size=200, sha="bbb"),
        ],
    )
    row = out[0]
    # Evidence is sorted by label for stable output.
    admin_ev = next(ev for ev in row.evidence if ev.label == "admin")
    user_ev = next(ev for ev in row.evidence if ev.label == "user")
    assert admin_ev.status == 200 and admin_ev.response_size_bytes == 100
    assert admin_ev.response_body_sha256 == "aaa"
    assert user_ev.response_size_bytes == 200 and user_ev.response_body_sha256 == "bbb"


def test_three_principals_one_differs() -> None:
    # Two identical, one differs -> still a divergence; all three in evidence.
    out = _run(
        principals=[_ADMIN, _USER, _ANON],
        endpoints=[_endpoint("e1")],
        reached=[
            _reached("e1", "pAdmin", size=100, sha="same"),
            _reached("e1", "pUser", size=100, sha="same"),
            _reached("e1", "pAnon", size=100, sha="different"),
        ],
    )
    assert len(out) == 1
    assert {ev.label for ev in out[0].evidence} == {"admin", "user", "anon"}


def test_out_of_scope_endpoint_excluded() -> None:
    out = _run(
        principals=[_ADMIN, _USER],
        endpoints=[_endpoint("e1", host="evil.test")],  # not in scope
        reached=[
            _reached("e1", "pAdmin", sha="aaa"),
            _reached("e1", "pUser", sha="bbb"),
        ],
    )
    assert out == []


def test_min_confidence_filters_decayed_rows() -> None:
    old = _NOW - timedelta(days=60)  # ~0.25 of stored at 30-day half-life
    kw: dict[str, Any] = dict(
        principals=[_ADMIN, _USER],
        endpoints=[_endpoint("e1", confidence=1.0, last_seen=old)],
        reached=[
            _reached("e1", "pAdmin", sha="aaa"),
            _reached("e1", "pUser", sha="bbb"),
        ],
    )
    out = _run(**kw)
    assert len(out) == 1
    assert abs(out[0].effective_confidence - 0.25) < 1e-9
    out2 = _run(**kw, min_confidence=0.5)
    assert out2 == []


def test_json_round_trips_the_typed_model() -> None:
    from doo.coverage.models import C2bResult

    out = _run(
        principals=[_ADMIN, _USER],
        endpoints=[_endpoint("e1")],
        reached=[
            _reached("e1", "pAdmin", sha="aaa"),
            _reached("e1", "pUser", sha="bbb"),
        ],
    )
    restored = C2bResult.model_validate_json(out[0].model_dump_json())
    assert restored == out[0]
    assert restored.query_id == "C2b"
