"""Unit tests for C4 (`run_c4`) + the strong/weak direction helper — no containers.

Drives `run_c4` against a fake Neo4j client answering its four reads (scope,
in-scope endpoints, AuthContext-granularity `reached`, AuthContexts-with-claims)
with canned rows, so the Python pairing/direction logic is tested in isolation: a
capability claim delta with a clear tier ordering surfaces the strong-reached /
weak-not differential; no delta or an ambiguous ordering yields nothing.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from doo.canonical.trust_boundary import stronger_capability_side
from doo.coverage.queries import run_c4
from doo.ids import EngagementId

_EID = EngagementId("eng-c4-unit")
_NOW = datetime(2026, 6, 1, tzinfo=UTC)

_SCOPE_RULES = {
    "host_patterns": ["api.example.com"],
    "allowed_methods": ["*"],
    "allowed_path_patterns": ["/**"],
    "payload_class_denylist": [],
    "rate_limit": None,
    "time_window": None,
    "required_headers": [],
}


def _endpoint(eid: str, *, path: str = "/admin", method: str = "GET") -> dict[str, Any]:
    return {
        "endpoint_id": eid, "method": method, "path_template": path,
        "confidence": 1.0, "last_seen": _NOW, "scheme": "https",
        "canonical_hostname": "api.example.com", "port": None, "is_ip_literal": False,
    }


def _auth(acid: str, pid: str, claims: dict[str, Any], *, label: str = "user") -> dict[str, Any]:
    return {"acid": acid, "claims": json.dumps(claims), "pid": pid,
            "p_anon": False, "label": label, "ikey": f"declared:{label}"}


def _reached(eid: str, acid: str, *, status: int = 200, size: int | None = 10) -> dict[str, Any]:
    return {"endpoint_id": eid, "auth_context_id": acid, "status": status,
            "response_size_bytes": size, "response_body_sha256": None}


class _FakeClient:
    def __init__(self, *, endpoints, auths, reached) -> None:  # type: ignore[no-untyped-def]
        self._endpoints, self._auths, self._reached = endpoints, auths, reached

    def execute_read(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
        if "UNDER_SCOPE" in cypher:
            return [{"rules": json.dumps(_SCOPE_RULES)}]
        if "ac.id AS auth_context_id" in cypher:  # reached_by_auth_map
            return self._reached
        if "identity_claims AS claims" in cypher:  # _load_auth_contexts_with_claims
            return self._auths
        if "MATCH (e:Endpoint)-[:ON_HOST]" in cypher:
            return self._endpoints
        raise AssertionError(f"unexpected query: {cypher[:80]!r}")


def _run(**kw: Any):  # type: ignore[no-untyped-def]
    client = _FakeClient(endpoints=kw["endpoints"], auths=kw["auths"], reached=kw["reached"])
    return run_c4(client, _EID, now=_NOW)  # type: ignore[arg-type]


# A single principal P with a broad-scope token (strong) and a narrow one (weak).
_STRONG = _auth("ac-strong", "P", {"scope": "read write admin"})
_WEAK = _auth("ac-weak", "P", {"scope": "read"})


def test_strong_reached_weak_not_is_surfaced() -> None:
    out = _run(endpoints=[_endpoint("e1")], auths=[_STRONG, _WEAK],
               reached=[_reached("e1", "ac-strong")])  # only the strong token reached e1
    assert len(out) == 1
    row = out[0]
    assert row.endpoint_id == "e1"
    assert row.capability_kind == "scope"
    assert row.strong_auth_context_id == "ac-strong"
    assert row.weak_auth_context_id == "ac-weak"
    assert row.evidence_strong.status == 200


def test_weak_also_reached_is_not_a_gap() -> None:
    out = _run(endpoints=[_endpoint("e1")], auths=[_STRONG, _WEAK],
               reached=[_reached("e1", "ac-strong"), _reached("e1", "ac-weak")])
    assert out == []


def test_no_capability_delta_yields_nothing() -> None:
    # Same scope on both tokens -> no distinguishing claim -> no gap.
    same_a = _auth("ac-a", "P", {"scope": "read write"})
    same_b = _auth("ac-b", "P", {"scope": "read write"})
    out = _run(endpoints=[_endpoint("e1")], auths=[same_a, same_b],
               reached=[_reached("e1", "ac-a")])
    assert out == []


def test_ambiguous_tier_ordering_yields_nothing() -> None:
    # Disjoint scopes -> neither is a superset -> ambiguous -> dropped.
    disj_a = _auth("ac-a", "P", {"scope": "read"})
    disj_b = _auth("ac-b", "P", {"scope": "write"})
    out = _run(endpoints=[_endpoint("e1")], auths=[disj_a, disj_b],
               reached=[_reached("e1", "ac-a")])
    assert out == []


# --- the direction helper directly --------------------------------------------


def test_direction_scope_superset() -> None:
    assert stronger_capability_side({"scope": "a b c"}, {"scope": "a b"}, "scope") == "a"
    assert stronger_capability_side({"scope": "a"}, {"scope": "a b"}, "scope") == "b"
    assert stronger_capability_side({"scope": "a"}, {"scope": "b"}, "scope") is None


def test_direction_mfa_acr_then_amr() -> None:
    assert stronger_capability_side({"acr": "2"}, {"acr": "1"}, "mfa") == "a"
    assert stronger_capability_side(
        {"amr": ["pwd", "otp"]}, {"amr": ["pwd"]}, "mfa") == "a"
    assert stronger_capability_side({"amr": ["pwd"]}, {"amr": ["otp"]}, "mfa") is None


def test_direction_freshness_auth_time() -> None:
    assert stronger_capability_side({"auth_time": 200}, {"auth_time": 100}, "freshness") == "a"
    assert stronger_capability_side({"auth_time": 100}, {"auth_time": 100}, "freshness") is None
