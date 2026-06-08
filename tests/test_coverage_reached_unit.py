"""Unit tests for the `reached` predicate (ADR-0033) — no containers.

`reached` is the subtle authz-coverage success rule: a principal *reached* an
endpoint only when an observation under that principal's AuthContext returned a
**2xx**. These tests drive `reached_map` / `reached` against a fake Neo4j client
that returns canned traversal rows, so the 2xx rule and — critically — its
asymmetry from C1's any-`HIT` "hit" are locked in isolation from a live graph.

The Cypher itself already filters `response_status` to 200..299, so the fake
mirrors that contract: it returns only the rows a correct 2xx traversal would,
and we assert the predicate's behaviour over them. The C1-vs-C2 asymmetry test
is explicit: a 401 row is a HIT (C1 counts it) but is NOT a 2xx (reached drops
it).
"""

from __future__ import annotations

import re
from typing import Any

from doo.coverage.reached import reached, reached_map
from doo.ids import EngagementId

_EID = EngagementId("eng-reached-unit")

# A 2xx-only success window per ADR-0033; rows outside it must never be returned
# by the (correct) Cypher, so the fake applies the same filter the query string
# encodes — this keeps the unit test honest about the predicate's contract.
_SUCCESS = range(200, 300)


def _obs_row(
    *,
    endpoint_id: str,
    principal_id: str,
    status: int,
    size: int | None = 10,
    sha: str | None = None,
) -> dict[str, Any]:
    return {
        "endpoint_id": endpoint_id,
        "principal_id": principal_id,
        "status": status,
        "response_size_bytes": size,
        "response_body_sha256": sha,
    }


class _FakeClient:
    """Mimics the `reached_map` traversal: returns only the 2xx rows.

    The real Cypher embeds `r.response_status >= 200 AND <= 299`; the fake honours
    that contract by filtering the canned rows, so a test that hands it a 401 row
    correctly sees zero reached pairs (the DB would never return it).
    """

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def execute_read(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
        # Mirror the query's 2xx filter + its ORDER BY status DESC, size DESC.
        assert "r.response_status >= 200" in cypher
        assert "r.response_status <= 299" in cypher
        assert re.search(r"OBSERVED_UNDER.*OF_PRINCIPAL", cypher, re.S)
        kept = [r for r in self._rows if r["status"] in _SUCCESS]
        kept.sort(
            key=lambda r: (r["status"], r["response_size_bytes"] or 0), reverse=True
        )
        return kept


def _map(rows: list[dict[str, Any]]):  # type: ignore[no-untyped-def]
    return reached_map(_FakeClient(rows), _EID)  # type: ignore[arg-type]


def test_2xx_observation_is_reached() -> None:
    rows = [_obs_row(endpoint_id="e1", principal_id="pA", status=200)]
    out = _map(rows)
    assert ("e1", "pA") in out
    assert out[("e1", "pA")].status == 200


def test_201_204_are_reached() -> None:
    rows = [
        _obs_row(endpoint_id="e1", principal_id="pA", status=201),
        _obs_row(endpoint_id="e2", principal_id="pA", status=204),
    ]
    out = _map(rows)
    assert set(out.keys()) == {("e1", "pA"), ("e2", "pA")}


def test_401_403_404_5xx_are_not_reached() -> None:
    # ADR-0033: a blocked attempt (or a server error) is NOT reached. On the B
    # side of C2 these are the bypass candidates we must not suppress.
    for status in (401, 403, 404, 500, 503):
        rows = [_obs_row(endpoint_id="e1", principal_id="pA", status=status)]
        assert _map(rows) == {}


def test_3xx_is_not_reached() -> None:
    # Slice-2 success is 2xx only; 3xx is conservatively not-reached (no passive
    # login-redirect classifier yet).
    rows = [_obs_row(endpoint_id="e1", principal_id="pA", status=302)]
    assert _map(rows) == {}


def test_c1_vs_c2_asymmetry_a_401_hit_is_not_reached() -> None:
    """The locked asymmetry (ADR-0033): a 401 is a HIT (C1 counts it as 'not
    dead') but is NOT a 2xx, so `reached` is False for it. C1 and C2 deliberately
    use different success definitions."""

    # C2 side: the 401 yields no reached pair.
    assert _map([_obs_row(endpoint_id="e1", principal_id="pA", status=401)]) == {}

    # C1 side (documented contract): C1's traversal collapses ANY HIT — including
    # a 401 — to has_hit=True, so the same endpoint is NOT reported dead. We
    # assert the contrast directly against run_c1's any-HIT branch.
    from datetime import UTC, datetime

    from doo.coverage.queries import run_c1

    now = datetime(2026, 6, 1, tzinfo=UTC)

    class _C1Fake:
        def execute_read(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
            if "UNDER_SCOPE" in cypher:
                import json

                return [
                    {
                        "rules": json.dumps(
                            {
                                "host_patterns": ["shop.example.com"],
                                "allowed_methods": ["*"],
                                "allowed_path_patterns": ["/**"],
                                "payload_class_denylist": [],
                                "rate_limit": None,
                                "time_window": None,
                                "required_headers": [],
                            }
                        )
                    }
                ]
            return [
                {
                    "endpoint_id": "e1",
                    "method": "GET",
                    "path_template": "/admin",
                    "confidence": 1.0,
                    "last_seen": now,
                    "scheme": "https",
                    "canonical_hostname": "shop.example.com",
                    "port": None,
                    "is_ip_literal": False,
                    "has_hit": True,  # the 401 made it a HIT
                }
            ]

    # The 401-touched endpoint is NOT dead in C1 (any HIT counts)...
    assert run_c1(_C1Fake(), _EID, now=now) == []  # type: ignore[arg-type]
    # ...yet it is NOT reached in C2 (2xx only). Same endpoint, opposite verdict.


def test_strongest_2xx_evidence_is_retained_per_pair() -> None:
    # Two successes for the same pair: keep the highest status, then largest body.
    rows = [
        _obs_row(endpoint_id="e1", principal_id="pA", status=200, size=5, sha="a" * 64),
        _obs_row(endpoint_id="e1", principal_id="pA", status=206, size=50, sha="b" * 64),
    ]
    out = _map(rows)
    ev = out[("e1", "pA")]
    assert ev.status == 206
    assert ev.response_size_bytes == 50
    assert ev.response_body_sha256 == "b" * 64


def test_null_body_sha256_and_size_are_tolerated() -> None:
    rows = [_obs_row(endpoint_id="e1", principal_id="pA", status=200, size=None, sha=None)]
    ev = _map(rows)[("e1", "pA")]
    assert ev.response_body_sha256 is None
    assert ev.response_size_bytes is None


def test_reached_boolean_wrapper() -> None:
    rows = [_obs_row(endpoint_id="e1", principal_id="pA", status=200)]
    client = _FakeClient(rows)
    assert reached(client, _EID, endpoint_id="e1", principal_id="pA") is True  # type: ignore[arg-type]
    assert reached(client, _EID, endpoint_id="e1", principal_id="pB") is False  # type: ignore[arg-type]
    assert reached(client, _EID, endpoint_id="e2", principal_id="pA") is False  # type: ignore[arg-type]
