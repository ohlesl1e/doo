"""Shared seam for the Cypher syntax smoke test (issue #156).

The bug class (#157, `cc61f22`): Cypher templates built via f-string +
`CypherFragment.and_(...)` / `for_engagement(...)` that are only *parsed* at
dispatch runtime. Every unit suite drives these helpers against a duck-typed
fake client that returns scripted rows and never parses the query string, so a
malformed template (the double-`WHERE` shape) ships green and only blows up as a
`CypherSyntaxError` against real Neo4j.

This module provides the two pieces the Layer-1 (`EXPLAIN`-backed) smoke test
needs:

* `RecordingClient` — a `Neo4jClient`-shaped test double whose `execute_read` /
  `execute_write` append the rendered `cypher` string to `.queries` and return
  canned rows (a Scope-rules row for the scope load, `[]` otherwise). Driving a
  query entrypoint with it collects every Cypher string that function emits
  without touching a database. Mirrors `_FakeClient` in
  `tests/test_coverage_c2_unit.py`.
* `REGISTRY` — an explicit list of `(label, driver)` entrypoints. Each `driver`
  takes a `RecordingClient`, calls one `for_engagement` / `.and_` emitter with
  canned arguments, and relies on the recording client to capture the query.

The registry can drift (a new emitter that nobody adds here is silently
uncovered) — which is exactly why issue #156 also ships the Layer-2 static guard
(`tests/test_cypher_static_guard.py`), the drift-proof net that flags the #157
shape across *all* of `src/` with zero per-call-site maintenance.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from doo.coverage.queries import (
    run_c1,
    run_c2,
    run_c2b,
    run_c3,
    run_c4,
    run_c5,
    run_c5a,
    run_c5b,
)
from doo.coverage.reached import reached_by_auth_map, reached_map
from doo.dispatch.candidates import list_redispatch_candidates
from doo.dispatch.executor.evidence import DispatchTestCase, load_evidence
from doo.dispatch.executor.liveness import infer_self_endpoint
from doo.dispatch.finding import (
    InMemoryFindingLedger,
    list_proposed_findings,
    list_reasserted_findings,
    resolve_finding_key,
)
from doo.dispatch.models import DispatchSelection
from doo.dispatch.rotation import is_waiting_on_rotation
from doo.dispatch.selection import select_testcases
from doo.ids import (
    AuthContextId,
    EngagementId,
    TestCaseKeyHash,
)
from doo.planner.commit import fetch_testcase
from doo.planner.review import InMemoryReviewLedger, fetch_target_evidence
from doo.planner.service import review_queue

_EID = EngagementId("eng-cypher-smoke")
_AC = AuthContextId("ac-cypher-smoke")
_KEY = TestCaseKeyHash("0" * 64)
_NOW = datetime(2026, 6, 1, tzinfo=UTC)

# A material Scope-rules view, JSON-encoded exactly as `_load_scope_rules` reads
# it back (`graph_state._scope_create` stores it as a JSON string on
# `Scope.rules`). Lets the C-query entrypoints clear their first read and go on
# to emit their remaining (f-string-composed) queries.
_SCOPE_RULES = {
    "host_patterns": ["shop.example.com"],
    "allowed_methods": ["*"],
    "allowed_path_patterns": ["/**"],
    "payload_class_denylist": [],
    "rate_limit": None,
    "time_window": None,
    "required_headers": [],
}

# A discovered-tier evidence row for `load_evidence`'s first read (#164). Without
# it that read returns `[]` and `load_evidence` returns early, so the ADR-0052
# sibling-walk follow-up query (`_walk_baseline_victim_sibling`) never fires and
# escapes the EXPLAIN net. `victim_ac_tier = "discovered"` drives `load_evidence`
# into the walk; the fields below are the minimum its `EvidenceObservation`
# construction reads.
_EVIDENCE_ROW = {
    "observation_id": "ro-smoke",
    "method": "GET",
    "concrete_path": "/orders/1",
    "query": [],
    "headers": [],
    "cookies": [],
    "body_blob_key": None,
    "body_content_type": None,
    "confidence": 1.0,
    "path_template": "/orders/{id}",
    "scheme": "https",
    "host": "shop.example.com",
    "port": None,
    "is_ip": False,
    "victim_ac_id": "ac-victim-discovered",
    "victim_ac_tier": "discovered",
    "victim_ac_carrier": "cookie",
}


class RecordingClient:
    """`Neo4jClient`-shaped double that records every rendered Cypher string.

    `execute_read` / `execute_write` append the `cypher` to `self.queries` and
    return canned rows: the Scope-rules row when the scope read fires (so the
    coverage entrypoints don't raise before emitting their later queries), a
    discovered-tier evidence row for `load_evidence`'s first read (so it proceeds
    into the ADR-0052 sibling-walk and that query is captured too, #164), and
    `[]` otherwise. Every other registered entrypoint either loops over the rows
    (empty -> empty result) or already handles a `None`/`[]` result, so an empty
    return never short-circuits the Cypher we want to capture.
    """

    def __init__(self) -> None:
        # (cypher, params) pairs, in emission order. Params are kept so the
        # smoke test can bind them when running `EXPLAIN` (Neo4j wants every
        # referenced `$param` present at plan time).
        self.calls: list[tuple[str, dict[str, Any]]] = []

    @property
    def queries(self) -> list[str]:
        return [cypher for cypher, _ in self.calls]

    def _record(self, cypher: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        self.calls.append((cypher, params))
        if "UNDER_SCOPE" in cypher and "Scope" in cypher:
            return [{"rules": json.dumps(_SCOPE_RULES)}]
        # `load_evidence`'s first read (#164): hand back a discovered-tier row so
        # the call proceeds into the ADR-0052 sibling-walk and that query is
        # captured too. `coalesce(rb, re, rp)` is unique to that read.
        if "coalesce(rb, re, rp)" in cypher:
            return [dict(_EVIDENCE_ROW)]
        return []

    def execute_read(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
        return self._record(cypher, params)

    def execute_write(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
        return self._record(cypher, params)


# --- Entrypoint drivers ----------------------------------------------------
#
# Each driver invokes ONE Cypher-emitting entrypoint with canned arguments. The
# RecordingClient captures whatever Cypher the call renders; the smoke test then
# `EXPLAIN`s each captured string against real Neo4j.

_TESTCASE = DispatchTestCase(
    engagement_id=_EID,
    key_hash=_KEY,
    test_class="bypass",
    payload_class="authz",
    auth_context_id=_AC,
    target_endpoint_id="e-smoke",
    target_parameter_id=None,
    target_trust_boundary_id=None,
    hold=(),
    replay_hazards=(),
)


def _driver(fn: Callable[..., Any], /, **kwargs: Any) -> Callable[[RecordingClient], None]:
    def run(client: RecordingClient) -> None:
        fn(client, **kwargs)

    return run


# (label, driver) pairs. Labels are stable parametrize ids.
REGISTRY: list[tuple[str, Callable[[RecordingClient], None]]] = [
    # coverage.queries — the C-family (each loads scope first, then its reads).
    ("coverage.run_c1", _driver(run_c1, engagement_id=_EID, now=_NOW)),
    ("coverage.run_c2", _driver(run_c2, engagement_id=_EID, now=_NOW)),
    (
        "coverage.run_c2.pinned",
        _driver(run_c2, engagement_id=_EID, as_label="admin", not_as_label="user", now=_NOW),
    ),
    ("coverage.run_c2b", _driver(run_c2b, engagement_id=_EID, now=_NOW)),
    ("coverage.run_c3", _driver(run_c3, engagement_id=_EID, now=_NOW)),
    ("coverage.run_c4", _driver(run_c4, engagement_id=_EID, now=_NOW)),
    ("coverage.run_c5", _driver(run_c5, engagement_id=_EID, now=_NOW)),
    ("coverage.run_c5a", _driver(run_c5a, engagement_id=_EID, now=_NOW)),
    ("coverage.run_c5b", _driver(run_c5b, engagement_id=_EID, now=_NOW)),
    # coverage.reached — the 2xx reach maps used by C2/C2b/C4.
    ("coverage.reached_map", _driver(reached_map, engagement_id=_EID)),
    ("coverage.reached_by_auth_map", _driver(reached_by_auth_map, engagement_id=_EID)),
    # dispatch.executor — incl. the exact #157 bug site (infer_self_endpoint).
    (
        "dispatch.infer_self_endpoint",
        _driver(infer_self_endpoint, engagement_id=_EID, auth_context_id=_AC),
    ),
    (
        "dispatch.load_evidence",
        _driver(load_evidence, engagement_id=_EID, testcase=_TESTCASE),
    ),
    # dispatch.selection — dynamic AND-join + interpolated LIMIT.
    (
        "dispatch.select_testcases",
        _driver(
            select_testcases,
            engagement_id=_EID,
            selection=DispatchSelection(generators=("c2",), test_classes=(), limit=50),
        ),
    ),
    # dispatch.rotation — the #170 re-dispatch watermark guard (auth_invalid +
    # OPTIONAL-MATCH double; two-stage WITH/aggregate the EXPLAIN net must parse).
    (
        "dispatch.is_waiting_on_rotation",
        _driver(
            is_waiting_on_rotation,
            engagement_id=_EID,
            key_hash=_KEY,
            principal_label="attacker-b",
            slot="bearer",
        ),
    ),
    # dispatch.candidates — the #171 re-dispatch candidate read (EXISTS subqueries,
    # NOT-EXISTS, two-stage WITH/aggregate + watermark OPTIONAL MATCH).
    (
        "dispatch.list_redispatch_candidates",
        _driver(list_redispatch_candidates, engagement_id=_EID),
    ),
    # dispatch.finding — proposed / reasserted listings + key resolution.
    ("dispatch.list_proposed_findings", _driver(list_proposed_findings, engagement_id=_EID)),
    (
        "dispatch.list_reasserted_findings",
        _driver(list_reasserted_findings, engagement_id=_EID, ledger=InMemoryFindingLedger()),
    ),
    ("dispatch.resolve_finding_key", _driver(resolve_finding_key, engagement_id=_EID, prefix="abc")),
    # planner — commit / review / service reads.
    ("planner.fetch_testcase", _driver(fetch_testcase, engagement_id=_EID, key_hash=_KEY)),
    (
        "planner.fetch_target_evidence",
        _driver(fetch_target_evidence, engagement_id=_EID, key_hash=_KEY, now=_NOW),
    ),
    (
        "planner.review_queue",
        _driver(review_queue, ledger=InMemoryReviewLedger(), engagement_id=_EID, now=_NOW),
    ),
]
