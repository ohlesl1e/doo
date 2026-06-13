"""Slice-4 hedge contracts: `TestCase`, `Finding`, `ExecutedAsEdge`.

No slice-1 code path constructs these — but the identity / target / dispatch
rules are *already settled* in ADRs 0007, 0013, and CONTEXT.md. Writing the
Pydantic shapes now prevents design drift when slice 4 lands and lets the L3
schema bootstrap include constraints for the corresponding node types.

The hedge is contracts only — no graph-mutation code, no Cypher writers.
"""

from __future__ import annotations

import hashlib
from typing import Literal, Self

from pydantic import ConfigDict, Field, model_validator

from doo.canonical.cross_cutting import Inferred, Provenanced
from doo.ids import (
    AuthContextId,
    EngagementId,
    FindingId,
    ObservationId,
    ParameterId,
    Sha256Hex,
    TestCaseKeyHash,
    TrustBoundaryId,
)

# Test-class controlled vocabulary. Expand as planner classes are added.
# `forced_browsing` is the slice-3 deterministic C1 class: a benign GET against a
# discovered-but-never-hit in-scope Endpoint (ADR-0036). No reasoning, no LLM.
TestClass = Literal[
    "idor",
    "bola",
    "privilege-escalation",
    "ssrf",
    "auth-bypass",
    "sql-injection",
    "xss",
    "path-traversal",
    "open-redirect",
    "rate-limit",
    "boundary-violation",
    "forced_browsing",
    "leak_replay",
]

# PayloadClass per ADR-0003: low-cardinality controlled vocabulary the ROE
# layer reasons about. A tag/enum, not a node.
PayloadClass = Literal[
    "destructive-sql",
    "non-destructive-sql",
    "ssrf-callback",
    "benign-probe",
    "auth-token-swap",
    "boundary-probe",
    "no-payload",
]

# Dispatch status per ADR-0013 + ADR-0041 (`replay_invalid`). Coverage queries
# filter to `ok` when computing "tested and clean."
DispatchStatus = Literal[
    "ok",
    "auth_invalid",
    "replay_invalid",
    "rate_limited",
    "dispatcher_blocked",
    "transport_error",
]
DISPATCH_STATUSES: tuple[DispatchStatus, ...] = (
    "ok",
    "auth_invalid",
    "replay_invalid",
    "rate_limited",
    "dispatcher_blocked",
    "transport_error",
)

# Finding severity / category. Categories live as enums for now; promotion to
# a node would mean reasoning about class-to-class relationships, which we
# defer (same logic as PayloadClass).
FindingSeverity = Literal["info", "low", "medium", "high", "critical"]
FindingCategory = Literal[
    "idor",
    "ssrf",
    "broken-auth",
    "broken-access-control",
    "sql-injection",
    "xss",
    "info-disclosure",
    "rate-limit-bypass",
    "boundary-violation",
    "other",
]


def compute_testcase_key_hash(
    *,
    engagement_id: EngagementId,
    test_class: TestClass,
    target_endpoint_id: str | None,
    target_parameter_id: ParameterId | None,
    target_trust_boundary_id: TrustBoundaryId | None,
    payload_class: PayloadClass,
    payload_hash: Sha256Hex,
    auth_context_id: AuthContextId,
) -> TestCaseKeyHash:
    """Canonicalised content-address per ADR-0007.

    Three-way XOR on the target: exactly one of the three target ids is set.
    Unused ids normalise to the empty string and fall out of canonicalisation.
    `payload_hash = sha256("")` for no-payload tests (sentinel, never null).
    """

    targets = [
        target_endpoint_id is not None,
        target_parameter_id is not None,
        target_trust_boundary_id is not None,
    ]
    if sum(targets) != 1:
        raise ValueError(
            "TestCase target is exactly one of "
            "target_endpoint_id / target_parameter_id / target_trust_boundary_id"
        )
    parts = [
        engagement_id,
        test_class,
        target_endpoint_id or "",
        target_parameter_id or "",
        target_trust_boundary_id or "",
        payload_class,
        payload_hash,
        auth_context_id,
    ]
    canonical = "|".join(parts).encode("utf-8")
    return TestCaseKeyHash(hashlib.sha256(canonical).hexdigest())


class TestCase(Inferred):
    """Content-addressed, Engagement-scoped TestCase per ADR-0007.

    `key_hash` is the unique identity; the three-way XOR on target plus the
    `payload_hash` discipline keep "same logical test" idempotent across
    proposals.

    Slice 1 does not construct these. They're declared here so:
    - the L3 schema bootstrap can install the unique-index constraint, and
    - slice-4 implementers cannot drift the identity rule.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    engagement_id: EngagementId
    test_class: TestClass
    target_endpoint_id: str | None = None
    target_parameter_id: ParameterId | None = None
    target_trust_boundary_id: TrustBoundaryId | None = None
    payload_class: PayloadClass
    payload_hash: Sha256Hex
    auth_context_id: AuthContextId
    key_hash: TestCaseKeyHash

    @model_validator(mode="after")
    def _target_xor_and_hash_matches(self) -> Self:
        expected = compute_testcase_key_hash(
            engagement_id=self.engagement_id,
            test_class=self.test_class,
            target_endpoint_id=self.target_endpoint_id,
            target_parameter_id=self.target_parameter_id,
            target_trust_boundary_id=self.target_trust_boundary_id,
            payload_class=self.payload_class,
            payload_hash=self.payload_hash,
            auth_context_id=self.auth_context_id,
        )
        if self.key_hash != expected:
            raise ValueError("key_hash does not match content per ADR-0007 canonicalisation")
        return self


class Finding(Inferred):
    """Confirmed vulnerability. References TestCase(s); affects Endpoints / TrustBoundaries.

    Slice 1 does not construct these — same hedge as TestCase.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    engagement_id: EngagementId
    id: FindingId
    severity: FindingSeverity
    category: FindingCategory
    title: str = Field(min_length=1)
    description: str | None = None
    # Edges enforced at the graph layer per Step 5 invariants. These tuples
    # capture the slice-4 contract that a Finding REFERENCES >=1 TestCase and
    # AFFECTS >=1 Endpoint/TrustBoundary.
    referenced_testcase_hashes: tuple[TestCaseKeyHash, ...] = Field(min_length=1)
    affected_endpoint_ids: tuple[str, ...] = ()
    affected_trust_boundary_ids: tuple[TrustBoundaryId, ...] = ()

    @model_validator(mode="after")
    def _affects_at_least_one(self) -> Self:
        if not self.affected_endpoint_ids and not self.affected_trust_boundary_ids:
            raise ValueError(
                "Finding must AFFECTS at least one Endpoint or TrustBoundary (Step 5 invariant)"
            )
        return self


class ExecutedAsEdge(Provenanced):
    """The `TestCase -[EXECUTED_AS]-> RequestObservation` edge.

    Carries `dispatch_status` per ADR-0013, plus `request_role` and `run_id`
    (ADR-0042/0043) so coverage and audit can distinguish a `primary` send from
    a baseline and group sends by the dispatch run that authorised them. The
    edge is the per-execution record; coverage queries filter to
    `dispatch_status = "ok"` when computing "tested and clean."
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    testcase_key_hash: TestCaseKeyHash
    request_observation_id: ObservationId
    engagement_id: EngagementId
    dispatch_status: DispatchStatus
    # ADR-0043: which constructor produced this send (`primary`, `baseline_*`,
    # `liveness`, `hazard_warmup`). Kept as a free `str` here (not the
    # `RequestRole` Literal) because the role enum is keyed on `test_class` and
    # the edge is test-class-agnostic.
    request_role: str
    run_id: str
