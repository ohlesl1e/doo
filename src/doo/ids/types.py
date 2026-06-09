"""Typed identifier aliases.

These are `NewType`s, not classes — zero runtime cost. mypy distinguishes them
to catch positional-argument swap bugs at type-check time. Runtime values are
plain `str`.
"""

from typing import NewType

# Engagement-root identifiers.
EngagementId = NewType("EngagementId", str)
"""The id of an `Engagement` node — the engagement-scoping root per ADR-0017."""

EngagementName = NewType("EngagementName", str)
"""Human-readable engagement name (display only; not an identity)."""

# Scope.
ScopeContentHash = NewType("ScopeContentHash", str)
"""`sha256(canonicalized(rule_document))` — the identity of a `Scope` node (ADR-0017)."""

# Observation / inference node ids.
ObservationId = NewType("ObservationId", str)
"""A `RequestObservation` or `ParseFailure` node id."""

ObservedValueId = NewType("ObservedValueId", str)
"""An `ObservedValue` node id, derived from `(engagement_id, value_hash)` (ADR-0009)."""

ParameterId = NewType("ParameterId", str)
"""A `Parameter` node id."""

HostId = NewType("HostId", str)
"""A `Host` node id."""

# Identity & access.
PrincipalId = NewType("PrincipalId", str)
"""A `Principal` node id (declared or discovered, two-tier per ADR-0010)."""

PrincipalLabel = NewType("PrincipalLabel", str)
"""The manual label of a declared Principal (e.g. `test_user_a`)."""

AuthContextId = NewType("AuthContextId", str)
"""An `AuthContext` node id, derived from `auth_hash` (sha256 of token kind+value)."""

# Testing & findings.
TestCaseKeyHash = NewType("TestCaseKeyHash", str)
"""Content-addressed `TestCase` identity per ADR-0007."""

TenantId = NewType("TenantId", str)
"""A `Tenant` node id, derived from `(engagement_id, kind, normalized_value)` (ADR-0008)."""

TrustBoundaryId = NewType("TrustBoundaryId", str)
"""A `TrustBoundary` node id, derived from `(engagement_id, kind, between_a_id, between_b_id)`
(ADR-0002 / ADR-0008 / ADR-0039)."""

FindingId = NewType("FindingId", str)
"""A `Finding` node id."""

# Layer-boundary identifiers.
EventId = NewType("EventId", str)
"""An `IngestionEnvelope.event_id` (UUID, distinct from any business identity)."""

L2EventId = NewType("L2EventId", str)
"""An L2 emission id; per-emission, not idempotency-stable (use semantic key for that)."""

CommitId = NewType("CommitId", str)
"""L3 `CommitResult.commit_id`, per-commit, recorded on emitted `l3-events`."""

IdempotencyKey = NewType("IdempotencyKey", str)
"""L1's blob-level idempotency key — `sha256(source|blob_sha256|engagement_id)`."""

SourceId = NewType("SourceId", str)
"""Per-source stable identifier inside an L2 event (ADR-0016)."""

BlobKey = NewType("BlobKey", str)
"""Object-storage key for a request/response body or full blob."""

Sha256Hex = NewType("Sha256Hex", str)
"""A sha256 digest in lowercase hex (64 chars)."""

# Observability / W3C trace-context (per ADR-0018).
TraceId = NewType("TraceId", str)
"""W3C trace-context trace-id: 16 bytes / 32 lowercase hex chars."""

SpanId = NewType("SpanId", str)
"""W3C trace-context span-id: 8 bytes / 16 lowercase hex chars."""
