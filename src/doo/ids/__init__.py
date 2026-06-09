"""Typed identifiers used across the system.

`NewType` aliases on top of `str` give mypy a positional-arg-swap catch without
runtime overhead. Every node identity that's stable across layers gets one of
these; pass-by-position bugs ("you handed an EngagementId where a PrincipalId
was expected") become type errors instead of silent corruption.
"""

from doo.ids.types import (
    AuthContextId,
    BlobKey,
    CommitId,
    EngagementId,
    EngagementName,
    EventId,
    FindingId,
    HostId,
    IdempotencyKey,
    L2EventId,
    ObservationId,
    ObservedValueId,
    ParameterId,
    PrincipalId,
    PrincipalLabel,
    ScopeContentHash,
    Sha256Hex,
    SourceId,
    SpanId,
    TenantId,
    TestCaseKeyHash,
    TraceId,
    TrustBoundaryId,
)

__all__ = [
    "AuthContextId",
    "BlobKey",
    "CommitId",
    "EngagementId",
    "EngagementName",
    "EventId",
    "FindingId",
    "HostId",
    "IdempotencyKey",
    "L2EventId",
    "ObservationId",
    "ObservedValueId",
    "ParameterId",
    "PrincipalId",
    "PrincipalLabel",
    "ScopeContentHash",
    "Sha256Hex",
    "SourceId",
    "SpanId",
    "TenantId",
    "TestCaseKeyHash",
    "TraceId",
    "TrustBoundaryId",
]
