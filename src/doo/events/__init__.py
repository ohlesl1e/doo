"""Layer-boundary event contracts.

L1 -> L2: `IngestionEnvelope` (one per arrival on the `ingest` stream).
L2 -> L3: `L2Event` discriminated union over `RequestObservation` /
`ParseFailure` (the `ResponseArtifact` variant is retired; ADR-0023 — values are
inline `ValueCandidate`s on the observation, promoted at flush).
L3 -> consumers: `L3Event` discriminated union of structural events.

Plus action-layer (L5) contracts (`TestCase`, `Finding`, `EXECUTED_AS`) — the
identity / target rules the Planner and dispatch loop build against.
See ARCHITECTURE.md "Layer contracts (L1 -> L2 -> L3)" and the grill-queue G2
outputs.
"""

from doo.events.envelope import SOURCE_KINDS, IngestionEnvelope, SourceKind
from doo.events.execution import (
    DISPATCH_STATUSES,
    DispatchStatus,
    ExecutedAsEdge,
    Finding,
    FindingCategory,
    FindingSeverity,
    PayloadClass,
    TestCase,
    TestClass,
)
from doo.events.observation import (
    L2Event,
    L2EventBase,
    ParseFailure,
    ParseFailureKind,
    RequestObservation,
    ValueCandidate,
)
from doo.events.structural import (
    EdgeCreated,
    EdgeRemoved,
    L3Event,
    NodeCreated,
    NodeUpdated,
    Reconciliation,
)

__all__ = [
    "DISPATCH_STATUSES",
    "DispatchStatus",
    "EdgeCreated",
    "EdgeRemoved",
    "ExecutedAsEdge",
    "Finding",
    "FindingCategory",
    "FindingSeverity",
    "IngestionEnvelope",
    "L2Event",
    "L2EventBase",
    "L3Event",
    "NodeCreated",
    "NodeUpdated",
    "ParseFailure",
    "ParseFailureKind",
    "PayloadClass",
    "Reconciliation",
    "RequestObservation",
    "SOURCE_KINDS",
    "SourceKind",
    "TestCase",
    "TestClass",
    "ValueCandidate",
]
