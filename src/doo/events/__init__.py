"""Layer-boundary event contracts.

L1 -> L2: `IngestionEnvelope` (one per arrival on the `ingest` stream).
L2 -> L3: `L2Event` discriminated union over `RequestObservation` /
`ResponseArtifact` / `ParseFailure`.
L3 -> consumers: `L3Event` discriminated union of structural events.

Plus slice-4 hedge contracts (`TestCase`, `Finding`, `EXECUTED_AS`) — the
identity / target rules must be locked in now so slice 4 doesn't drift.
See ARCHITECTURE.md "Layer contracts (L1 -> L2 -> L3)" and the grill-queue G2
outputs.
"""

from doo.events.envelope import IngestionEnvelope, SourceKind, SOURCE_KINDS
from doo.events.l2 import (
    L2Event,
    L2EventBase,
    ParseFailure,
    ParseFailureKind,
    RequestObservation,
    ResponseArtifact,
    ResponseArtifactKind,
)
from doo.events.l3 import (
    EdgeCreated,
    EdgeRemoved,
    L3Event,
    NodeCreated,
    NodeUpdated,
    Reconciliation,
)
from doo.events.slice4 import (
    DispatchStatus,
    DISPATCH_STATUSES,
    ExecutedAsEdge,
    Finding,
    FindingCategory,
    FindingSeverity,
    PayloadClass,
    TestCase,
    TestClass,
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
    "ResponseArtifact",
    "ResponseArtifactKind",
    "SOURCE_KINDS",
    "SourceKind",
    "TestCase",
    "TestClass",
]
