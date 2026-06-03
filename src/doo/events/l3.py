"""L3 -> consumers: low-level structural events on `l3-events` stream.

Discriminator: `kind`. Consumers (planner, coverage, audit) compose business
meaning by filtering on `node_type` / `edge_type`. Per ADR-0017, every payload
carries `commit_id`, `trace_id`, `span_id`, `engagement_id`, `emitted_at`.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from doo.ids import CommitId, EngagementId, SpanId, TraceId

_TRACE_RE = re.compile(r"^[0-9a-f]{32}$")
_SPAN_RE = re.compile(r"^[0-9a-f]{16}$")


class _L3EventBase(BaseModel):
    """Fields every l3-events payload carries."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    commit_id: CommitId
    trace_id: TraceId
    span_id: SpanId
    engagement_id: EngagementId
    emitted_at: datetime

    @model_validator(mode="after")
    def _trace_format(self) -> Self:
        if not _TRACE_RE.match(self.trace_id):
            raise ValueError("trace_id must be W3C 16-byte hex (32 lowercase hex chars)")
        if not _SPAN_RE.match(self.span_id):
            raise ValueError("span_id must be W3C 8-byte hex (16 lowercase hex chars)")
        return self


class NodeCreated(_L3EventBase):
    """A new node was created at commit time."""

    kind: Literal["node_created"] = "node_created"
    node_type: str = Field(min_length=1)
    node_id: str = Field(min_length=1)
    properties: dict[str, Any]


class PropertyChange(BaseModel):
    """An old/new value pair for one changed property on a `NodeUpdated`."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)
    old: Any
    new: Any


# Backwards-compatible alias (the type was originally underscore-private).
_PropertyChange = PropertyChange


class NodeUpdated(_L3EventBase):
    """Properties of an existing node changed."""

    kind: Literal["node_updated"] = "node_updated"
    node_type: str = Field(min_length=1)
    node_id: str = Field(min_length=1)
    # Property name -> {old, new}.
    changed_properties: dict[str, PropertyChange]


class EdgeCreated(_L3EventBase):
    """A new edge between two nodes."""

    kind: Literal["edge_created"] = "edge_created"
    edge_type: str = Field(min_length=1)
    from_node: str = Field(min_length=1)
    to_node: str = Field(min_length=1)
    properties: dict[str, Any] = Field(default_factory=dict)


EdgeRemovalReason = Literal["retemplating", "reconciliation", "retraction"]


class EdgeRemoved(_L3EventBase):
    """An edge was removed.

    Per ADR-0001 / Step 5, retraction is a flag — the edge removal is part of
    re-templating or merge mechanics, not data deletion.
    """

    kind: Literal["edge_removed"] = "edge_removed"
    edge_type: str = Field(min_length=1)
    from_node: str = Field(min_length=1)
    to_node: str = Field(min_length=1)
    reason: EdgeRemovalReason


class Reconciliation(_L3EventBase):
    """Multi-step atomic merge.

    Consumers need this as one event because the underlying edge re-pointing
    plus status update on the orphan must be observed atomically.
    Applies to Principal-merge (ADR-0010), Tenant-merge (ADR-0008),
    Asset-merge (ADR-0011).
    """

    kind: Literal["reconciliation"] = "reconciliation"
    node_type: str = Field(min_length=1)
    survivor_id: str = Field(min_length=1)
    retracted_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)


L3Event = Annotated[
    NodeCreated | NodeUpdated | EdgeCreated | EdgeRemoved | Reconciliation,
    Field(discriminator="kind"),
]
