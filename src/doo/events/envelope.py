"""L1 -> L2 `IngestionEnvelope`.

One envelope per arrival on the `ingest` Redis Stream. L1 validates the
envelope only; blob content is opaque at L1. Malformed blobs surface as
`ParseFailure` events from L2.

See ARCHITECTURE.md "Layer contracts (L1 -> L2 -> L3)" and ADR-0018 (trace_id /
span_id from day one).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from doo.ids import (
    BlobKey,
    EngagementId,
    EventId,
    IdempotencyKey,
    Sha256Hex,
    SpanId,
    TraceId,
)

# Closed source enum per the L1 contract. Forces the ADR-0012 "is this a
# tester-side fact?" conversation whenever a new source is added.
SourceKind = Literal[
    "har",
    "burp-streamed",
    "nuclei",
    "agent",
    "manual",
    "logger++",
    "ffuf",
    "subfinder",
]
SOURCE_KINDS: tuple[SourceKind, ...] = (
    "har",
    "burp-streamed",
    "nuclei",
    "agent",
    "manual",
    "logger++",
    "ffuf",
    "subfinder",
)

_TRACE_RE = re.compile(r"^[0-9a-f]{32}$")
_SPAN_RE = re.compile(r"^[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class IngestionEnvelope(BaseModel):
    """Canonical L1 -> L2 envelope.

    `extra = "forbid"` is the schema-evolution discipline: schema changes are
    stop-the-world deploys; no embedded `schema_version`. Long-term audit is
    satisfied by re-running current parsers against historic blobs in object
    storage.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    event_id: UUID
    trace_id: TraceId
    span_id: SpanId
    engagement_id: EngagementId
    source: SourceKind
    source_version: str | None
    blob_ref: BlobKey
    blob_format: str = Field(min_length=1)
    blob_sha256: Sha256Hex
    idempotency_key: IdempotencyKey
    received_at: datetime
    producer_id: str = Field(min_length=1)
    bytes_size: int = Field(ge=0)

    @model_validator(mode="after")
    def _trace_format(self) -> Self:
        if not _TRACE_RE.match(self.trace_id):
            raise ValueError("trace_id must be W3C 16-byte hex (32 lowercase hex chars)")
        if not _SPAN_RE.match(self.span_id):
            raise ValueError("span_id must be W3C 8-byte hex (16 lowercase hex chars)")
        if not _SHA256_RE.match(self.blob_sha256):
            raise ValueError("blob_sha256 must be 64 lowercase hex chars")
        return self


# Backwards-compat alias for code that wants to grab the L1 event_id type.
__all__ = ["IngestionEnvelope", "SourceKind", "SOURCE_KINDS", "EventId"]
