"""L2 -> L3 events: `RequestObservation` / `ResponseArtifact` / `ParseFailure`.

Discriminator: `kind`. Each variant carries the trace_id / span_id propagated
from the originating `IngestionEnvelope` (per ADR-0018), plus provenance fields
per ADR-0005, plus the secrets-handling discipline per ADR-0015.

`Parameter` aggregation is *not* L2's job — Parameter nodes are an emergent L3
aggregate over many RequestObservations sharing `(endpoint_id, name, location)`.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from doo.canonical.value_objects import AuthContextCue, BlobRef, HostRef
from doo.ids import (
    EngagementId,
    L2EventId,
    ObservationId,
    Sha256Hex,
    SourceId,
    SpanId,
    TraceId,
)

Method = Literal[
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "TRACE",
    "CONNECT",
]

ParameterLocation = Literal["path", "query", "header", "body", "cookie"]


class ObservedParameter(BaseModel):
    """One observed (location, name, value) tuple inside a request.

    L2 emits these flat under the RequestObservation; L3 aggregates them into
    `Parameter` nodes keyed on `(endpoint_id, name, location)`.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    location: ParameterLocation
    # Raw observed value. Secret-shaped values are scrubbed upstream in L2 per
    # ADR-0015; the dispatcher-trust path is separate.
    value: str | None = None


class L2EventBase(BaseModel):
    """Fields every L2 event variant carries."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    event_id: L2EventId
    trace_id: TraceId
    span_id: SpanId
    engagement_id: EngagementId
    envelope_event_id: UUID
    # Provenance (ADR-0005). `source` and `source_id` together make the L3
    # idempotency key per ADR-0016.
    source: str = Field(min_length=1)
    source_id: SourceId
    ingested_at: datetime
    observed_at: datetime
    # Always 1.0 for clean observations; lower if the parser flagged ambiguity.
    confidence: float = Field(ge=0.0, le=1.0)


_TRACE_RE = re.compile(r"^[0-9a-f]{32}$")
_SPAN_RE = re.compile(r"^[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _check_trace_span(trace_id: str, span_id: str) -> None:
    if not _TRACE_RE.match(trace_id):
        raise ValueError("trace_id must be W3C 16-byte hex (32 lowercase hex chars)")
    if not _SPAN_RE.match(span_id):
        raise ValueError("span_id must be W3C 8-byte hex (16 lowercase hex chars)")


class RequestObservation(L2EventBase):
    """One observed HTTP exchange.

    Mirrors the CONTEXT.md `RequestObservation` term: concrete path, the
    AuthContext used (as a cue, not raw bytes), references to bodies in object
    storage, and a parsed input/response shape. Becomes a `RequestObservation`
    node in L3 with the cross-cutting fields per ADR-0005.
    """

    kind: Literal["request_observation"] = "request_observation"
    observation_id: ObservationId

    # Request side.
    method: Method
    host: HostRef
    concrete_path: str = Field(min_length=1)
    query_string: str | None = None
    headers: tuple[ObservedParameter, ...] = ()
    cookies: tuple[ObservedParameter, ...] = ()
    query_params: tuple[ObservedParameter, ...] = ()
    body_params: tuple[ObservedParameter, ...] = ()
    request_body_ref: BlobRef | None = None

    auth_context_cue: AuthContextCue

    # Response side.
    response_status: int = Field(ge=100, le=599)
    response_headers: tuple[ObservedParameter, ...] = ()
    response_body_ref: BlobRef | None = None
    response_size_bytes: int = Field(ge=0)
    duration_ms: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _validate(self) -> Self:
        _check_trace_span(self.trace_id, self.span_id)
        if not self.concrete_path.startswith("/"):
            raise ValueError("concrete_path must be absolute (start with /)")
        return self


ResponseArtifactKind = Literal[
    "identifier",
    "url",
    "hostname",
    "email",
    "error_message",
    "fingerprint",
    "internal_path",
    "secret_shaped",
    "token",
]


class ResponseArtifact(L2EventBase):
    """One discrete thing extracted from a response.

    Per ADR-0015: for `secret_shaped` / `token` kinds, only `value_hash`,
    `value_length`, `value_preview` are carried. For other kinds, the raw
    substring is carried in `value`. Both populated is invalid.
    """

    kind: Literal["response_artifact"] = "response_artifact"
    observation_id: ObservationId
    request_observation_id: ObservationId
    artifact_kind: ResponseArtifactKind
    # Non-secret kinds: raw value lives here.
    value: str | None = None
    # Secret-shaped kinds: hashed shape only (ADR-0015).
    value_hash: Sha256Hex | None = None
    value_length: int | None = Field(default=None, ge=0)
    value_preview: str | None = None
    location_hint: str | None = None

    @model_validator(mode="after")
    def _secret_discipline(self) -> Self:
        _check_trace_span(self.trace_id, self.span_id)
        is_secret_kind = self.artifact_kind in ("secret_shaped", "token")
        if is_secret_kind:
            if self.value is not None:
                raise ValueError(
                    f"artifact_kind={self.artifact_kind!r}: raw `value` is forbidden; "
                    "carry value_hash + value_length + value_preview only (ADR-0015)"
                )
            if self.value_hash is None or self.value_length is None:
                raise ValueError(
                    f"artifact_kind={self.artifact_kind!r}: value_hash and value_length required"
                )
            if not _SHA256_RE.match(self.value_hash):
                raise ValueError("value_hash must be 64 lowercase hex chars")
        else:
            if self.value is None:
                raise ValueError(
                    f"artifact_kind={self.artifact_kind!r}: `value` is required for non-secret kinds"
                )
            if self.value_hash is not None or self.value_length is not None:
                raise ValueError(
                    f"artifact_kind={self.artifact_kind!r}: non-secret kinds must not carry "
                    "value_hash / value_length (those are the secret-shape fields)"
                )
        return self


ParseFailureKind = Literal[
    "malformed_blob",
    "schema_mismatch",
    "missing_required_field",
    "decode_error",
]


class ParseFailure(L2EventBase):
    """First-class observation that L2 could not parse the blob (or an entry of it).

    Becomes a `ParseFailure` node so audit can see what didn't make it through.
    Re-extraction with a fixed parser may produce real observations that
    supersede this; the prior ParseFailure is marked `status = "retracted"`.
    """

    kind: Literal["parse_failure"] = "parse_failure"
    observation_id: ObservationId
    error_kind: ParseFailureKind
    error_message: str = Field(min_length=1)
    location_hint: str | None = None

    @model_validator(mode="after")
    def _trace(self) -> Self:
        _check_trace_span(self.trace_id, self.span_id)
        return self


# Discriminated union over `kind`. Pydantic v2 enforces the discriminator.
L2Event = Annotated[
    RequestObservation | ResponseArtifact | ParseFailure,
    Field(discriminator="kind"),
]
