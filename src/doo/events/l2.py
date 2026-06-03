"""L2 -> L3 events: `RequestObservation` / `ParseFailure`.

Response extraction does NOT emit a node per value (the retired `ResponseArtifact`;
ADR-0023). Each `RequestObservation` records its extracted value occurrences
inline (`value_candidates`, `output` role) plus one-per-response diagnostics
(`server_fingerprint`, `error_excerpt`). A deferred promotion pass at flush mints
an `ObservedValue` only for values clearing the shape-allowlist.

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
from doo.canonical.values import CandidateKind, is_secret_kind
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


class BodyParam(BaseModel):
    """One parameter extracted from a request body (T5).

    A richer sibling of `ObservedParameter` for body inputs: it additionally
    carries the body's `content_type` and, for structured (JSON) bodies, an
    RFC 6901 `json_pointer` addressing the leaf the value came from
    (e.g. `/user/profile/email`). For flat bodies (form-urlencoded, multipart
    text fields) `json_pointer` is `None`.

    L2 emits these flat under the `RequestObservation`; L3 aggregates them into
    `Parameter` nodes keyed `(engagement_id, endpoint_id, name, location="body")`,
    exactly like query/path params (the emergent-aggregate model). The aggregate
    `Parameter.location` is always `"body"`.

    Secret discipline (ADR-0015): known-secret-shape body values are *not*
    surfaced here as raw `value`s — see `extraction/har.py`'s
    `# TODO(secret-shape-bodies)`. Until that lands, `value` carries the raw leaf
    for non-secret bodies; the raw body itself always lives only in object storage.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    content_type: str = Field(min_length=1)
    # RFC 6901 JSON Pointer for JSON-body leaves; None for flat bodies.
    json_pointer: str | None = None
    value: str | None = None


ValueRole = Literal["output", "input"]
ValueSection = Literal["body", "header"]


class ValueCandidate(BaseModel):
    """One extracted value occurrence, recorded inline on a `RequestObservation`.

    Supersedes the per-extraction `ResponseArtifact` node (ADR-0023): candidates
    are arrays on one observation, not N nodes. A deferred promotion pass at flush
    aggregates these by `value_hash` (engagement-scoped) and mints an
    `ObservedValue` for kinds in the shape-allowlist.

    `role` is `output` for values surfaced in a response; `input` for values
    *sent* as request parameters (path/query/body) — the leak-to-input branch
    (#16, ADR-0023). `section` is `body` or `header`.

    `parameter_name` is set for `input`-role candidates: the name of the request
    parameter (query key, body-leaf name) that carried the value. It feeds the
    `SENT_VALUE {parameter_name}` edge from the consuming request to the promoted
    `ObservedValue`. Output candidates leave it `None` (they carry a structural
    location — `header_name` / `json_pointer` / byte offsets — instead).

    Secret discipline (ADR-0015): for `secret` / `token` kinds, `value` is null and
    only `value_hash` + `value_length` + `value_preview` (first 8 chars) are
    carried; the raw value lives only in the response/request-body blob. Non-secret
    kinds carry the raw `value` and a `value_hash` over its normalised form.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    value_hash: Sha256Hex
    kind: CandidateKind
    extractor: str = Field(min_length=1)
    role: ValueRole = "output"
    section: ValueSection = "body"
    value: str | None = None
    value_length: int | None = Field(default=None, ge=0)
    value_preview: str | None = None
    header_name: str | None = None
    json_pointer: str | None = None
    byte_start: int | None = Field(default=None, ge=0)
    byte_end: int | None = Field(default=None, ge=0)
    # Set for input-role candidates: the request parameter that carried the value
    # (the `SENT_VALUE.parameter_name`). None for output candidates.
    parameter_name: str | None = None

    @model_validator(mode="after")
    def _shape(self) -> Self:
        if not _SHA256_RE.match(self.value_hash):
            raise ValueError("value_hash must be 64 lowercase hex chars")
        if is_secret_kind(self.kind):
            if self.value is not None:
                raise ValueError(
                    f"kind={self.kind!r}: raw `value` is forbidden; carry "
                    "value_hash + value_length + value_preview only (ADR-0015)"
                )
            if self.value_length is None:
                raise ValueError(f"kind={self.kind!r}: value_length required for secrets")
        else:
            if self.value is None:
                raise ValueError(f"kind={self.kind!r}: `value` is required for non-secret kinds")
        if self.section == "header":
            if not self.header_name:
                raise ValueError("header candidates must carry a header_name")
        if self.role == "input" and not self.parameter_name:
            raise ValueError("input candidates must carry a parameter_name")
        return self


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
    # Legacy flat body params (kept for back-compat; T5 emits the richer
    # `request_body_params` below carrying content_type + RFC 6901 json_pointer).
    body_params: tuple[ObservedParameter, ...] = ()
    request_body_params: tuple[BodyParam, ...] = ()
    request_body_ref: BlobRef | None = None

    auth_context_cue: AuthContextCue

    # Response side.
    response_status: int = Field(ge=100, le=599)
    response_headers: tuple[ObservedParameter, ...] = ()
    response_body_ref: BlobRef | None = None
    response_size_bytes: int = Field(ge=0)
    duration_ms: int | None = Field(default=None, ge=0)

    # ADR-0023: extracted value occurrences (inline, replacing ResponseArtifact
    # nodes) + one-per-response diagnostics (inline, replacing fingerprint/error
    # nodes). The promotion pass at flush turns allowlisted candidates into
    # `ObservedValue`s; diagnostics become RequestObservation node properties.
    value_candidates: tuple[ValueCandidate, ...] = ()
    server_fingerprint: str | None = None
    error_excerpt: str | None = None

    @model_validator(mode="after")
    def _validate(self) -> Self:
        _check_trace_span(self.trace_id, self.span_id)
        if not self.concrete_path.startswith("/"):
            raise ValueError("concrete_path must be absolute (start with /)")
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
# `ResponseArtifact` retired (ADR-0023): values are inline candidates + a
# promotion pass; `RequestObservation` and `ParseFailure` remain.
L2Event = Annotated[
    RequestObservation | ParseFailure,
    Field(discriminator="kind"),
]
