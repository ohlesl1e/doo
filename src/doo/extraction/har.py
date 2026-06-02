"""HAR 1.2 parser (slice-1 T2, deep module B).

Turns a HAR blob into a sequence of `L2Event`s. Slice-1 scope is the simplest
contents: anonymous unauthenticated `GET`s with concrete paths, no body
extraction, no path templating, no response-artifact extraction. Each entry
becomes exactly one `RequestObservation` carrying `AuthContextCue(is_anonymous
=True)`.

`ParseFailure` handling is first-class from day one: a malformed entry yields a
`ParseFailure` event (not an exception) so the L2 worker never crashes on bad
input, and other entries in the same HAR still parse. A blob that isn't valid
JSON / isn't a HAR log yields a single whole-blob `ParseFailure`.

No LLM here — deterministic parsing only (CLAUDE.md hard rule).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlsplit

from doo.canonical.identity import canonicalize_host, canonicalize_path, derive_har_source_id
from doo.canonical.value_objects import AuthContextCue, HostRef
from doo.events.envelope import IngestionEnvelope
from doo.events.l2 import (
    L2Event,
    Method,
    ObservedParameter,
    ParseFailure,
    RequestObservation,
)
from doo.ids import L2EventId, ObservationId, SourceId
from doo.observability.ids import new_span_id

# Methods we accept in slice-1. HAR may carry others; an unexpected method on an
# otherwise-valid entry is still parsed (we don't restrict to GET) — scope
# filtering is L4's job, not the parser's. We only reject methods outside the
# HTTP method vocabulary the L2 contract declares.
_VALID_METHODS: frozenset[str] = frozenset(
    ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT")
)

_SOURCE = "har"


def _now() -> datetime:
    return datetime.now(UTC)


def _new_l2_event_id() -> L2EventId:
    return L2EventId(new_span_id() + new_span_id())  # 32 hex chars; per-emission id.


def _parse_started_at(raw: str) -> datetime:
    """Parse a HAR `startedDateTime` (ISO-8601, possibly `Z`-suffixed)."""

    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def parse_har(blob: bytes, envelope: IngestionEnvelope) -> Iterator[L2Event]:
    """Parse a HAR blob into `L2Event`s, propagating envelope correlation fields.

    Yields one `RequestObservation` per well-formed entry and one `ParseFailure`
    per malformed entry. A whole-blob failure (bad JSON / not a HAR log) yields a
    single blob-level `ParseFailure`. Never raises on bad input.
    """

    ingested_at = _now()
    try:
        doc = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        yield _blob_parse_failure(
            envelope,
            ingested_at,
            error_kind="decode_error",
            message=f"HAR blob is not valid UTF-8 JSON: {exc}",
        )
        return

    log = doc.get("log") if isinstance(doc, dict) else None
    if not isinstance(log, dict) or not isinstance(log.get("entries"), list):
        yield _blob_parse_failure(
            envelope,
            ingested_at,
            error_kind="schema_mismatch",
            message="HAR document missing `log.entries` list (not a HAR 1.2 log)",
        )
        return

    entries = log["entries"]
    for index, entry in enumerate(entries):
        yield _parse_entry(entry, index, envelope, ingested_at)


def _parse_entry(
    entry: object,
    index: int,
    envelope: IngestionEnvelope,
    ingested_at: datetime,
) -> L2Event:
    """Parse one HAR entry into a `RequestObservation` or a `ParseFailure`."""

    location_hint = f"log.entries[{index}]"
    try:
        if not isinstance(entry, dict):
            raise _EntryError("missing_required_field", "entry is not an object")

        started_at_raw = entry.get("startedDateTime")
        if not isinstance(started_at_raw, str) or not started_at_raw:
            raise _EntryError("missing_required_field", "entry missing `startedDateTime`")
        observed_at = _parse_started_at(started_at_raw)
        source_id = derive_har_source_id(index, started_at_raw)

        request = entry.get("request")
        if not isinstance(request, dict):
            raise _EntryError("missing_required_field", "entry missing `request` object")

        method_raw = request.get("method")
        if not isinstance(method_raw, str) or method_raw.upper() not in _VALID_METHODS:
            raise _EntryError("schema_mismatch", f"unsupported/missing method {method_raw!r}")
        method: Method = method_raw.upper()  # type: ignore[assignment]

        url = request.get("url")
        if not isinstance(url, str) or not url:
            raise _EntryError("missing_required_field", "request missing `url`")

        host_ref, concrete_path, query_string = _split_url(url)
        query_params = _query_parameters(request, query_string)

        response = entry.get("response")
        response_status, response_size = _response_shape(response)

        observation_id = ObservationId(
            f"{envelope.engagement_id}:{_SOURCE}:{source_id}"
        )
        return RequestObservation(
            event_id=_new_l2_event_id(),
            trace_id=envelope.trace_id,
            span_id=new_span_id(),
            engagement_id=envelope.engagement_id,
            envelope_event_id=envelope.event_id,
            source=_SOURCE,
            source_id=source_id,
            ingested_at=ingested_at,
            observed_at=observed_at,
            confidence=1.0,
            observation_id=observation_id,
            method=method,
            host=host_ref,
            concrete_path=concrete_path,
            query_string=query_string,
            # Slice-1: no body / no parsed inputs / no response artifacts.
            headers=(),
            cookies=(),
            query_params=query_params,
            body_params=(),
            request_body_ref=None,
            auth_context_cue=AuthContextCue(is_anonymous=True),
            response_status=response_status,
            response_headers=(),
            response_body_ref=None,
            response_size_bytes=response_size,
            duration_ms=None,
        )
    except _EntryError as err:
        return _entry_parse_failure(
            envelope,
            ingested_at,
            source_id=SourceId(f"{index}|<unparsed>"),
            error_kind=err.kind,
            message=err.message,
            location_hint=location_hint,
        )
    except Exception as exc:  # noqa: BLE001 - any unexpected shape becomes a ParseFailure
        return _entry_parse_failure(
            envelope,
            ingested_at,
            source_id=SourceId(f"{index}|<unparsed>"),
            error_kind="malformed_blob",
            message=f"unexpected error parsing entry: {exc}",
            location_hint=location_hint,
        )


def _split_url(url: str) -> tuple[HostRef, str, str | None]:
    """Split a request URL into `(HostRef, canonical concrete path, query)`."""

    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        raise _EntryError("schema_mismatch", f"request url not absolute: {url!r}")
    host_ref = canonicalize_host(parts.scheme, parts.hostname, parts.port)
    raw_path = parts.path or "/"
    concrete_path = canonicalize_path(raw_path)
    query_string = parts.query if parts.query else None
    return host_ref, concrete_path, query_string


def _query_parameters(
    request: dict[str, object], query_string: str | None
) -> tuple[ObservedParameter, ...]:
    """Extract query `ObservedParameter`s from a HAR request.

    Prefers HAR's structured `request.queryString` array (`[{name, value}]`);
    falls back to parsing the raw query string when the array is absent. Each
    becomes a flat `ObservedParameter(location="query")` — L3 aggregates these
    into `Parameter` nodes over many observations (the emergent-aggregate model
    in `events/l2.py`). Slice-1 does not scrub query values (no secrets policy
    applies to query inputs here; ADR-0015 governs response artifacts).
    """

    out: list[ObservedParameter] = []
    raw = request.get("queryString")
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name:
                continue
            value = item.get("value")
            out.append(
                ObservedParameter(
                    name=name,
                    location="query",
                    value=value if isinstance(value, str) else None,
                )
            )
        if out:
            # A populated structured array is authoritative.
            return tuple(out)

    # No (or empty) structured array: fall back to parsing the raw query string.
    # Some exporters emit `queryString: []` even for a query URL, so the raw
    # string is the more reliable source when the array is empty.
    if query_string:
        for name, value in parse_qsl(query_string, keep_blank_values=True):
            if name:
                out.append(ObservedParameter(name=name, location="query", value=value or None))
    return tuple(out)


def _response_shape(response: object) -> tuple[int, int]:
    """Extract `(status, size_bytes)` from a HAR response, with safe defaults.

    Slice-1 does not extract ResponseArtifacts; it only records the status and a
    size for the RequestObservation. A missing/odd status is clamped into the
    valid range so a present-but-sloppy response doesn't fail an otherwise-good
    request observation.
    """

    if not isinstance(response, dict):
        return 200, 0  # default 200 when the response object is absent
    status = response.get("status")
    status_int = status if isinstance(status, int) and 100 <= status <= 599 else 200
    size = response.get("bodySize")
    size_int = size if isinstance(size, int) and size >= 0 else 0
    return status_int, size_int


class _EntryError(Exception):
    """Internal signal: a single HAR entry could not be parsed."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


def _blob_parse_failure(
    envelope: IngestionEnvelope,
    ingested_at: datetime,
    *,
    error_kind: str,
    message: str,
) -> ParseFailure:
    return _entry_parse_failure(
        envelope,
        ingested_at,
        source_id=SourceId("blob|<unparsed>"),
        error_kind=error_kind,
        message=message,
        location_hint="log",
    )


def _entry_parse_failure(
    envelope: IngestionEnvelope,
    ingested_at: datetime,
    *,
    source_id: SourceId,
    error_kind: str,
    message: str,
    location_hint: str,
) -> ParseFailure:
    observation_id = ObservationId(
        f"{envelope.engagement_id}:{_SOURCE}:parse_failure:{source_id}"
    )
    return ParseFailure(
        event_id=_new_l2_event_id(),
        trace_id=envelope.trace_id,
        span_id=new_span_id(),
        engagement_id=envelope.engagement_id,
        envelope_event_id=envelope.event_id,
        source=_SOURCE,
        source_id=source_id,
        ingested_at=ingested_at,
        observed_at=ingested_at,
        confidence=1.0,
        observation_id=observation_id,
        error_kind=error_kind,  # type: ignore[arg-type]
        error_message=message,
        location_hint=location_hint,
    )
