"""HAR 1.2 parser (slice-1 T2, deep module B).

Turns a HAR blob into a sequence of `L2Event`s. Each entry becomes one
`RequestObservation` carrying an `AuthContextCue` extracted from its request
headers/cookies — hashed at the L2 boundary so raw tokens never leave this layer
(ADR-0015). Anonymous requests carry `AuthContextCue(is_anonymous=True)`.

Request/response bodies are uploaded to object storage and referenced by `BlobRef`
on the observation (T5): the graph holds only the hash + metadata + storage key,
never the raw bytes (CLAUDE.md hard rule / ADR-0015). Body *parameters* are
extracted deterministically — form-urlencoded pairs, JSON leaves with RFC 6901
JSON Pointers, and best-effort multipart text fields. Known-secret-shape leaf
values are not surfaced as raw `BodyParam.value`s; the raw token lives only in the
uploaded body. Response value-candidate extraction (ADR-0023) records inline
`ValueCandidate`s + diagnostics on the observation; no `ResponseArtifact` nodes.

`ParseFailure` handling is first-class from day one: a malformed entry yields a
`ParseFailure` event (not an exception) so the L2 worker never crashes on bad
input, and other entries in the same HAR still parse. A blob that isn't valid
JSON / isn't a HAR log yields a single whole-blob `ParseFailure`.

No LLM here — deterministic parsing only (CLAUDE.md hard rule).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from email.parser import BytesParser
from email.policy import default as default_email_policy
from typing import Protocol
from urllib.parse import parse_qsl, urlsplit

import jwt

from doo.canonical.cookies import cookie_feeds_identity
from doo.canonical.identity import (
    canonicalize_host,
    canonicalize_path,
    compute_auth_hash,
    derive_har_source_id,
)
from doo.canonical.value_objects import AuthContextCue, BlobRef, HostRef
from doo.events.envelope import IngestionEnvelope
from doo.events.l2 import (
    BodyParam,
    L2Event,
    Method,
    ObservedParameter,
    ParseFailure,
    RequestObservation,
    ValueCandidate,
)
from doo.extraction.artifacts import (
    CandidateOccurrence,
    ResponseDiagnostics,
    extract_candidates,
    extract_diagnostics,
    extract_input_candidate,
)
from doo.ids import (
    EngagementId,
    L2EventId,
    ObservationId,
    Sha256Hex,
    SourceId,
)
from doo.observability.ids import new_span_id


class BodyUploader(Protocol):
    """Sink for raw request/response body bytes (the T5 MinIO upload).

    `parse_har` is handed one of these by the L2 worker (a `BlobClient`). It is a
    Protocol so the parser stays decoupled from boto3 and is trivially fakeable in
    unit tests. `raw` is the *decoded* body (the caller resolves base64); the
    implementation content-addresses it by `sha256(raw)` and returns a `BlobRef`.
    """

    def put_body(
        self,
        engagement_id: EngagementId,
        *,
        raw: bytes,
        content_type: str,
        encoding: str | None = None,
    ) -> BlobRef: ...

# Header names (lowercased) treated as API-key-bearing. `Authorization` is handled
# separately (bearer / basic); these are the common bespoke key headers.
_API_KEY_HEADER_NAMES: frozenset[str] = frozenset(
    ("x-api-key", "apikey", "api-key", "x-api-token", "x-auth-token", "x-access-token")
)

# Methods we accept in slice-1. HAR may carry others; an unexpected method on an
# otherwise-valid entry is still parsed (we don't restrict to GET) — scope
# filtering is L4's job, not the parser's. We only reject methods outside the
# HTTP method vocabulary the L2 contract declares.
_VALID_METHODS: frozenset[str] = frozenset(
    ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT")
)

_SOURCE = "har"

_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
_DEFAULT_CONTENT_TYPE = "application/octet-stream"

# Known-secret-shape value detectors (T5 / ADR-0015). A leaf body value matching
# any of these is treated as a secret and its raw value is *not* surfaced on a
# BodyParam — the body still lands in object storage, but the graph never sees the
# raw token. Secret-shape *extraction* (emitting hashed shape, like response
# artifacts) is deferred — see `# TODO(secret-shape-bodies)` below.
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
# Parameter *names* that conventionally carry secrets regardless of value shape.
_SECRET_NAME_HINTS: frozenset[str] = frozenset(
    (
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "client_secret",
        "private_key",
    )
)


def _is_secret_shaped(name: str, value: str) -> bool:
    """True if `(name, value)` looks like a secret whose raw value must not surface.

    Conservative: a JWT-shaped value, or a non-trivial value under a
    secret-conventional parameter name. Used only to *suppress* the raw value on a
    BodyParam (ADR-0015); the body itself is still uploaded to object storage.
    """

    if _JWT_RE.match(value):
        return True
    if name.lower() in _SECRET_NAME_HINTS and value:
        return True
    return False


def _now() -> datetime:
    return datetime.now(UTC)


def _new_l2_event_id() -> L2EventId:
    return L2EventId(new_span_id() + new_span_id())  # 32 hex chars; per-emission id.


def _parse_started_at(raw: str) -> datetime:
    """Parse a HAR `startedDateTime` (ISO-8601, possibly `Z`-suffixed)."""

    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def parse_har(
    blob: bytes,
    envelope: IngestionEnvelope,
    body_uploader: BodyUploader | None = None,
) -> Iterator[L2Event]:
    """Parse a HAR blob into `L2Event`s, propagating envelope correlation fields.

    Yields one `RequestObservation` per well-formed entry and one `ParseFailure`
    per malformed entry. A whole-blob failure (bad JSON / not a HAR log) yields a
    single blob-level `ParseFailure`. Never raises on bad input.

    When `body_uploader` is supplied (the L2 worker always supplies a `BlobClient`),
    request/response bodies are uploaded to object storage and referenced via
    `BlobRef`s on the emitted `RequestObservation` (T5). When it is `None` (pure
    parser unit tests), bodies are skipped and the refs are `None`.
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
        yield from _parse_entry(
            entry,
            index,
            envelope,
            ingested_at,
            body_uploader,
            session_cookie_names=envelope.session_cookie_names,
        )


def _parse_entry(
    entry: object,
    index: int,
    envelope: IngestionEnvelope,
    ingested_at: datetime,
    body_uploader: BodyUploader | None,
    *,
    session_cookie_names: tuple[str, ...] = (),
) -> Iterator[L2Event]:
    """Parse one HAR entry into a `RequestObservation` with inline value candidates.

    The extracted value occurrences (`output` role) and one-per-response
    diagnostics (`server_fingerprint`, `error_excerpt`) are recorded inline on the
    emitted observation (ADR-0023) — no per-value `ResponseArtifact` event. A
    malformed entry yields a single `ParseFailure` instead.
    """

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
        auth_context_cue = extract_auth_context_cue(
            request, session_cookie_names=session_cookie_names
        )

        response = entry.get("response")
        response_status, response_size = _response_shape(response)

        # --- T5: bodies -> object storage, body params extracted. ---
        request_body_ref, request_body_params, body_input_candidates = (
            _extract_request_body(request, envelope.engagement_id, body_uploader)
        )
        response_body_ref, response_body_bytes, response_content_type = (
            _extract_response_body(response, envelope.engagement_id, body_uploader)
        )

        observation_id = ObservationId(
            f"{envelope.engagement_id}:{_SOURCE}:{source_id}"
        )
        # --- ADR-0023: inline value candidates + diagnostics (replaces T6 nodes). ---
        output_candidates, diagnostics = _extract_response_values(
            response=response,
            response_body_bytes=response_body_bytes,
            response_content_type=response_content_type,
            response_status=response_status,
        )
        # #16 leak-to-input: request-parameter values as `input`-role candidates
        # (query keys + body leaves), hashed via the same canonicalisation.
        input_candidates = tuple(
            _to_value_candidate(o)
            for o in (*_query_input_candidates(query_params), *body_input_candidates)
        )
        value_candidates = (*output_candidates, *input_candidates)
        yield RequestObservation(
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
            # Slice-1: no parsed request headers/cookies surfaced flat.
            headers=(),
            cookies=(),
            query_params=query_params,
            body_params=(),
            request_body_params=request_body_params,
            request_body_ref=request_body_ref,
            auth_context_cue=auth_context_cue,
            response_status=response_status,
            response_headers=(),
            response_body_ref=response_body_ref,
            response_size_bytes=response_size,
            duration_ms=None,
            value_candidates=value_candidates,
            server_fingerprint=diagnostics.server_fingerprint,
            error_excerpt=diagnostics.error_excerpt,
        )
        return
    except _EntryError as err:
        yield _entry_parse_failure(
            envelope,
            ingested_at,
            source_id=SourceId(f"{index}|<unparsed>"),
            error_kind=err.kind,
            message=err.message,
            location_hint=location_hint,
        )
    except Exception as exc:  # noqa: BLE001 - any unexpected shape becomes a ParseFailure
        yield _entry_parse_failure(
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


def _header_map(request: dict[str, object]) -> dict[str, str]:
    """Lowercased header name -> value from a HAR request's `headers` array.

    On duplicate header names, the last value wins (HAR rarely repeats them).
    """

    out: dict[str, str] = {}
    raw = request.get("headers")
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            value = item.get("value")
            if isinstance(name, str) and isinstance(value, str):
                out[name.lower()] = value
    return out


def _cookie_pairs(request: dict[str, object]) -> list[tuple[str, str]]:
    """`(name, value)` cookie pairs from a HAR request's `cookies` array."""

    out: list[tuple[str, str]] = []
    raw = request.get("cookies")
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            value = item.get("value")
            if isinstance(name, str) and name and isinstance(value, str):
                out.append((name, value))
    return out


def _decode_jwt_claims(token: str) -> dict[str, str | int | float | bool | None]:
    """Decode a JWT *without verification* (claim peek only, never a trust call).

    Per ADR-0015 / the issue: `verify_signature=False`, `verify_exp=False`. Any
    non-JWT bearer token (opaque, not three base64url segments) yields `{}`.
    Only scalar claims are kept (the cue's `identity_claims` type is scalar-valued);
    structured claims are dropped for the cue.
    """

    try:
        decoded = jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False},
        )
    except jwt.PyJWTError:
        return {}
    if not isinstance(decoded, dict):
        return {}
    claims: dict[str, str | int | float | bool | None] = {}
    for key, value in decoded.items():
        if isinstance(value, str | int | float | bool) or value is None:
            claims[str(key)] = value
    return claims


def extract_auth_context_cue(
    request: dict[str, object], *, session_cookie_names: tuple[str, ...] = ()
) -> AuthContextCue:
    """Extract an `AuthContextCue` from a HAR request, hashing at the L2 boundary.

    Per ADR-0015 raw tokens never leave L2: every credential is reduced to a
    sha256 here and the raw bytes are dropped. Detects:

    - `Authorization: Bearer <jwt>` -> `bearer_token_hash` + decoded (unverified)
      `identity_claims`.
    - `Authorization: Basic <b64>` -> hash of the *username only*; the password is
      never carried forward.
    - cookies -> per-cookie-name value hashes (sorted by name).
    - `X-API-Key`-style headers -> per-header-name value hashes.

    When no auth-bearing material is present, returns the anonymous singleton cue
    (`is_anonymous=True`).
    """

    headers = _header_map(request)

    bearer_token_hash: Sha256Hex | None = None
    basic_auth_user_hash: Sha256Hex | None = None
    identity_claims: dict[str, str | int | float | bool | None] = {}

    authorization = headers.get("authorization", "").strip()
    if authorization:
        scheme, _, credential = authorization.partition(" ")
        scheme_lower = scheme.lower()
        credential = credential.strip()
        if scheme_lower == "bearer" and credential:
            bearer_token_hash = compute_auth_hash("bearer", credential)
            identity_claims = _decode_jwt_claims(credential)
        elif scheme_lower == "basic" and credential:
            username = _basic_auth_username(credential)
            if username is not None:
                # Hash the username only — the password never leaves L2.
                basic_auth_user_hash = compute_auth_hash("basic_auth", username)

    # Authoritative engagement allowlist (ADR-0026 #28) when configured; else the
    # shape heuristic decides which cookies are session credentials.
    allowlist = frozenset(session_cookie_names) if session_cookie_names else None
    cookie_hashes = tuple(
        compute_auth_hash("cookie", value)
        for _name, value in sorted(_cookie_pairs(request), key=lambda p: p[0])
        if cookie_feeds_identity(_name, value, allowlist=allowlist)
    )

    api_key_headers: dict[str, Sha256Hex] = {}
    for name_lower, value in headers.items():
        if name_lower in _API_KEY_HEADER_NAMES and value:
            api_key_headers[name_lower] = compute_auth_hash("api_key", value)

    if (
        bearer_token_hash is None
        and basic_auth_user_hash is None
        and not cookie_hashes
        and not api_key_headers
    ):
        return AuthContextCue(is_anonymous=True)

    return AuthContextCue(
        is_anonymous=False,
        bearer_token_hash=bearer_token_hash,
        cookie_session_hashes=cookie_hashes,
        api_key_headers=api_key_headers,
        basic_auth_user_hash=basic_auth_user_hash,
        identity_claims=identity_claims,
    )


def _basic_auth_username(credential: str) -> str | None:
    """Decode a base64 `Basic` credential and return the username only.

    Returns `None` if the credential isn't decodable base64 `user:pass`. The
    password is intentionally never returned — it must not leave L2 (ADR-0015).
    """

    try:
        raw = base64.b64decode(credential, validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return None
    username, sep, _password = raw.partition(":")
    if not sep:
        return None
    return username


def _response_shape(response: object) -> tuple[int, int]:
    """Extract `(status, size_bytes)` from a HAR response, with safe defaults.

    Records the status and a size for the RequestObservation. A missing/odd status
    is clamped into the valid range so a present-but-sloppy response doesn't fail
    an otherwise-good request observation.
    """

    if not isinstance(response, dict):
        return 200, 0  # default 200 when the response object is absent
    status = response.get("status")
    status_int = status if isinstance(status, int) and 100 <= status <= 599 else 200
    size = response.get("bodySize")
    size_int = size if isinstance(size, int) and size >= 0 else 0
    return status_int, size_int


# --------------------------------------------------------------------------- #
# T5: body extraction + body-parameter parsing.
# --------------------------------------------------------------------------- #


def _content_type_of(headers: dict[str, str], fallback_mime: str | None) -> str:
    """Resolve a body's content type from request/response headers (or mimeType).

    Prefers the `Content-Type` header (full value, params kept). Falls back to the
    HAR `postData.mimeType` / `content.mimeType` when no header is present, then to
    `application/octet-stream`.
    """

    raw = headers.get("content-type") or fallback_mime
    return raw.strip() if isinstance(raw, str) and raw.strip() else _DEFAULT_CONTENT_TYPE


def _base_mime(content_type: str) -> str:
    """The bare media type, lowercased, sans parameters (`;charset=...`)."""

    return content_type.split(";", 1)[0].strip().lower()


def _content_encoding(headers: dict[str, str]) -> str | None:
    """The compression encoding HAR/headers declare (`gzip` / `br`), else None.

    Informational only — HAR `postData.text` / `content.text` is already the
    decompressed body, so we never decompress here; we just record the metadata on
    the `BlobRef.encoding` so downstream knows the wire encoding.
    """

    enc = headers.get("content-encoding", "").strip().lower()
    if "gzip" in enc:
        return "gzip"
    if "br" in enc:
        return "br"
    return None


def _extract_request_body(
    request: dict[str, object],
    engagement_id: str,
    body_uploader: BodyUploader | None,
) -> tuple[BlobRef | None, tuple[BodyParam, ...], tuple[CandidateOccurrence, ...]]:
    """Upload a request body to object storage and parse its parameters.

    Returns `(request_body_ref, body_params, input_candidates)`. No body ->
    `(None, (), ())` with **no** object created. The body text comes from
    `postData.text`, or is reconstructed from `postData.params` for form-encoded
    entries. Body-param parsing is content-type driven (form / JSON / multipart /
    other). The `input_candidates` are the `input`-role value occurrences over the
    raw body-leaf values (#16, the leak-to-input pivot).
    """

    post = request.get("postData")
    if not isinstance(post, dict):
        return None, (), ()

    headers = _header_map(request)
    fallback_mime = post.get("mimeType") if isinstance(post.get("mimeType"), str) else None
    content_type = _content_type_of(headers, fallback_mime)
    base_mime = _base_mime(content_type)

    raw = _request_body_bytes(post, base_mime)
    if raw is None:
        return None, (), ()

    body_params, input_candidates = _parse_body_params(raw, base_mime, content_type)

    if body_uploader is None:
        return None, body_params, input_candidates
    ref = body_uploader.put_body(
        EngagementId(engagement_id),
        raw=raw,
        content_type=content_type,
        encoding=_content_encoding(headers),
    )
    return ref, body_params, input_candidates


def _request_body_bytes(post: dict[str, object], base_mime: str) -> bytes | None:
    """The raw request-body bytes from a HAR `postData`, or None when absent.

    Prefers `postData.text`; for form-encoded entries with no text, reconstructs
    the body from the structured `postData.params` array. An empty body yields
    `None` (no object is created for an empty body).
    """

    text = post.get("text")
    if isinstance(text, str) and text:
        return text.encode("utf-8")

    if base_mime == _FORM_CONTENT_TYPE:
        params = post.get("params")
        if isinstance(params, list):
            pairs: list[tuple[str, str]] = []
            for item in params:
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                if not isinstance(name, str) or not name:
                    continue
                value = item.get("value")
                pairs.append((name, value if isinstance(value, str) else ""))
            if pairs:
                from urllib.parse import urlencode

                return urlencode(pairs).encode("utf-8")
    return None


def _extract_response_body(
    response: object,
    engagement_id: str,
    body_uploader: BodyUploader | None,
) -> tuple[BlobRef | None, bytes | None, str]:
    """Upload a response body to object storage; return ref + decoded bytes + ctype.

    `response.content.encoding == "base64"` is decoded *before* upload so the
    stored bytes are raw and `BlobRef.sha256` is over the raw bytes (ADR-0015 /
    acceptance criterion). No body -> `(None, None, default ctype)` with no object
    created.

    The decoded `raw` bytes + resolved `content_type` are returned alongside the
    ref so the T6 response-artifact pass can extract over the same bytes that were
    content-addressed — without re-reading the blob. When no `body_uploader` is
    supplied (pure parser unit tests) the ref is `None` but the bytes are still
    returned so artifact extraction is exercised independently of upload.
    """

    if not isinstance(response, dict):
        return None, None, _DEFAULT_CONTENT_TYPE
    content = response.get("content")
    if not isinstance(content, dict):
        return None, None, _DEFAULT_CONTENT_TYPE

    text = content.get("text")
    if not isinstance(text, str) or not text:
        return None, None, _DEFAULT_CONTENT_TYPE

    encoding = content.get("encoding")
    if isinstance(encoding, str) and encoding.lower() == "base64":
        try:
            raw = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            # Declared base64 but not decodable: store the literal text bytes
            # rather than dropping the body (best-effort, never crash).
            raw = text.encode("utf-8")
    else:
        raw = text.encode("utf-8")

    headers = _header_map(response)
    fallback_mime = (
        content.get("mimeType") if isinstance(content.get("mimeType"), str) else None
    )
    content_type = _content_type_of(headers, fallback_mime)

    if not raw:
        return None, None, content_type

    if body_uploader is None:
        return None, raw, content_type
    ref = body_uploader.put_body(
        EngagementId(engagement_id),
        raw=raw,
        content_type=content_type,
        encoding=_content_encoding(headers),
    )
    return ref, raw, content_type


# --------------------------------------------------------------------------- #
# ADR-0023: inline value-candidate extraction + diagnostics.
# --------------------------------------------------------------------------- #


def _to_value_candidate(occ: CandidateOccurrence) -> ValueCandidate:
    """Convert a pure `CandidateOccurrence` into the L2 `ValueCandidate` model.

    Secret discipline (ADR-0015) was already applied at the extractor edge: secret
    occurrences arrive with `value=None` and a `value_hash` over the raw bytes; this
    only re-shapes the dataclass into the strict Pydantic model recorded inline.
    """

    return ValueCandidate(
        value_hash=occ.value_hash,
        kind=occ.kind,
        extractor=occ.extractor,
        role=occ.role,  # type: ignore[arg-type]
        section=occ.section,  # type: ignore[arg-type]
        value=occ.value,
        value_length=occ.value_length,
        value_preview=occ.value_preview,
        header_name=occ.header_name,
        json_pointer=occ.json_pointer,
        byte_start=occ.byte_start,
        byte_end=occ.byte_end,
        parameter_name=occ.parameter_name,
    )


_QUERY_INPUT_EXTRACTOR = "request-param:query_v1"


def _query_input_candidates(
    query_params: tuple[ObservedParameter, ...],
) -> list[CandidateOccurrence]:
    """`input`-role candidates for a request's query parameter values (#16).

    One per query param carrying a non-empty value; classified + hashed via the
    same canonicalisation as response outputs (secret-shaped suppressed to
    hash+preview only). Blank-valued params contribute no value occurrence.
    """

    out: list[CandidateOccurrence] = []
    for param in query_params:
        if param.value:
            out.append(
                extract_input_candidate(
                    param.name, param.value, extractor=_QUERY_INPUT_EXTRACTOR
                )
            )
    return out


def _extract_response_values(
    *,
    response: object,
    response_body_bytes: bytes | None,
    response_content_type: str,
    response_status: int,
) -> tuple[tuple[ValueCandidate, ...], ResponseDiagnostics]:
    """Run the deterministic extractors over a response (ADR-0023).

    Returns `(value_candidates, diagnostics)`: the `output`-role candidate
    occurrences recorded inline on the observation, and the one-per-response
    diagnostics (`server_fingerprint`, `error_excerpt`) recorded as inline
    observation properties. No per-value `ResponseArtifact` event is emitted.
    """

    headers = _header_map(response) if isinstance(response, dict) else {}
    occurrences: list[CandidateOccurrence] = []
    if response_body_bytes is not None:
        occurrences.extend(
            extract_candidates(
                response_body_bytes, content_type=response_content_type
            )
        )
    diagnostics = extract_diagnostics(
        response_body_bytes, headers, status=response_status
    )
    candidates = tuple(_to_value_candidate(o) for o in occurrences)
    return candidates, diagnostics


def _parse_body_params(
    raw: bytes, base_mime: str, content_type: str
) -> tuple[tuple[BodyParam, ...], tuple[CandidateOccurrence, ...]]:
    """Parse a request body into `BodyParam`s + `input`-role value candidates.

    - `application/x-www-form-urlencoded` -> one BodyParam per `name=value` pair,
      `json_pointer=None`.
    - `application/json` -> recurse the structure; one BodyParam per leaf with an
      RFC 6901 JSON Pointer (`/user/profile/email`, `/items/0/sku`).
    - `multipart/form-data` -> best-effort text fields (RFC 7578 lite); binary
      parts (those with a `filename` or non-text content type) are skipped.
    - any other content type -> no BodyParams (the body is still uploaded).

    Alongside each `BodyParam`, an `input`-role `CandidateOccurrence` is emitted
    over the *raw* leaf value (ADR-0023, #16) — hashed via the same `hash_for` as
    response outputs so a leaked-then-resent value collapses to one `value_hash`
    (the leak-to-input pivot). Secret-shaped leaf values are suppressed on the
    `BodyParam` (`value=None`; ADR-0015) but still produce a *secret* input
    candidate carrying hash + length + preview only — never the raw token.
    """

    body_params: list[BodyParam] = []
    inputs: list[CandidateOccurrence] = []
    if base_mime == _FORM_CONTENT_TYPE:
        _parse_form_body(raw, content_type, body_params, inputs)
    elif base_mime == "application/json" or base_mime.endswith("+json"):
        _parse_json_body(raw, content_type, body_params, inputs)
    elif base_mime == "multipart/form-data":
        _parse_multipart_body(raw, content_type, body_params, inputs)
    return tuple(body_params), tuple(inputs)


_BODY_INPUT_EXTRACTOR = "request-param:body_v1"


def _body_param(
    name: str,
    value: str,
    json_pointer: str | None,
    content_type: str,
    inputs: list[CandidateOccurrence],
) -> BodyParam:
    """Build a `BodyParam` + its `input` candidate, suppressing secret raw values.

    The raw `value` always feeds the input `CandidateOccurrence` (secret discipline
    is applied inside `extract_input_candidate`); only the `BodyParam.value` is
    blanked for secret-shaped leaves.
    """

    inputs.append(
        extract_input_candidate(name, value, extractor=_BODY_INPUT_EXTRACTOR)
    )
    safe_value: str | None = None if _is_secret_shaped(name, value) else value
    return BodyParam(
        name=name,
        content_type=content_type,
        json_pointer=json_pointer,
        value=safe_value,
    )


def _parse_form_body(
    raw: bytes,
    content_type: str,
    out: list[BodyParam],
    inputs: list[CandidateOccurrence],
) -> None:
    """One `BodyParam` (+ input candidate) per `name=value` pair, form-urlencoded."""

    text = raw.decode("utf-8", errors="replace")
    for name, value in parse_qsl(text, keep_blank_values=True):
        if name:
            out.append(_body_param(name, value, None, _FORM_CONTENT_TYPE, inputs))


def _parse_json_body(
    raw: bytes,
    content_type: str,
    out: list[BodyParam],
    inputs: list[CandidateOccurrence],
) -> None:
    """One `BodyParam` (+ input candidate) per JSON leaf, addressed by RFC 6901."""

    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    _walk_json("", doc, content_type, out, inputs)


def _rfc6901_escape(token: str) -> str:
    """Escape a single RFC 6901 reference token (`~` -> `~0`, `/` -> `~1`)."""

    return token.replace("~", "~0").replace("/", "~1")


def _walk_json(
    pointer: str,
    node: object,
    content_type: str,
    out: list[BodyParam],
    inputs: list[CandidateOccurrence],
) -> None:
    """Recurse a JSON value, emitting a `BodyParam` (+ input candidate) per leaf.

    `pointer` is the RFC 6901 JSON Pointer to `node`. Object keys and array indices
    extend the pointer; scalars (and empty containers) are leaves. The leaf's
    `name` is its final reference token (the JSON key, or the array index for
    array elements); the full pointer is carried on `json_pointer`.
    """

    if isinstance(node, dict):
        if not node:
            return
        for key, value in node.items():
            child = f"{pointer}/{_rfc6901_escape(str(key))}"
            _walk_json(child, value, content_type, out, inputs)
        return
    if isinstance(node, list):
        for index, value in enumerate(node):
            child = f"{pointer}/{index}"
            _walk_json(child, value, content_type, out, inputs)
        return

    # Leaf. Derive the parameter name from the final pointer token.
    name = pointer.rsplit("/", 1)[-1] if pointer else ""
    if not name:
        # A bare scalar top-level JSON body has no key to name; skip it.
        return
    name = name.replace("~1", "/").replace("~0", "~")
    value_str = _scalar_to_str(node)
    out.append(_body_param(name, value_str, pointer, content_type, inputs))


def _scalar_to_str(value: object) -> str:
    """Render a JSON scalar as the string a `BodyParam.value` carries."""

    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value)


def _parse_multipart_body(
    raw: bytes,
    content_type: str,
    out: list[BodyParam],
    inputs: list[CandidateOccurrence],
) -> None:
    """Best-effort RFC 7578 multipart parse: text fields only, binary parts skipped.

    Uses the stdlib email parser to split parts (multipart/form-data is MIME).
    A part is treated as a text field when it has a `name` in its
    Content-Disposition, no `filename`, and a text-ish (or absent) content type.
    Binary parts (those with a `filename`, or a non-text content type) are skipped
    — the whole body is still uploaded to object storage by the caller.
    """

    message_bytes = b"Content-Type: " + content_type.encode("utf-8") + b"\r\n\r\n" + raw
    try:
        msg = BytesParser(policy=default_email_policy).parsebytes(message_bytes)
    except Exception:  # noqa: BLE001 - never crash the parser on odd multipart
        return
    if not msg.is_multipart():
        return

    for part in msg.iter_parts():
        disposition = part.get_content_disposition()
        if disposition != "form-data":
            continue
        filename = part.get_filename()
        if filename is not None:
            continue  # file upload part: binary, skip.
        name = part.get_param("name", header="content-disposition")
        if not isinstance(name, str) or not name:
            continue
        part_ctype = (part.get_content_type() or "").lower()
        if part_ctype and not (
            part_ctype.startswith("text/")
            or part_ctype == "application/json"
            or part_ctype.endswith("+json")
        ):
            continue  # non-text part: skip its (possibly binary) payload.
        try:
            value = part.get_content()
        except Exception:  # noqa: BLE001 - undecodable part -> skip, don't crash
            continue
        if not isinstance(value, str):
            continue
        out.append(
            _body_param(name, value.rstrip("\r\n"), None, "multipart/form-data", inputs)
        )


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
