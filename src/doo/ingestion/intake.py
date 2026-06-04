"""L1 intake: HAR upload -> blob storage + `IngestionEnvelope` on `ingest`.

`build_app(deps)` returns a FastAPI app exposing `POST /ingest/har` (multipart).
The handler:

1. reads the uploaded bytes and computes `blob_sha256`,
2. rejects an unknown `engagement_id` with a 4xx **before** touching storage or
   the stream (nothing lands for a bad engagement),
3. streams the blob to object storage under
   `engagement/{engagement_id}/source/har/{blob_sha256}.har`,
4. builds the canonical `IngestionEnvelope` (trace_id generated at intake,
   ADR-0018) with the ADR-0016 blob-level idempotency key
   `sha256(f"{source}|{blob_sha256}|{engagement_id}")`,
5. `XADD`s the envelope onto the `ingest` Redis Stream.

L1 validates the envelope only; the blob is opaque here (ARCHITECTURE.md L1->L2
contract). Malformed HAR surfaces later as a `ParseFailure` from L2.

The wire-format handling lives only here (per-source intake). Dependencies are
injected via `IntakeDeps` so the app is testable with fakes and so the same app
serves MinIO/Neo4j in deployment.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated as _Annotated
from typing import Protocol
from uuid import uuid4

from fastapi import FastAPI, File, Form, HTTPException, UploadFile

from doo.events.envelope import IngestionEnvelope, SourceKind
from doo.ids import BlobKey, EngagementId, IdempotencyKey, Sha256Hex
from doo.infra.blobs import sha256_hex
from doo.infra.streams import INGEST_STREAM
from doo.observability.ids import new_span_id, new_trace_id
from doo.observability.logging import bind_correlation, clear_correlation, get_logger

log = get_logger(__name__)

HAR_SOURCE: SourceKind = "har"
HAR_BLOB_FORMAT = "har-1.2"
PRODUCER_ID = "har-upload-cli"


def compute_idempotency_key(
    source: str, blob_sha256: Sha256Hex, engagement_id: EngagementId
) -> IdempotencyKey:
    """ADR-0016 blob-level idempotency key: `sha256(source|blob_sha256|engagement_id)`."""

    digest = hashlib.sha256(
        f"{source}|{blob_sha256}|{engagement_id}".encode()
    ).hexdigest()
    return IdempotencyKey(digest)


class EngagementChecker(Protocol):
    """Duck-type: does this engagement exist? (Read-only graph check.)"""

    def engagement_exists(self, engagement_id: EngagementId) -> bool: ...

    def get_session_cookie_names(self, engagement_id: EngagementId) -> tuple[str, ...]:
        """The engagement's configured session-cookie allowlist (ADR-0026 #28).

        Empty tuple when none configured (the parser then uses the shape
        heuristic). Read at L1 so it travels on the envelope to L2.
        """
        ...


class BlobStore(Protocol):
    """Duck-type for the blob client surface intake needs."""

    def put_har(
        self, engagement_id: EngagementId, blob_sha256: Sha256Hex, data: bytes
    ) -> BlobKey: ...


class StreamPublisher(Protocol):
    """Duck-type for the stream client surface intake needs."""

    def publish(self, stream: str, payload: dict[str, object]) -> str: ...


@dataclass(frozen=True, slots=True)
class IntakeDeps:
    """Injected collaborators for the intake app."""

    engagements: EngagementChecker
    blobs: BlobStore
    streams: StreamPublisher


@dataclass(frozen=True, slots=True)
class IntakeResult:
    """What `ingest_har` produced — returned in the HTTP response body."""

    engagement_id: EngagementId
    blob_sha256: Sha256Hex
    blob_ref: BlobKey
    idempotency_key: IdempotencyKey
    trace_id: str
    event_id: str
    stream_message_id: str


def ingest_har(
    deps: IntakeDeps,
    *,
    engagement_id: EngagementId,
    filename: str | None,
    data: bytes,
) -> IntakeResult:
    """Core intake logic (no HTTP) — testable directly and called by the route.

    Order matters: the engagement existence check happens before any write, so a
    bad engagement leaves nothing in storage or on the stream.
    """

    trace_id = new_trace_id()
    span_id = new_span_id()
    bind_correlation(trace_id=trace_id, span_id=span_id, engagement_id=engagement_id)
    try:
        if not deps.engagements.engagement_exists(engagement_id):
            log.warning("intake.unknown_engagement", filename=filename)
            raise UnknownEngagementError(engagement_id)

        blob_sha256 = sha256_hex(data)
        blob_ref = deps.blobs.put_har(engagement_id, blob_sha256, data)
        idempotency_key = compute_idempotency_key(HAR_SOURCE, blob_sha256, engagement_id)
        session_cookie_names = deps.engagements.get_session_cookie_names(engagement_id)

        envelope = IngestionEnvelope(
            event_id=uuid4(),
            trace_id=trace_id,
            span_id=span_id,
            engagement_id=engagement_id,
            source=HAR_SOURCE,
            source_version=None,
            blob_ref=blob_ref,
            blob_format=HAR_BLOB_FORMAT,
            blob_sha256=blob_sha256,
            idempotency_key=idempotency_key,
            received_at=datetime.now(UTC),
            producer_id=PRODUCER_ID,
            bytes_size=len(data),
            session_cookie_names=session_cookie_names,
        )
        message_id = deps.streams.publish(
            INGEST_STREAM, envelope.model_dump(mode="json")
        )
        log.info(
            "intake.har.accepted",
            filename=filename,
            blob_ref=str(blob_ref),
            blob_sha256=blob_sha256,
            bytes_size=len(data),
            stream_message_id=message_id,
        )
        return IntakeResult(
            engagement_id=engagement_id,
            blob_sha256=blob_sha256,
            blob_ref=blob_ref,
            idempotency_key=idempotency_key,
            trace_id=trace_id,
            event_id=str(envelope.event_id),
            stream_message_id=message_id,
        )
    finally:
        clear_correlation()


class UnknownEngagementError(Exception):
    """Raised when intake is handed an engagement_id that doesn't exist."""

    def __init__(self, engagement_id: EngagementId) -> None:
        super().__init__(f"unknown engagement_id {engagement_id!r}")
        self.engagement_id = engagement_id


def build_app(deps: IntakeDeps) -> FastAPI:
    """Construct the FastAPI app wired to `deps`."""

    app = FastAPI(title="doo L1 intake", version="0.1.0")

    @app.post("/ingest/har")
    async def post_ingest_har(  # type: ignore[no-untyped-def]
        engagement_id: _Annotated[str, Form()],
        file: _Annotated[UploadFile, File()],
    ):
        data = await file.read()
        try:
            result = ingest_har(
                deps,
                engagement_id=EngagementId(engagement_id),
                filename=file.filename,
                data=data,
            )
        except UnknownEngagementError as exc:
            raise HTTPException(
                status_code=404,
                detail=f"unknown engagement_id {exc.engagement_id!r}; "
                "start it first (`doo engagement start`)",
            ) from exc
        return {
            "engagement_id": result.engagement_id,
            "blob_sha256": result.blob_sha256,
            "blob_ref": result.blob_ref,
            "idempotency_key": result.idempotency_key,
            "trace_id": result.trace_id,
            "event_id": result.event_id,
            "stream_message_id": result.stream_message_id,
        }

    return app
