"""Unit tests for T5 HAR body extraction + body-parameter parsing.

These exercise the parser in isolation with a fake `BodyUploader` (no MinIO): we
assert which bodies are uploaded, the raw bytes / sha256 stored, the BlobRefs on
the observation, and the BodyParams (form pairs, JSON RFC 6901 pointers, multipart
text fields, secret suppression). The real MinIO round-trip lives in the pipeline
integration test.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from uuid import uuid4

from doo.canonical.value_objects import BlobRef
from doo.events.envelope import IngestionEnvelope
from doo.events.l2 import RequestObservation
from doo.extraction.har import parse_har
from doo.ids import BlobKey, EngagementId, IdempotencyKey, Sha256Hex
from tests.fixtures import BODIES_HAR

ENG = EngagementId("eng-bodies-test")
TRACE = "a" * 32
SPAN = "b" * 16
SHA = "c" * 64

# The refresh token embedded in the JSON fixture; must never surface as a raw value.
SECRET_TOKEN = "eyJhbGciOiJIUzI1Ni1.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"


def _envelope() -> IngestionEnvelope:
    return IngestionEnvelope(
        event_id=uuid4(),
        trace_id=TRACE,  # type: ignore[arg-type]
        span_id=SPAN,  # type: ignore[arg-type]
        engagement_id=ENG,
        source="har",
        source_version=None,
        blob_ref=BlobKey("engagement/eng-bodies-test/source/har/x.har"),
        blob_format="har-1.2",
        blob_sha256=Sha256Hex(SHA),
        idempotency_key=IdempotencyKey("d" * 64),
        received_at=datetime.now(UTC),
        producer_id="test",
        bytes_size=10,
    )


class _FakeUploader:
    """Records every uploaded body keyed by storage key; returns real BlobRefs."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put_body(
        self,
        engagement_id: EngagementId,
        *,
        raw: bytes,
        content_type: str,
        encoding: str | None = None,
    ) -> BlobRef:
        sha = hashlib.sha256(raw).hexdigest()
        key = f"engagement/{engagement_id}/source/har/bodies/{sha}.bin"
        self.objects[key] = raw
        return BlobRef(
            key=key,
            sha256=Sha256Hex(sha),
            content_type=content_type,
            size_bytes=len(raw),
            encoding=encoding,
        )


def _parse() -> tuple[list[RequestObservation], _FakeUploader]:
    up = _FakeUploader()
    events = list(parse_har(BODIES_HAR.read_bytes(), _envelope(), up))
    obs = [e for e in events if isinstance(e, RequestObservation)]
    return obs, up


def _by_path(obs: list[RequestObservation], path: str) -> RequestObservation:
    return next(o for o in obs if o.concrete_path == path)


def test_six_observations_parsed() -> None:
    obs, _ = _parse()
    assert len(obs) == 6


def test_json_body_uploaded_and_pointers_extracted() -> None:
    obs, up = _parse()
    users = _by_path(obs, "/api/users")

    # Body uploaded; ref points at it; key follows the prescribed layout.
    assert users.request_body_ref is not None
    ref = users.request_body_ref
    assert ref.key == f"engagement/{ENG}/source/har/bodies/{ref.sha256}.bin"
    assert ref.content_type == "application/json"
    assert up.objects[ref.key]  # stored
    # sha256 is over the stored raw bytes.
    assert hashlib.sha256(up.objects[ref.key]).hexdigest() == ref.sha256

    # JSON leaves -> BodyParams with RFC 6901 pointers.
    pointers = {bp.json_pointer: bp for bp in users.request_body_params}
    assert "/user/email" in pointers
    assert "/user/profile/email" in pointers
    assert pointers["/user/profile/email"].value == "alice.profile@example.com"
    assert pointers["/user/email"].name == "email"
    # Array leaves are addressed by index.
    assert "/roles/0" in pointers
    assert pointers["/roles/0"].value == "admin"
    # Boolean leaf rendered.
    assert pointers["/active"].value == "true"


def test_json_secret_token_not_surfaced_but_body_uploaded() -> None:
    obs, up = _parse()
    users = _by_path(obs, "/api/users")

    refresh = next(bp for bp in users.request_body_params if bp.name == "refresh_token")
    # Secret-shape value suppressed (ADR-0015): the param exists, value is None.
    assert refresh.json_pointer == "/refresh_token"
    assert refresh.value is None

    # The raw token must not appear anywhere in the emitted L2 event...
    dumped = users.model_dump_json()
    assert SECRET_TOKEN not in dumped
    # ...but it does live, intact, in the uploaded body in object storage.
    body = up.objects[users.request_body_ref.key]  # type: ignore[union-attr]
    assert SECRET_TOKEN.encode() in body


def test_form_body_via_text() -> None:
    obs, _ = _parse()
    login = _by_path(obs, "/api/login")
    assert login.request_body_ref is not None
    assert login.request_body_ref.content_type == "application/x-www-form-urlencoded"
    params = {bp.name: bp for bp in login.request_body_params}
    assert set(params) == {"username", "password", "remember"}
    for bp in login.request_body_params:
        assert bp.content_type == "application/x-www-form-urlencoded"
        assert bp.json_pointer is None
    assert params["username"].value == "bob"
    # "password" is a secret-conventional name -> value suppressed.
    assert params["password"].value is None
    assert params["remember"].value == "1"


def test_form_body_assembled_from_params() -> None:
    obs, up = _parse()
    search = _by_path(obs, "/api/search")
    # No postData.text: body reconstructed from postData.params and uploaded.
    assert search.request_body_ref is not None
    body = up.objects[search.request_body_ref.key]
    assert body == b"q=widgets&page=2"
    params = {bp.name: bp.value for bp in search.request_body_params}
    assert params == {"q": "widgets", "page": "2"}


def test_multipart_text_field_extracted_binary_skipped() -> None:
    obs, up = _parse()
    upload = _by_path(obs, "/api/upload")
    # Whole multipart body still uploaded.
    assert upload.request_body_ref is not None
    assert upload.request_body_ref.content_type.startswith("multipart/form-data")
    assert up.objects[upload.request_body_ref.key]
    # Only the text field is surfaced; the file (binary) part is skipped.
    names = {bp.name for bp in upload.request_body_params}
    assert names == {"caption"}
    caption = next(bp for bp in upload.request_body_params if bp.name == "caption")
    assert caption.value == "hello world"
    assert caption.content_type == "multipart/form-data"


def test_base64_response_body_decoded_before_upload() -> None:
    obs, up = _parse()
    avatar = _by_path(obs, "/api/avatar")
    assert avatar.response_body_ref is not None
    ref = avatar.response_body_ref
    expected_raw = base64.b64decode("iVBORw0KGgoAAAByYXdiaW5hcnktYnl0ZXM=")
    stored = up.objects[ref.key]
    # Stored bytes are the decoded raw bytes, not the base64 text.
    assert stored == expected_raw
    assert ref.sha256 == hashlib.sha256(expected_raw).hexdigest()
    assert ref.content_type == "image/png"
    # The request side of this GET has no body.
    assert avatar.request_body_ref is None


def test_no_body_entry_has_no_refs_and_no_object() -> None:
    obs, up = _parse()
    health = _by_path(obs, "/api/health")
    assert health.request_body_ref is None
    assert health.response_body_ref is None
    assert health.request_body_params == ()
    # No placeholder objects: only the 5 bodies with content were uploaded
    # (4 request bodies + 1 response body).
    assert len(up.objects) == 5


def test_parser_without_uploader_skips_bodies_but_still_parses_params() -> None:
    # When no uploader is supplied (pure parse), refs are None but body params
    # are still extracted (parsing is independent of upload).
    events = list(parse_har(BODIES_HAR.read_bytes(), _envelope(), None))
    obs = [e for e in events if isinstance(e, RequestObservation)]
    users = next(o for o in obs if o.concrete_path == "/api/users")
    assert users.request_body_ref is None
    assert any(bp.json_pointer == "/user/email" for bp in users.request_body_params)
