"""Unit tests for T6 response-artifact extraction (parser + extractors).

These exercise the deterministic extractors and the HAR parser's response pass in
isolation (no docker): which `ResponseArtifact` events a HAR produces, their kind
/ location / extractor / value, the secret-shape discipline (hash + 8-char
preview, never a raw value), and the deterministic `source_id` that backs
re-ingestion idempotency. The live Neo4j commit + YIELDED edge live in the
pipeline integration test.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from uuid import uuid4

from doo.canonical.value_objects import BlobRef
from doo.events.envelope import IngestionEnvelope
from doo.events.l2 import RequestObservation, ResponseArtifact
from doo.extraction.artifacts import extract_from_body, extract_from_headers
from doo.extraction.har import parse_har
from doo.ids import BlobKey, EngagementId, IdempotencyKey, Sha256Hex
from tests.fixtures import RESPONSE_ARTIFACTS_HAR

ENG = EngagementId("eng-ra-test")
TRACE = "a" * 32
SPAN = "b" * 16
SHA = "c" * 64

# The JWT embedded in the /session response; must never surface as a raw value.
SESSION_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVC19."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5Nabc123"
)
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def _envelope() -> IngestionEnvelope:
    return IngestionEnvelope(
        event_id=uuid4(),
        trace_id=TRACE,  # type: ignore[arg-type]
        span_id=SPAN,  # type: ignore[arg-type]
        engagement_id=ENG,
        source="har",
        source_version=None,
        blob_ref=BlobKey("engagement/eng-ra-test/source/har/x.har"),
        blob_format="har-1.2",
        blob_sha256=Sha256Hex(SHA),
        idempotency_key=IdempotencyKey("d" * 64),
        received_at=datetime.now(UTC),
        producer_id="test",
        bytes_size=10,
    )


def _parse() -> tuple[list[RequestObservation], list[ResponseArtifact]]:
    events = list(parse_har(RESPONSE_ARTIFACTS_HAR.read_bytes(), _envelope(), None))
    obs = [e for e in events if isinstance(e, RequestObservation)]
    arts = [e for e in events if isinstance(e, ResponseArtifact)]
    return obs, arts


def _ro_for(obs: list[RequestObservation], path: str) -> RequestObservation:
    return next(o for o in obs if o.concrete_path == path)


def _arts_for(
    obs: list[RequestObservation], arts: list[ResponseArtifact], path: str
) -> list[ResponseArtifact]:
    ro = _ro_for(obs, path)
    return [a for a in arts if a.request_observation_id == ro.observation_id]


# --------------------------------------------------------------------------- #
# Extractor-unit coverage.
# --------------------------------------------------------------------------- #


def test_internal_hostname_extracted_from_500_body() -> None:
    body = b"Internal Server Error: upstream internal-billing.corp.example timed out"
    ex = extract_from_body(body, content_type="text/plain", status=500)
    hosts = [e for e in ex if e.artifact_kind == "hostname"]
    assert len(hosts) == 1
    assert hosts[0].value == "internal-billing.corp.example"
    assert hosts[0].extractor == "regex:internal_hostname_v1"
    assert hosts[0].section == "body"
    # Byte offsets index into the body.
    assert body[hosts[0].byte_start : hosts[0].byte_end] == b"internal-billing.corp.example"


def test_error_message_only_on_5xx() -> None:
    body = b"<html><body>boom internal-x.corp.example</body></html>"
    err5 = [e for e in extract_from_body(body, content_type="text/html", status=500)
            if e.artifact_kind == "error_message"]
    err2 = [e for e in extract_from_body(body, content_type="text/html", status=200)
            if e.artifact_kind == "error_message"]
    assert len(err5) == 1
    assert "<" not in err5[0].value  # HTML stripped
    assert err5[0].value.startswith("boom")
    assert err2 == []


def test_private_ip_is_ip_address_kind() -> None:
    ex = extract_from_body(b"host 10.0.0.5 and 8.8.8.8", content_type="text/plain", status=200)
    ips = [e for e in ex if e.artifact_kind == "ip_address"]
    assert [e.value for e in ips] == ["10.0.0.5"]  # public IP not captured


def test_jwt_is_secret_shaped_and_carries_no_raw_value_through_caller() -> None:
    ex = extract_from_body(
        f'{{"access_token": "{SESSION_JWT}"}}'.encode(),
        content_type="application/json",
        status=200,
    )
    secrets = [e for e in ex if e.is_secret]
    assert any(e.extractor == "regex:jwt_v1" for e in secrets)
    assert any(e.value == SESSION_JWT for e in secrets)  # raw only at the extractor edge


def test_aws_key_is_secret_shaped() -> None:
    ex = extract_from_body(b"aws_key=AKIAIOSFODNN7EXAMPLE", content_type="text/plain", status=200)
    secrets = [e for e in ex if e.is_secret]
    assert any(e.value == AWS_KEY and e.extractor == "regex:aws_access_key_v1" for e in secrets)


def test_json_walk_id_fields() -> None:
    ex = extract_from_body(
        b'{"id": 42, "user_id": 7, "name": "bob"}',
        content_type="application/json",
        status=200,
    )
    ids = {e.json_pointer: e.value for e in ex if e.extractor == "json-walk:id-fields_v1"}
    assert ids == {"/id": "42", "/user_id": "7"}


def test_fingerprint_from_server_header() -> None:
    ex = extract_from_headers({"server": "nginx/1.21.6"})
    assert len(ex) == 1
    assert ex[0].artifact_kind == "fingerprint"
    assert ex[0].section == "header"
    assert ex[0].header_name == "Server"
    assert ex[0].value == "nginx/1.21.6"


# --------------------------------------------------------------------------- #
# Parser-level acceptance criteria.
# --------------------------------------------------------------------------- #


def test_five_observations_parsed() -> None:
    obs, _ = _parse()
    assert len(obs) == 5


def test_acceptance_internal_hostname_artifact() -> None:
    obs, arts = _parse()
    ra = _arts_for(obs, arts, "/billing/report")
    host = next(a for a in ra if a.artifact_kind == "hostname")
    assert host.value == "internal-billing.corp.example"
    assert host.extractor == "regex:internal_hostname_v1"
    assert host.location.section == "body"
    assert host.location.byte_offset_start is not None
    # The 500 also yields an error_message excerpt.
    assert any(a.artifact_kind == "error_message" for a in ra)


def test_acceptance_jwt_secret_shape_hash_preview_no_raw() -> None:
    obs, arts = _parse()
    ra = _arts_for(obs, arts, "/session")
    jwt_art = next(a for a in ra if a.artifact_kind == "secret_shaped")
    assert jwt_art.value is None
    assert jwt_art.value_hash == hashlib.sha256(SESSION_JWT.encode()).hexdigest()
    assert jwt_art.value_length == len(SESSION_JWT.encode())
    assert jwt_art.value_preview == SESSION_JWT[:8]
    # The raw JWT appears nowhere in the serialised event (ADR-0015).
    assert SESSION_JWT not in jwt_art.model_dump_json()


def test_acceptance_server_fingerprint_header() -> None:
    obs, arts = _parse()
    ra = _arts_for(obs, arts, "/health")
    fp = next(a for a in ra if a.artifact_kind == "fingerprint")
    assert fp.location.section == "header"
    assert fp.location.header_name == "Server"
    assert fp.value == "nginx/1.21.6"


def test_url_and_aws_key_extracted() -> None:
    obs, arts = _parse()
    links = _arts_for(obs, arts, "/links")
    assert any(a.artifact_kind == "url" and "admin.internal.example" in (a.value or "")
               for a in links)
    config = _arts_for(obs, arts, "/config")
    aws = next(a for a in config if a.artifact_kind == "secret_shaped")
    assert aws.value is None
    assert aws.value_hash == hashlib.sha256(AWS_KEY.encode()).hexdigest()


def test_source_id_is_deterministic_across_reparse() -> None:
    """The deterministic source_id is what backs ADR-0016 idempotency despite the
    random UUID7 artifact_id. Re-parsing the same HAR yields the same per-artifact
    source_ids (but fresh artifact_ids)."""

    _, arts1 = _parse()
    _, arts2 = _parse()
    sids1 = sorted(a.source_id for a in arts1)
    sids2 = sorted(a.source_id for a in arts2)
    assert sids1 == sids2
    # The artifact_ids, by contrast, are fresh UUID7s each parse.
    assert {a.artifact_id for a in arts1} != {a.artifact_id for a in arts2}
    # source_id is secret-free: no raw JWT / AWS key in any key.
    joined = "|".join(sids1)
    assert SESSION_JWT not in joined
    assert AWS_KEY not in joined


def test_source_id_secret_free_uses_hash_not_value() -> None:
    _, arts = _parse()
    secret = next(a for a in arts if a.artifact_kind == "secret_shaped")
    # The value_hash is part of the source_id; the raw value is not.
    assert secret.value_hash is not None
    assert secret.value_hash in secret.source_id


class _FakeUploader:
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


def test_secret_raw_bytes_live_only_in_uploaded_blob() -> None:
    """With an uploader, the raw JWT bytes are present in the uploaded response
    body blob but in no emitted ResponseArtifact (ADR-0015)."""

    up = _FakeUploader()
    events = list(parse_har(RESPONSE_ARTIFACTS_HAR.read_bytes(), _envelope(), up))
    arts = [e for e in events if isinstance(e, ResponseArtifact)]

    # Raw JWT not in any emitted artifact.
    for a in arts:
        assert SESSION_JWT not in a.model_dump_json()

    # Raw JWT *is* in an uploaded blob.
    assert any(SESSION_JWT.encode() in body for body in up.objects.values())
