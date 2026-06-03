"""Unit tests for response value-candidate extraction (ADR-0023, was T6).

Pure (no docker): which `CandidateOccurrence`s a response body/headers produce —
their kind / location / role; the secret discipline (hash + 8-char preview, never
a raw value); and diagnostics (`server_fingerprint`, `error_excerpt`) returned
*separately* as inline observation properties, not values. Plus the HAR parser's
inline recording of candidates + diagnostics on the emitted `RequestObservation`.

Replaces the retired `tests/test_response_artifacts.py`: the secret-discipline
assertions carry over to the inline candidate (and, end-to-end, to `ObservedValue`).
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from uuid import uuid4

from doo.canonical.value_objects import BlobRef
from doo.canonical.values import hash_for
from doo.events.envelope import IngestionEnvelope
from doo.events.l2 import RequestObservation
from doo.extraction.artifacts import (
    extract_candidates,
    extract_diagnostics,
    extract_input_candidate,
)
from doo.extraction.har import parse_har
from doo.ids import BlobKey, EngagementId, IdempotencyKey, Sha256Hex
from tests.fixtures import RESPONSE_ARTIFACTS_HAR

ENG = EngagementId("eng-ra-test")
TRACE = "a" * 32
SPAN = "b" * 16
SHA = "c" * 64

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


# --------------------------------------------------------------------------- #
# Candidate-extraction units.
# --------------------------------------------------------------------------- #


def test_internal_hostname_candidate_kind_location_role() -> None:
    body = b"Internal Server Error: upstream internal-billing.corp.example timed out"
    cands = extract_candidates(body, content_type="text/plain")
    hosts = [c for c in cands if c.kind == "internal_hostname"]
    assert len(hosts) == 1
    h = hosts[0]
    assert h.value == "internal-billing.corp.example"
    assert h.extractor == "regex:internal_hostname_v1"
    assert h.section == "body"
    assert h.role == "output"
    assert body[h.byte_start : h.byte_end] == b"internal-billing.corp.example"
    # value_hash is over the normalised form (ADR-0009).
    assert h.value_hash == hash_for("internal_hostname", "internal-billing.corp.example")


def test_email_candidate_promotable_kind() -> None:
    cands = extract_candidates(
        b'{"contact": "ops@internal.example"}', content_type="application/json"
    )
    emails = [c for c in cands if c.kind == "email"]
    assert [c.value for c in emails] == ["ops@internal.example"]


def test_private_ip_is_ip_address_kind_not_promotable() -> None:
    cands = extract_candidates(b"host 10.0.0.5 and 8.8.8.8", content_type="text/plain")
    ips = [c for c in cands if c.kind == "ip_address"]
    assert [c.value for c in ips] == ["10.0.0.5"]  # public IP not captured


def test_uuid_is_identifier_kind_with_value() -> None:
    cands = extract_candidates(
        b'{"x": "550e8400-e29b-41d4-a716-446655440000"}',
        content_type="application/json",
    )
    uuids = [c for c in cands if c.extractor == "regex:uuid_v1"]
    assert len(uuids) == 1
    assert uuids[0].kind == "identifier"
    assert uuids[0].value == "550e8400-e29b-41d4-a716-446655440000"


def test_json_walk_id_fields_carry_pointer() -> None:
    cands = extract_candidates(
        b'{"id": 42, "user_id": 7, "name": "bob"}', content_type="application/json"
    )
    ids = {
        c.json_pointer: c.value for c in cands if c.extractor == "json-walk:id-fields_v1"
    }
    assert ids == {"/id": "42", "/user_id": "7"}


def test_jwt_is_secret_kind_hash_preview_no_raw_value() -> None:
    cands = extract_candidates(
        f'{{"access_token": "{SESSION_JWT}"}}'.encode(),
        content_type="application/json",
    )
    secrets = [c for c in cands if c.is_secret]
    jwt = next(c for c in secrets if c.extractor == "regex:jwt_v1")
    assert jwt.kind == "secret"
    assert jwt.value is None  # no raw value (ADR-0015)
    assert jwt.value_hash == hashlib.sha256(SESSION_JWT.encode()).hexdigest()
    assert jwt.value_length == len(SESSION_JWT.encode())
    assert jwt.value_preview == SESSION_JWT[:8]
    # The raw JWT appears nowhere in the candidate.
    assert SESSION_JWT not in repr(jwt)


def test_aws_key_is_secret_kind() -> None:
    cands = extract_candidates(b"aws_key=AKIAIOSFODNN7EXAMPLE", content_type="text/plain")
    secret = next(c for c in cands if c.extractor == "regex:aws_access_key_v1")
    assert secret.kind == "secret"
    assert secret.value is None
    assert secret.value_hash == hashlib.sha256(AWS_KEY.encode()).hexdigest()


def test_extract_candidates_does_not_return_diagnostics() -> None:
    # Fingerprint/error are NOT values; extract_candidates never emits them.
    cands = extract_candidates(
        b"<html><body>500 boom internal-x.corp.example</body></html>",
        content_type="text/html",
    )
    assert all(c.kind != "ip_address" or c.value for c in cands)
    assert not any(c.section == "header" for c in cands)
    assert not any("error" in c.extractor or "fingerprint" in c.extractor for c in cands)


# --------------------------------------------------------------------------- #
# Diagnostics units (returned separately).
# --------------------------------------------------------------------------- #


def test_diagnostics_server_fingerprint_from_header() -> None:
    diag = extract_diagnostics(b"{}", {"server": "nginx/1.21.6"}, status=200)
    assert diag.server_fingerprint == "nginx/1.21.6"
    assert diag.error_excerpt is None


def test_diagnostics_x_powered_by_fingerprint() -> None:
    diag = extract_diagnostics(b"{}", {"x-powered-by": "Express"}, status=200)
    assert diag.server_fingerprint == "Express"


def test_diagnostics_error_excerpt_only_on_5xx() -> None:
    body = b"<html><body>boom internal-x.corp.example</body></html>"
    err5 = extract_diagnostics(body, {}, status=500)
    err2 = extract_diagnostics(body, {}, status=200)
    assert err5.error_excerpt is not None
    assert "<" not in err5.error_excerpt  # HTML stripped
    assert err5.error_excerpt.startswith("boom")
    assert err2.error_excerpt is None


def test_diagnostics_no_body_no_error_excerpt() -> None:
    diag = extract_diagnostics(None, {"server": "nginx"}, status=500)
    assert diag.error_excerpt is None
    assert diag.server_fingerprint == "nginx"


# --------------------------------------------------------------------------- #
# Parser-level: candidates + diagnostics recorded inline on the observation.
# --------------------------------------------------------------------------- #


def _parse() -> list[RequestObservation]:
    events = list(parse_har(RESPONSE_ARTIFACTS_HAR.read_bytes(), _envelope(), None))
    return [e for e in events if isinstance(e, RequestObservation)]


def _ro_for(obs: list[RequestObservation], path: str) -> RequestObservation:
    return next(o for o in obs if o.concrete_path == path)


def test_parser_emits_only_observations_no_artifact_events() -> None:
    events = list(parse_har(RESPONSE_ARTIFACTS_HAR.read_bytes(), _envelope(), None))
    assert all(e.kind in ("request_observation", "parse_failure") for e in events)
    assert len([e for e in events if e.kind == "request_observation"]) == 5


def test_inline_internal_hostname_candidate_and_error_excerpt() -> None:
    obs = _parse()
    ro = _ro_for(obs, "/billing/report")  # 500 HTML body
    hosts = [c for c in ro.value_candidates if c.kind == "internal_hostname"]
    assert hosts and hosts[0].value == "internal-billing.corp.example"
    # The 5xx error excerpt is an inline property, not a candidate.
    assert ro.error_excerpt is not None
    assert not any(c.kind == "email" and "error" in str(c.value) for c in ro.value_candidates)


def test_inline_jwt_candidate_secret_only_hash_preview() -> None:
    obs = _parse()
    ro = _ro_for(obs, "/session")
    jwt = next(c for c in ro.value_candidates if c.kind == "secret")
    assert jwt.value is None
    assert jwt.value_hash == hashlib.sha256(SESSION_JWT.encode()).hexdigest()
    assert jwt.value_preview == SESSION_JWT[:8]
    assert SESSION_JWT not in ro.model_dump_json()


def test_inline_server_fingerprint_property() -> None:
    obs = _parse()
    ro = _ro_for(obs, "/health")
    assert ro.server_fingerprint == "nginx/1.21.6"
    # The fingerprint is NOT a value candidate.
    assert not any(c.section == "header" for c in ro.value_candidates)


def test_inline_aws_secret_candidate_no_raw_value() -> None:
    obs = _parse()
    ro = _ro_for(obs, "/config")
    aws = next(c for c in ro.value_candidates if c.kind == "secret")
    assert aws.value is None
    assert aws.value_hash == hashlib.sha256(AWS_KEY.encode()).hexdigest()
    assert AWS_KEY not in ro.model_dump_json()


def test_secret_raw_bytes_live_only_in_uploaded_blob() -> None:
    """With an uploader, the raw JWT bytes are in the uploaded response body blob
    but in no emitted observation property (ADR-0015)."""

    up = _FakeUploader()
    events = list(parse_har(RESPONSE_ARTIFACTS_HAR.read_bytes(), _envelope(), up))
    obs = [e for e in events if isinstance(e, RequestObservation)]
    for ro in obs:
        assert SESSION_JWT not in ro.model_dump_json()
        assert AWS_KEY not in ro.model_dump_json()
    assert any(SESSION_JWT.encode() in body for body in up.objects.values())


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


def test_short_secret_input_param_has_no_revealing_preview() -> None:
    """ADR-0015 regression (#16): a 7-char `password`'s first-8 preview would BE
    the whole secret, so a short secret input carries no preview at all."""
    c = extract_input_candidate("password", "hunter2", extractor="request-param:body_v1")
    assert c.is_secret
    assert c.value is None
    assert c.value_preview is None
    assert c.value_length == 7
    assert "hunter2" not in (c.value_preview or "")


def test_long_secret_input_param_keeps_partial_preview_never_full() -> None:
    long_secret = "supersecretlongtoken1234567890"
    c = extract_input_candidate("token", long_secret, extractor="request-param:body_v1")
    assert c.value is None
    assert c.value_preview == long_secret[:8]
    assert long_secret not in (c.value_preview or "")  # never the full value
