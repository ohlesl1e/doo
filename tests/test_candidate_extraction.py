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

import jwt as pyjwt

from doo.canonical.value_objects import BlobRef
from doo.canonical.values import hash_for
from doo.events.envelope import IngestionEnvelope
from doo.events.observation import RequestObservation
from doo.extraction.artifacts import (
    extract_candidates,
    extract_diagnostics,
    extract_input_candidate,
    is_opaque_token_shaped,
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


_CLAIM_SK = "claims-signing-key-at-least-32-bytes-long!!"


def test_jwt_claims_emit_sub_identifier_and_email_alongside_secret() -> None:
    """ADR-0025: a JWT yields the hash-only `secret` AND value candidates for its
    identity claims — `sub` -> identifier, `email` -> email — carrying raw values."""

    token = pyjwt.encode(
        {"sub": "user-42", "email": "alice@corp.example.com", "exp": 4102444800},
        _CLAIM_SK,
        algorithm="HS256",
    )
    cands = extract_candidates(
        f'{{"access_token": "{token}"}}'.encode(), content_type="application/json"
    )

    # The token is still a hash-only secret.
    secret = next(c for c in cands if c.extractor == "regex:jwt_v1")
    assert secret.kind == "secret"
    assert secret.value is None

    claims = [c for c in cands if c.extractor == "jwt-claims:identity_v1"]
    sub = next(c for c in claims if c.kind == "identifier")
    email = next(c for c in claims if c.kind == "email")
    # Claims are non-secret: raw value carried (the leak-to-input pivot needs it).
    assert sub.value == "user-42"
    assert sub.value_hash == hash_for("identifier", "user-42")
    assert email.value == "alice@corp.example.com"
    assert email.role == "output"
    # No raw token bytes ride along on a claim candidate.
    assert token not in repr(sub)
    assert token not in repr(email)


def test_jwt_without_sub_emits_no_sub_candidate() -> None:
    token = pyjwt.encode(
        {"email": "bob@corp.example.com", "exp": 4102444800}, _CLAIM_SK, algorithm="HS256"
    )
    cands = extract_candidates(
        f'{{"id_token": "{token}"}}'.encode(), content_type="application/json"
    )
    claims = [c for c in cands if c.extractor == "jwt-claims:identity_v1"]
    assert {c.kind for c in claims} == {"email"}
    assert all(c.kind != "identifier" for c in claims)


def test_jwt_broadened_identity_claims_emit_identifier_values() -> None:
    """ADR-0027: the broadened claim set (uid / _id / username / …) emits
    `identifier` candidates alongside the hash-only secret."""

    token = pyjwt.encode(
        {"uid": "u-7", "_id": "507f1f77bcf86cd799439011", "username": "carol", "exp": 4102444800},
        _CLAIM_SK,
        algorithm="HS256",
    )
    cands = extract_candidates(
        f'{{"access_token": "{token}"}}'.encode(), content_type="application/json"
    )
    claim_values = {c.value for c in cands if c.extractor == "jwt-claims:identity_v1"}
    assert {"u-7", "507f1f77bcf86cd799439011", "carol"} <= claim_values
    assert all(
        c.kind == "identifier"
        for c in cands
        if c.extractor == "jwt-claims:identity_v1"
    )


def test_malformed_jwt_does_not_crash_extraction() -> None:
    # Matches the JWT regex (eyJ + three base64url segments) but the header/payload
    # are not valid base64url JSON, so the decode must fail closed, not raise.
    malformed = "eyJBBBBBBBB.eyJCCCCCCCC.DDDDDDDDDD"
    cands = extract_candidates(
        f'{{"token": "{malformed}"}}'.encode(), content_type="application/json"
    )
    # The secret candidate is still produced; no claim candidates, no exception.
    assert any(c.extractor == "regex:jwt_v1" for c in cands)
    assert not [c for c in cands if c.extractor == "jwt-claims:identity_v1"]


def test_aws_key_is_secret_kind() -> None:
    cands = extract_candidates(b"aws_key=AKIAIOSFODNN7EXAMPLE", content_type="text/plain")
    secret = next(c for c in cands if c.extractor == "regex:aws_access_key_v1")
    assert secret.kind == "secret"
    assert secret.value is None
    assert secret.value_hash == hashlib.sha256(AWS_KEY.encode()).hexdigest()


def test_generic_high_entropy_blob_is_opaque_token_not_secret() -> None:
    # A long base64url/hex blob with no recognised structure (an ETag / signed-URL
    # token) is `opaque_token` (ADR-0024/ADR-0028): hash-only for storage but not
    # promoted on shape. It must NOT be classified `secret`.
    # ADR-0028: opaque_token now comes from whole JSON leaf values (json-walk),
    # not from the body-text substring sweep. The blob must be in [32, 512] and
    # mixed upper+lower+digit to qualify.
    blob = "Ab3Cd9Ef2Gh5Ij8Kl1Mn4Op7Qr0St6Uv"  # 33 chars, mixed classes
    assert is_opaque_token_shaped(blob)  # sanity-check the predicate
    cands = extract_candidates(
        f'{{"etag": "{blob}"}}'.encode(), content_type="application/json"
    )
    tok = next(c for c in cands if c.extractor == "json-walk:opaque_token_v1")
    assert tok.kind == "opaque_token"
    # Still hash-only for storage (ADR-0015): no raw value, hash + preview carried.
    assert tok.is_secret  # secret-for-storage predicate
    assert tok.value is None
    assert tok.value_hash == hashlib.sha256(blob.encode()).hexdigest()
    assert tok.value_preview == blob[:8]
    assert blob not in repr(tok)
    # No structured detector mislabels it as `secret`.
    assert not any(c.kind == "secret" for c in cands)
    # json_pointer is set (ADR-0028: whole-leaf, not byte-offset).
    assert tok.json_pointer == "/etag"


# --------------------------------------------------------------------------- #
# ADR-0028: is_opaque_token_shaped unit tests.
# --------------------------------------------------------------------------- #


def test_is_opaque_token_shaped_accepts_33_char_mixed_base64() -> None:
    # A 33-char mixed-class base64url string -> True.
    assert is_opaque_token_shaped("Ab3Cd9Ef2Gh5Ij8Kl1Mn4Op7Qr0St6Uv")


def test_is_opaque_token_shaped_rejects_length_31() -> None:
    # 31 chars — below the [32, 512] floor.
    assert not is_opaque_token_shaped("Ab3Cd9Ef2Gh5Ij8Kl1Mn4Op7Qr0St6U")


def test_is_opaque_token_shaped_rejects_length_600() -> None:
    # 600-char value — above the 512 ceiling.
    value = "Ab3C" * 150  # 600 chars, mixed classes
    assert len(value) == 600
    assert not is_opaque_token_shaped(value)


def test_is_opaque_token_shaped_rejects_data_uri() -> None:
    # data: URI leaves are never opaque tokens.
    data_uri = "data:image/png;base64," + "Ab3C" * 20  # starts with data:
    assert not is_opaque_token_shaped(data_uri)


def test_is_opaque_token_shaped_rejects_all_hex_md5() -> None:
    # A 32-hex all-lowercase MD5 hash: no uppercase → not mixed-class.
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    assert len(md5) == 32
    assert not is_opaque_token_shaped(md5)


def test_is_opaque_token_shaped_rejects_lowercase_slug() -> None:
    # A 32-char all-lowercase slug: no uppercase or digit mixing → rejected.
    slug = "a" * 32
    assert not is_opaque_token_shaped(slug)


# --------------------------------------------------------------------------- #
# ADR-0028: output-side whole-leaf extraction.
# --------------------------------------------------------------------------- #


def test_opaque_token_from_json_leaf_bounded_and_pointer_set() -> None:
    # A JSON body with a bounded mixed-class leaf emits ONE opaque_token from the
    # JSON walk (not the body sweep), with json_pointer set.
    blob = "Ab3Cd9Ef2Gh5Ij8Kl1Mn4Op7Qr0St6Uv"  # 33 chars
    cands = extract_candidates(
        f'{{"etag": "{blob}"}}'.encode(), content_type="application/json"
    )
    toks = [c for c in cands if c.kind == "opaque_token"]
    assert len(toks) == 1
    assert toks[0].extractor == "json-walk:opaque_token_v1"
    assert toks[0].json_pointer == "/etag"
    assert toks[0].value is None  # hash-only (ADR-0015)
    assert toks[0].value_hash == hashlib.sha256(blob.encode()).hexdigest()


def test_oversized_json_leaf_yields_no_opaque_token() -> None:
    # A 600-char base64 leaf (e.g. inline PNG data) exceeds the 512-char ceiling and
    # must NOT produce an opaque_token (the root cause of the 14k noise nodes).
    big_value = "Ab3C" * 150  # 600 chars, mixed classes
    assert len(big_value) == 600
    cands = extract_candidates(
        f'{{"img": "{big_value}"}}'.encode(), content_type="application/json"
    )
    assert not any(c.kind == "opaque_token" for c in cands)


def test_non_json_body_with_high_entropy_run_yields_no_opaque_token() -> None:
    # An HTML (non-JSON) body with a high-entropy run produces NO opaque_token.
    # opaque_token now comes only from JSON leaf values (ADR-0028).
    blob = "Ab3Cd9Ef2Gh5Ij8Kl1Mn4Op7Qr0St6Uv"  # 33 chars, would have been swept
    html_body = f"<html><body>token={blob}</body></html>".encode()
    cands = extract_candidates(html_body, content_type="text/html")
    assert not any(c.kind == "opaque_token" for c in cands)


def test_id_field_json_leaf_emits_identifier_not_opaque_token() -> None:
    # A leaf whose key matches *_id stays `identifier` (never double-emitted as
    # opaque_token, even if the value is opaque-token-shaped).
    blob = "Ab3Cd9Ef2Gh5Ij8Kl1Mn4Op7Qr0St6Uv"  # 33 chars, would pass is_opaque_token_shaped
    cands = extract_candidates(
        f'{{"session_id": "{blob}"}}'.encode(), content_type="application/json"
    )
    id_cands = [c for c in cands if c.extractor == "json-walk:id-fields_v1"]
    opaque_cands = [c for c in cands if c.kind == "opaque_token"]
    assert len(id_cands) == 1  # emitted as identifier
    assert len(opaque_cands) == 0  # NOT also emitted as opaque_token


def test_jwt_in_any_body_still_yields_secret() -> None:
    # Structured detectors run over the whole body regardless of content-type.
    cands = extract_candidates(
        f"token={SESSION_JWT}".encode(), content_type="text/plain"
    )
    assert any(c.extractor == "regex:jwt_v1" and c.kind == "secret" for c in cands)


def test_aws_key_in_json_body_still_yields_secret() -> None:
    cands = extract_candidates(
        f'{{"key": "{AWS_KEY}"}}'.encode(), content_type="application/json"
    )
    assert any(c.extractor == "regex:aws_access_key_v1" and c.kind == "secret" for c in cands)


def test_stripe_key_in_text_body_still_yields_secret() -> None:
    cands = extract_candidates(
        b"sk_live_abc123ABC456def789X", content_type="text/plain"
    )
    assert any(c.extractor == "regex:stripe_key_v1" and c.kind == "secret" for c in cands)


# --------------------------------------------------------------------------- #
# ADR-0028: input side uses is_opaque_token_shaped (length bound + data: guard).
# --------------------------------------------------------------------------- #


def test_classify_input_rejects_oversized_value_as_identifier_not_opaque() -> None:
    # A 600-char high-entropy value exceeds the 512-char ceiling; classify_input_kind
    # must fall through to `identifier`, not `opaque_token`.
    big = "Ab3C" * 150  # 600 chars
    c = extract_input_candidate("sig", big, extractor="request-param:query_v1")
    assert c.kind == "identifier"


def test_classify_input_rejects_data_uri_value_as_identifier_not_opaque() -> None:
    # A data: URI input parameter must not classify as opaque_token.
    data_uri = "data:image/png;base64," + "Ab3C" * 20
    c = extract_input_candidate("img", data_uri, extractor="request-param:query_v1")
    assert c.kind != "opaque_token"


def test_structured_secrets_stay_secret_not_opaque_token() -> None:
    # JWT, AWS, Stripe keep emitting `secret` (the always-promoted shape-allowlist).
    jwt = extract_candidates(
        f'{{"t": "{SESSION_JWT}"}}'.encode(), content_type="application/json"
    )
    assert next(c for c in jwt if c.extractor == "regex:jwt_v1").kind == "secret"
    aws = extract_candidates(b"AKIAIOSFODNN7EXAMPLE", content_type="text/plain")
    assert next(c for c in aws if c.extractor == "regex:aws_access_key_v1").kind == "secret"
    stripe = extract_candidates(
        b"sk_live_abc123ABC456def789X", content_type="text/plain"
    )
    s = next(c for c in stripe if c.extractor == "regex:stripe_key_v1")
    assert s.kind == "secret"


def test_high_entropy_request_param_input_is_opaque_token() -> None:
    # classify_input_kind maps a high-entropy request param to `opaque_token`
    # (ADR-0024): hash-only, gated for promotion (not on shape).
    blob = "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0Fe"
    c = extract_input_candidate("sig", blob, extractor="request-param:query_v1")
    assert c.kind == "opaque_token"
    assert c.role == "input"
    assert c.is_secret  # secret-for-storage
    assert c.value is None
    assert c.value_hash == hash_for("opaque_token", blob)
    assert c.value_preview == blob[:8]
    assert blob not in repr(c)


def test_plain_identifier_input_stays_identifier_not_opaque_token() -> None:
    # A non-high-entropy param value (a slug / plain id) is still `identifier`, not
    # opaque_token — the high-entropy gate requires mixed character classes.
    c = extract_input_candidate("page", "next-page", extractor="request-param:query_v1")
    assert c.kind == "identifier"


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
