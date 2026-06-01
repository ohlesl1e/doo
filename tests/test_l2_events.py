"""L2Event tagged-union tests.

Strict mode + extra=forbid on every variant. ADR-0015 secrets discipline
enforced on ResponseArtifact. HostRef canonicalisation enforced.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import TypeAdapter, ValidationError

from doo.canonical.value_objects import AuthContextCue, BlobRef, HostRef
from doo.events.l2 import (
    L2Event,
    ParseFailure,
    RequestObservation,
    ResponseArtifact,
)


def _envelope_id() -> uuid.UUID:
    return uuid.uuid4()


def _base_l2_kwargs() -> dict:
    return dict(
        event_id="l2-evt-1",
        trace_id="0" * 32,
        span_id="0" * 16,
        engagement_id="acme-2026",
        envelope_event_id=_envelope_id(),
        source="har",
        source_id="entry-0|2026-05-31T00:00:00Z",
        ingested_at=datetime.now(timezone.utc),
        observed_at=datetime.now(timezone.utc),
        confidence=1.0,
    )


def _ro_kwargs() -> dict:
    return {
        **_base_l2_kwargs(),
        "observation_id": "ro-1",
        "method": "GET",
        "host": HostRef(scheme="https", canonical_hostname="api.example.com", port=None),
        "concrete_path": "/orgs/42/projects",
        "auth_context_cue": AuthContextCue(is_anonymous=True),
        "response_status": 200,
        "response_size_bytes": 1024,
    }


def test_request_observation_constructs() -> None:
    ro = RequestObservation(**_ro_kwargs())
    assert ro.kind == "request_observation"
    assert ro.method == "GET"
    assert ro.host.canonical_hostname == "api.example.com"


def test_request_observation_strict_mode_rejects_unknown_fields() -> None:
    bad = _ro_kwargs()
    bad["bogus"] = 1
    with pytest.raises(ValidationError):
        RequestObservation(**bad)


def test_request_observation_rejects_relative_path() -> None:
    bad = _ro_kwargs()
    bad["concrete_path"] = "orgs/42"  # missing leading /
    with pytest.raises(ValidationError):
        RequestObservation(**bad)


def test_response_artifact_secret_kind_forbids_raw_value() -> None:
    base = _base_l2_kwargs()
    with pytest.raises(ValidationError) as exc_info:
        ResponseArtifact(
            **base,
            observation_id="ra-1",
            request_observation_id="ro-1",
            artifact_kind="token",
            value="eyJraWQiOi...",  # raw value forbidden for secret kinds (ADR-0015)
        )
    assert "secret" in str(exc_info.value).lower() or "forbidden" in str(exc_info.value).lower()


def test_response_artifact_secret_kind_requires_hash() -> None:
    base = _base_l2_kwargs()
    # Carrying hash+length is valid.
    ra = ResponseArtifact(
        **base,
        observation_id="ra-1",
        request_observation_id="ro-1",
        artifact_kind="token",
        value_hash="a" * 64,
        value_length=512,
        value_preview="eyJraWQi",
    )
    assert ra.value is None
    assert ra.value_hash == "a" * 64


def test_response_artifact_non_secret_kind_requires_raw_value() -> None:
    base = _base_l2_kwargs()
    with pytest.raises(ValidationError):
        ResponseArtifact(
            **base,
            observation_id="ra-1",
            request_observation_id="ro-1",
            artifact_kind="email",
            # value missing
        )
    # Non-secret kind with a value is fine.
    ra = ResponseArtifact(
        **base,
        observation_id="ra-2",
        request_observation_id="ro-1",
        artifact_kind="email",
        value="alice@example.com",
    )
    assert ra.value == "alice@example.com"


def test_response_artifact_non_secret_kind_rejects_hash_fields() -> None:
    base = _base_l2_kwargs()
    with pytest.raises(ValidationError):
        ResponseArtifact(
            **base,
            observation_id="ra-1",
            request_observation_id="ro-1",
            artifact_kind="email",
            value="alice@example.com",
            value_hash="a" * 64,
        )


def test_parse_failure_constructs_with_required_fields() -> None:
    base = _base_l2_kwargs()
    pf = ParseFailure(
        **base,
        observation_id="pf-1",
        error_kind="malformed_blob",
        error_message="HAR root is not an object",
    )
    assert pf.kind == "parse_failure"
    assert pf.error_kind == "malformed_blob"


def test_parse_failure_strict_rejects_unknown_fields() -> None:
    base = _base_l2_kwargs()
    with pytest.raises(ValidationError):
        ParseFailure(
            **base,
            observation_id="pf-1",
            error_kind="malformed_blob",
            error_message="boom",
            something_extra=1,
        )


def test_l2_event_discriminator_selects_variant_by_kind() -> None:
    """Pydantic v2 discriminated union: validating a dict with `kind` picks the variant."""
    adapter = TypeAdapter(L2Event)
    base = _base_l2_kwargs()
    ro_dict = {
        **base,
        "kind": "request_observation",
        "observation_id": "ro-1",
        "method": "GET",
        "host": {
            "scheme": "https",
            "canonical_hostname": "api.example.com",
            "port": None,
            "is_ip_literal": False,
        },
        "concrete_path": "/health",
        "auth_context_cue": {"is_anonymous": True},
        "response_status": 200,
        "response_size_bytes": 0,
    }
    parsed = adapter.validate_python(ro_dict)
    assert isinstance(parsed, RequestObservation)
    assert parsed.kind == "request_observation"


def test_host_ref_rejects_default_port() -> None:
    with pytest.raises(ValidationError):
        HostRef(scheme="https", canonical_hostname="api.example.com", port=443)


def test_host_ref_rejects_uppercase_hostname() -> None:
    with pytest.raises(ValidationError):
        HostRef(scheme="https", canonical_hostname="API.example.com", port=None)


def test_host_ref_rejects_trailing_dot() -> None:
    with pytest.raises(ValidationError):
        HostRef(scheme="https", canonical_hostname="api.example.com.", port=None)


def test_auth_context_cue_anonymous_forbids_credentials() -> None:
    with pytest.raises(ValidationError):
        AuthContextCue(is_anonymous=True, bearer_token_hash="a" * 64)


def test_auth_context_cue_non_anonymous_requires_credentials() -> None:
    with pytest.raises(ValidationError):
        AuthContextCue(is_anonymous=False)


def test_blob_ref_rejects_short_sha() -> None:
    with pytest.raises(ValidationError):
        BlobRef(key="k", sha256="abc", content_type="application/json", size_bytes=0)
