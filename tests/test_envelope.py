"""IngestionEnvelope contract tests.

Acceptance criterion: strict mode rejects unknown fields, plus W3C trace-id /
span-id format enforcement.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from doo.events import IngestionEnvelope


def _valid_kwargs() -> dict:
    return dict(
        event_id=uuid.uuid4(),
        trace_id="0" * 32,
        span_id="0" * 16,
        engagement_id="acme-2026",
        source="har",
        source_version="1.2",
        blob_ref="engagements/acme-2026/blobs/abc.har",
        blob_format="har-1.2",
        blob_sha256="a" * 64,
        idempotency_key="b" * 64,
        received_at=datetime.now(UTC),
        producer_id="har-upload-cli",
        bytes_size=12345,
    )


def test_envelope_constructs_cleanly() -> None:
    env = IngestionEnvelope(**_valid_kwargs())
    assert env.source == "har"
    assert env.bytes_size == 12345


def test_envelope_rejects_unknown_fields() -> None:
    bad = _valid_kwargs()
    bad["bogus_field"] = "value"
    with pytest.raises(ValidationError) as exc_info:
        IngestionEnvelope(**bad)
    assert "bogus_field" in str(exc_info.value).lower() or "extra" in str(exc_info.value).lower()


def test_envelope_rejects_unknown_source() -> None:
    bad = _valid_kwargs()
    bad["source"] = "not-a-real-tool"
    with pytest.raises(ValidationError):
        IngestionEnvelope(**bad)


def test_envelope_rejects_bad_trace_id() -> None:
    bad = _valid_kwargs()
    bad["trace_id"] = "not-hex"
    with pytest.raises(ValidationError):
        IngestionEnvelope(**bad)


def test_envelope_rejects_bad_span_id() -> None:
    bad = _valid_kwargs()
    bad["span_id"] = "0" * 8  # too short
    with pytest.raises(ValidationError):
        IngestionEnvelope(**bad)


def test_envelope_rejects_bad_blob_sha256() -> None:
    bad = _valid_kwargs()
    bad["blob_sha256"] = "ZZZ"
    with pytest.raises(ValidationError):
        IngestionEnvelope(**bad)


def test_envelope_accepts_every_canonical_source() -> None:
    from doo.events import SOURCE_KINDS

    base = _valid_kwargs()
    for source in SOURCE_KINDS:
        base["source"] = source
        env = IngestionEnvelope(**base)
        assert env.source == source
