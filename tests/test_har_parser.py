"""Unit tests for the HAR 1.2 parser (T2 deep module B)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from doo.events.envelope import IngestionEnvelope
from doo.events.observation import ParseFailure, RequestObservation
from doo.extraction.har import parse_har
from doo.ids import BlobKey, EngagementId, IdempotencyKey, Sha256Hex
from tests.fixtures import ALL_MALFORMED_HAR, ANON_HAR, MIXED_HAR, NOT_JSON_HAR

ENG = EngagementId("eng-har-test")
TRACE = "a" * 32
SPAN = "b" * 16
SHA = "c" * 64


def _envelope() -> IngestionEnvelope:
    return IngestionEnvelope(
        event_id=uuid4(),
        trace_id=TRACE,  # type: ignore[arg-type]
        span_id=SPAN,  # type: ignore[arg-type]
        engagement_id=ENG,
        source="har",
        source_version=None,
        blob_ref=BlobKey("engagement/eng-har-test/source/har/x.har"),
        blob_format="har-1.2",
        blob_sha256=Sha256Hex(SHA),
        idempotency_key=IdempotencyKey("d" * 64),
        received_at=datetime.now(UTC),
        producer_id="test",
        bytes_size=10,
    )


def test_anon_har_yields_one_observation_per_entry() -> None:
    events = list(parse_har(ANON_HAR.read_bytes(), _envelope()))
    obs = [e for e in events if isinstance(e, RequestObservation)]
    failures = [e for e in events if isinstance(e, ParseFailure)]
    assert len(obs) == 4
    assert failures == []
    for o in obs:
        assert o.method == "GET"
        assert o.auth_context_cue.is_anonymous is True
        assert o.request_body_ref is None
        assert o.body_params == ()
        assert o.response_body_ref is None
        assert o.trace_id == TRACE  # trace propagated from envelope
        assert o.envelope_event_id is not None


def test_anon_har_canonicalises_paths() -> None:
    events = list(parse_har(ANON_HAR.read_bytes(), _envelope()))
    paths = sorted({e.concrete_path for e in events if isinstance(e, RequestObservation)})
    # /products and /products/ both canonicalise to /products.
    assert paths == ["/about", "/products", "/products/42"]


def test_source_id_is_stable_per_entry() -> None:
    env = _envelope()
    first = [e.source_id for e in parse_har(ANON_HAR.read_bytes(), env)]
    second = [e.source_id for e in parse_har(ANON_HAR.read_bytes(), env)]
    assert first == second  # deterministic, re-extraction stable (ADR-0016)
    assert first[0] == "0|2026-05-01T10:00:00.000Z"


def test_mixed_har_one_malformed_entry_others_ingest() -> None:
    events = list(parse_har(MIXED_HAR.read_bytes(), _envelope()))
    obs = [e for e in events if isinstance(e, RequestObservation)]
    failures = [e for e in events if isinstance(e, ParseFailure)]
    assert len(obs) == 2
    assert len(failures) == 1
    pf = failures[0]
    assert pf.error_kind == "missing_required_field"
    assert pf.envelope_event_id is not None
    assert "url" in pf.error_message


def test_all_malformed_har_yields_only_failures_no_crash() -> None:
    events = list(parse_har(ALL_MALFORMED_HAR.read_bytes(), _envelope()))
    assert all(isinstance(e, ParseFailure) for e in events)
    assert len(events) == 4  # one per entry, none dropped


def test_not_json_blob_yields_single_blob_level_failure() -> None:
    events = list(parse_har(NOT_JSON_HAR.read_bytes(), _envelope()))
    assert len(events) == 1
    assert isinstance(events[0], ParseFailure)
    assert events[0].error_kind == "decode_error"


def test_har_without_log_entries_yields_schema_mismatch() -> None:
    events = list(parse_har(b'{"not": "a har"}', _envelope()))
    assert len(events) == 1
    assert isinstance(events[0], ParseFailure)
    assert events[0].error_kind == "schema_mismatch"
