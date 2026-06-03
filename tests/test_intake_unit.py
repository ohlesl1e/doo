"""Unit tests for L1 intake with injected fakes (no docker)."""

from __future__ import annotations

import json

import pytest

from doo.events.envelope import IngestionEnvelope
from doo.ids import BlobKey, EngagementId, Sha256Hex
from doo.infra.blobs import sha256_hex
from doo.ingestion.intake import (
    IntakeDeps,
    UnknownEngagementError,
    ingest_har,
)


class _FakeEngagements:
    def __init__(self, known: set[str]) -> None:
        self._known = known

    def engagement_exists(self, engagement_id: EngagementId) -> bool:
        return engagement_id in self._known


class _FakeBlobs:
    def __init__(self) -> None:
        self.stored: dict[str, bytes] = {}

    def put_har(
        self, engagement_id: EngagementId, blob_sha256: Sha256Hex, data: bytes
    ) -> BlobKey:
        key = BlobKey(f"engagement/{engagement_id}/source/har/{blob_sha256}.har")
        self.stored[str(key)] = data
        return key


class _FakeStreams:
    def __init__(self) -> None:
        self.published: list[tuple[str, dict[str, object]]] = []

    def publish(self, stream: str, payload: dict[str, object]) -> str:
        self.published.append((stream, payload))
        return f"0-{len(self.published)}"


def _deps(known: set[str]) -> tuple[IntakeDeps, _FakeBlobs, _FakeStreams]:
    blobs = _FakeBlobs()
    streams = _FakeStreams()
    return (
        IntakeDeps(engagements=_FakeEngagements(known), blobs=blobs, streams=streams),
        blobs,
        streams,
    )


def test_known_engagement_lands_blob_and_valid_envelope() -> None:
    deps, blobs, streams = _deps({"eng-1"})
    data = b'{"log": {"entries": []}}'
    result = ingest_har(deps, engagement_id=EngagementId("eng-1"), filename="x.har", data=data)

    # Blob stored under the T2 key layout.
    expected_key = f"engagement/eng-1/source/har/{sha256_hex(data)}.har"
    assert expected_key in blobs.stored
    assert result.blob_ref == expected_key

    # Envelope published on `ingest` and passes schema validation.
    assert len(streams.published) == 1
    stream, payload = streams.published[0]
    assert stream == "ingest"
    env = IngestionEnvelope.model_validate_json(json.dumps(payload))
    assert env.engagement_id == "eng-1"
    assert env.source == "har"
    assert env.blob_format == "har-1.2"
    assert env.blob_sha256 == sha256_hex(data)
    assert len(env.trace_id) == 32


def test_unknown_engagement_rejected_before_any_write() -> None:
    deps, blobs, streams = _deps(set())
    with pytest.raises(UnknownEngagementError):
        ingest_har(deps, engagement_id=EngagementId("nope"), filename="x.har", data=b"{}")
    # Nothing landed.
    assert blobs.stored == {}
    assert streams.published == []
