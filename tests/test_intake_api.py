"""FastAPI route tests for `POST /ingest/har` (multipart), using fakes."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from doo.events.envelope import IngestionEnvelope
from doo.ids import BlobKey, EngagementId, Sha256Hex
from doo.ingestion.intake import IntakeDeps, build_app


class _Engagements:
    def __init__(self, known: set[str]) -> None:
        self._known = known

    def engagement_exists(self, engagement_id: EngagementId) -> bool:
        return engagement_id in self._known


class _Blobs:
    def __init__(self) -> None:
        self.stored: dict[str, bytes] = {}

    def put_har(self, engagement_id, blob_sha256: Sha256Hex, data: bytes) -> BlobKey:  # type: ignore[no-untyped-def]
        key = BlobKey(f"engagement/{engagement_id}/source/har/{blob_sha256}.har")
        self.stored[str(key)] = data
        return key


class _Streams:
    def __init__(self) -> None:
        self.published: list[tuple[str, dict[str, object]]] = []

    def publish(self, stream: str, payload: dict[str, object]) -> str:
        self.published.append((stream, payload))
        return f"0-{len(self.published)}"


def _client(known: set[str]) -> tuple[TestClient, _Blobs, _Streams]:
    blobs = _Blobs()
    streams = _Streams()
    app = build_app(IntakeDeps(engagements=_Engagements(known), blobs=blobs, streams=streams))
    return TestClient(app), blobs, streams


def test_post_ingest_har_accepts_known_engagement() -> None:
    client, blobs, streams = _client({"eng-1"})
    har = b'{"log": {"entries": []}}'
    resp = client.post(
        "/ingest/har",
        data={"engagement_id": "eng-1"},
        files={"file": ("x.har", har, "application/json")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["engagement_id"] == "eng-1"
    assert body["blob_ref"].startswith("engagement/eng-1/source/har/")
    assert len(streams.published) == 1
    env = IngestionEnvelope.model_validate_json(json.dumps(streams.published[0][1]))
    assert env.source == "har"


def test_post_ingest_har_unknown_engagement_returns_4xx_and_lands_nothing() -> None:
    client, blobs, streams = _client(set())
    resp = client.post(
        "/ingest/har",
        data={"engagement_id": "nope"},
        files={"file": ("x.har", b"{}", "application/json")},
    )
    assert resp.status_code == 404
    assert blobs.stored == {}
    assert streams.published == []
