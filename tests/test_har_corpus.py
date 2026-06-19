"""Exporter-shape robustness for the HAR parser (T8 capstone, PRD story 37).

The parser targets HAR 1.2 but must tolerate the shape quirks each real-world
exporter emits: Chrome's `_priority` / `_resourceType` / HTTP/2 pseudo-headers,
Firefox's `cache` blocks and non-UTC timestamps, Charles's `bodySize: -1` and
formatting, Burp's `postData.params`. This test ingests every exporter variant
through the pure parser and asserts it yields `RequestObservation`s without
raising, and that the malformed corpus surfaces `ParseFailure`s (never crashes)
while still parsing the good entry beside them.

Pure parser test — no infrastructure (the bodies are skipped when no uploader is
passed). The full L1->L2->L3 wiring is covered by `tests/test_pipeline_e2e.py`
and the comprehensive E2E.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from doo.events.envelope import IngestionEnvelope
from doo.events.observation import ParseFailure, RequestObservation
from doo.extraction.har import parse_har
from doo.ids import BlobKey, EngagementId, IdempotencyKey, Sha256Hex
from tests.fixtures import (
    BURP_EXPORT_HAR,
    CHARLES_EXPORT_HAR,
    CHROME_EXPORT_HAR,
    EXPORTER_HARS,
    FIREFOX_EXPORT_HAR,
    HAR_DIR_MALFORMED,
)


def _envelope() -> IngestionEnvelope:
    return IngestionEnvelope(
        event_id=uuid4(),
        trace_id="a" * 32,  # type: ignore[arg-type]
        span_id="b" * 16,  # type: ignore[arg-type]
        engagement_id=EngagementId("eng-corpus"),
        source="har",
        source_version=None,
        blob_ref=BlobKey("engagement/eng-corpus/source/har/x.har"),
        blob_format="har-1.2",
        blob_sha256=Sha256Hex("c" * 64),
        idempotency_key=IdempotencyKey("d" * 64),
        received_at=datetime.now(UTC),
        producer_id="test",
        bytes_size=10,
    )


@pytest.mark.parametrize(
    "har_path",
    EXPORTER_HARS,
    ids=[p.stem for p in EXPORTER_HARS],
)
def test_exporter_variant_parses_without_error(har_path: Path) -> None:
    """Every exporter variant yields >=1 RequestObservation and no ParseFailures."""

    events = list(parse_har(har_path.read_bytes(), _envelope()))
    obs = [e for e in events if isinstance(e, RequestObservation)]
    failures = [e for e in events if isinstance(e, ParseFailure)]
    assert obs, f"{har_path.name}: parser yielded no RequestObservation"
    assert failures == [], (
        f"{har_path.name}: well-formed exporter HAR produced ParseFailures: "
        f"{[f.error_message for f in failures]}"
    )
    # Shape sanity: absolute URL split into a canonical host + path on each RO.
    for o in obs:
        assert o.host.canonical_hostname
        assert o.concrete_path.startswith("/")
        assert o.method in {"GET", "POST", "PUT", "PATCH", "DELETE"}


def test_all_exporter_variants_use_distinct_hosts() -> None:
    """Each exporter fixture lives on its own host (keeps subgraphs separable)."""

    hosts: set[str] = set()
    for har_path in EXPORTER_HARS:
        events = list(parse_har(har_path.read_bytes(), _envelope()))
        for o in events:
            if isinstance(o, RequestObservation):
                hosts.add(o.host.canonical_hostname)
    assert hosts == {
        "shop.example.com",
        "app.example.com",
        "www.example.org",
        "api.charlestest.example",
    }


def test_chrome_http2_pseudo_headers_and_extras_tolerated() -> None:
    """Chrome's `:authority` pseudo-headers + `_priority`/`_resourceType` don't break parsing."""

    events = list(parse_har(CHROME_EXPORT_HAR.read_bytes(), _envelope()))
    obs = [e for e in events if isinstance(e, RequestObservation)]
    assert len(obs) == 1
    o = obs[0]
    assert o.host.canonical_hostname == "app.example.com"
    assert o.concrete_path == "/dashboard"
    # Chrome puts the session cookie in `cookies`; the cue is non-anonymous.
    assert o.auth_context_cue.is_anonymous is False
    assert {p.name for p in o.query_params} == {"tab"}


def test_firefox_cache_block_and_offset_timestamp_tolerated() -> None:
    events = list(parse_har(FIREFOX_EXPORT_HAR.read_bytes(), _envelope()))
    obs = [e for e in events if isinstance(e, RequestObservation)]
    assert len(obs) == 1
    assert obs[0].host.canonical_hostname == "www.example.org"
    assert obs[0].concrete_path == "/api/items"


def test_burp_form_postdata_params_tolerated() -> None:
    events = list(parse_har(BURP_EXPORT_HAR.read_bytes(), _envelope()))
    obs = [e for e in events if isinstance(e, RequestObservation)]
    methods = sorted(o.method for o in obs)
    assert methods == ["GET", "POST"]


def test_charles_unknown_bodysize_tolerated() -> None:
    events = list(parse_har(CHARLES_EXPORT_HAR.read_bytes(), _envelope()))
    obs = [e for e in events if isinstance(e, RequestObservation)]
    assert len(obs) == 1
    assert obs[0].host.canonical_hostname == "api.charlestest.example"


def test_malformed_corpus_surfaces_failures_and_still_parses_good_entry() -> None:
    """The malformed HAR yields ParseFailures for the bad entries + 1 good RO."""

    events = list(parse_har(HAR_DIR_MALFORMED.read_bytes(), _envelope()))
    obs = [e for e in events if isinstance(e, RequestObservation)]
    failures = [e for e in events if isinstance(e, ParseFailure)]
    assert len(obs) == 1  # the one well-formed entry
    assert obs[0].concrete_path == "/ok"
    assert len(failures) == 3  # missing time, missing request, relative url
    kinds = {f.error_kind for f in failures}
    assert kinds == {"missing_required_field", "schema_mismatch"}
