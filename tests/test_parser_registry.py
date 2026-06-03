"""Unit tests for the parser registry keyed by (source, blob_format)."""

from __future__ import annotations

import pytest

from doo.extraction.har import parse_har
from doo.extraction.registry import (
    UnknownParserError,
    get_parser,
    has_parser,
)


def test_har_parser_registered() -> None:
    assert has_parser("har", "har-1.2") is True
    assert get_parser("har", "har-1.2") is parse_har


def test_unknown_pair_raises() -> None:
    assert has_parser("nuclei", "nuclei-jsonl-v3") is False
    with pytest.raises(UnknownParserError):
        get_parser("nuclei", "nuclei-jsonl-v3")
