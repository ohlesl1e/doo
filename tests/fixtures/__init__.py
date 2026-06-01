"""Test fixtures for the slice-1 T2 pipeline (HAR corpus + path helpers)."""

from __future__ import annotations

from pathlib import Path

FIXTURES_DIR = Path(__file__).parent

# Anonymous Burp-exported HAR: several GETs across 3 distinct concrete paths on
# one host.
ANON_HAR = FIXTURES_DIR / "anon_burp.har"
# One malformed entry mixed with good entries.
MIXED_HAR = FIXTURES_DIR / "mixed_one_malformed.har"
# Every entry malformed (worker must complete without crashing).
ALL_MALFORMED_HAR = FIXTURES_DIR / "all_malformed.har"
# Not even valid JSON.
NOT_JSON_HAR = FIXTURES_DIR / "not_json.har"
