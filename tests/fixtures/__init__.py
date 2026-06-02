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

# --- T3 path-templating corpus ---
# /users/42, /users/87, /users/123 -> one Endpoint /users/{user_id}.
USERS_TEMPLATING_HAR = FIXTURES_DIR / "users_templating.har"
# /v1/orgs/abc-123/projects + /v2/orgs/def-456/projects -> two Endpoints,
# version segment stays literal under multiplicity.
VERSION_TEMPLATING_HAR = FIXTURES_DIR / "version_templating.har"
# /users/42, /users/87, /users/settings -> /users/{user_id} + literal /users/settings.
LITERAL_SIBLING_HAR = FIXTURES_DIR / "literal_sibling.har"

# --- T5 body-extraction corpus ---
# POST+JSON (nested + a refresh_token), POST+form (text), POST+form (params),
# multipart upload (one text field + one skipped binary part), a base64 response
# body, and a no-body entry. All on api.example.com (one Host).
BODIES_HAR = FIXTURES_DIR / "bodies.har"
