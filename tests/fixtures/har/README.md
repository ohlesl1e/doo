# HAR fixture corpus

HAR 1.2 fixtures for the slice-1 ingestion pipeline. The corpus has two jobs:

1. **Exporter-shape robustness** — at least one HAR per real-world exporter, each
   reflecting that exporter's shape quirks, so the parser is regression-protected
   against exporter variation (PRD user story 37). `tests/test_har_corpus.py`
   ingests every exporter variant and asserts the parser produces
   `RequestObservation`s without raising.
2. **Comprehensive end-to-end** — one HAR (`comprehensive.har`) that exercises
   *every* T2–T6 capability, driven by `tests/e2e/test_slice1_full.py` against
   testcontainer Neo4j + Redis + MinIO.

The older single-scenario fixtures used by the per-tracer tests still live one
level up in `tests/fixtures/` (anon_burp.har, bodies.har, response_artifacts.har,
the templating trio, the malformed trio). This directory is the exporter corpus +
the capstone comprehensive HAR.

## Exporter variants

| File | Exporter | Shape quirks it carries |
|------|----------|-------------------------|
| `burp.har` | Burp Suite Professional | `creator.name = "Burp Suite Professional"`, `+00:00` offset timestamps, `bodySize: 0` GET, a form-urlencoded POST with both `postData.text` and `postData.params`. |
| `chrome.har` | Chrome DevTools (WebInspector) | Chrome-only `_priority` / `_resourceType` / `_initiator` / `_transferSize` / `_blocked_queueing` extras, HTTP/2 pseudo-headers (`:authority`, `:method`, `:path`, `:scheme`), a `pages`/`pageref` block, empty `statusText`. |
| `firefox.har` | Firefox DevTools | Non-UTC (`+02:00`) timestamps, a populated `cache.beforeRequest` block (eTag, hitCount), `headersSize` set to real byte counts, `request` keys in Firefox's field order. |
| `charles.har` | Charles Proxy | 4-space-indented formatting, `bodySize: -1` (unknown), `ssl: -1` timing, `serverIPAddress` + `connection` on the entry, `charset` in the content mimeType. |

Each exporter file is minimal (1–2 entries) but uses a **distinct host** so a test
can ingest them together and keep their subgraphs visually separable.

## Capstone + negative fixtures

| File | Purpose |
|------|---------|
| `comprehensive.har` | The single HAR the comprehensive E2E ingests. One host (`api.example.com`). Exercises: anonymous + authenticated traffic (bearer JWT whose `sub=uuid-aaa` matches the declared Principal, plus a cookie); templating (multiplicity collapse `/users/{user_id}`, version-segment-stays-literal `v1`/`v2`, literal-sibling-wins `/users/settings`); a POST + JSON body (body → MinIO, `BodyParam`s, `refresh_token` suppressed); a 500 response with an internal hostname (→ hostname + error_message artifacts); a 200 JSON response with a JWT in `access_token` + a `Server` fingerprint header (→ secret_shaped + fingerprint artifacts); and one deliberately malformed entry (missing `startedDateTime`) → `ParseFailure`. Expected graph shape is asserted with explicit Cypher in `tests/e2e/test_slice1_full.py`. |
| `malformed.har` | Valid HAR JSON whose entries are individually malformed (missing `startedDateTime`, missing `request`, relative URL) alongside one well-formed entry. Proves the parser emits `ParseFailure` events (never raises) and that good entries in the same blob still parse. |

## Adding an exporter

Drop a new `<exporter>.har` here, add a row to the table above, and add it to the
parametrised list in `tests/test_har_corpus.py`. Keep it minimal and put the
traffic on a host no other fixture uses. Tokens/secrets in a fixture are fine —
they only ever live in object storage at runtime, never in a graph node property
(ADR-0015); the E2E asserts that discipline.
