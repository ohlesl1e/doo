# Testing conventions (slice 1)

How the test suite is laid out and how to extend it. CI (`.github/workflows/ci.yml`)
runs `ruff check src tests`, `mypy src` (strict), and `pytest -q` on every PR and on
pushes to `main`.

## Layout

- **Unit tests** — pure, no Docker. Fakes stand in for the Neo4j client, the
  idempotency store, and the stream client (see `tests/test_commit_unit.py` for the
  fake pattern). Fast; run on every change.
- **Integration tests** — backed by `testcontainers` (Neo4j Community, Redis, MinIO).
  They start and tear down their own containers, so no external services are needed —
  only a running Docker daemon. Use the shared fixtures in `tests/conftest.py`:
  `neo4j_container` (exposes `.username` / `.password`) and `redis_url`.
- **Dual-path Scope tests** (`tests/test_scope_dual_path.py`) — run the same
  `(node, scope)` fixtures through the Python `is_in_scope` helper and the real Rego
  policy via the `opa` CLI, asserting agreement (per ADR-0020 / CLAUDE.md "tests for
  policy decisions are unit tests on Rego"). They **skip** with a clear reason if the
  `opa` binary isn't on `PATH`; CI installs it so they run.

Run the whole suite: `pytest -q`. Skip the container-backed tests in a Docker-less
environment with `DOO_SKIP_TESTCONTAINERS=1 pytest -q`. To run the dual-path test
locally, put an `opa` binary on `PATH` (`brew install opa`, or the static binary from
openpolicyagent.org).

## Adding a HAR fixture

HAR fixtures live in `tests/fixtures/`. Keep them minimal and purpose-built: one
scenario per file (anonymous traffic, a malformed entry that must become a
`ParseFailure`, an all-malformed file the worker must survive, etc.). Name the file
for what it exercises and add a one-line note where the corpus is described. The
parser targets HAR 1.2; an exporter-variety corpus (Burp / Chrome / Firefox / Charles)
and the comprehensive end-to-end HAR land with the T8 capstone (see below).

## Adding a dual-path Scope test

Add the `(node, scope)` fixture to the shared fixture set used by
`tests/test_scope_dual_path.py` so it flows through **both** the Python helper and the
Rego policy. Slice-1 fixtures all expect `false` (deny-all Rego); when the real Rego
matching rules land (slice 4), add the `true` cases.

## Cross-engagement isolation

The engagement-scoping invariant (ADR-0017) is defended at three layers, each with a
test:

- **Commit-time gate** — `tests/test_commit_unit.py::test_scope_gate_refuses_mismatched_engagement`
  (a commit whose `engagement_id` mismatches the worker's expected id is refused
  before any write).
- **DB uniqueness constraints** — `tests/test_cross_engagement.py` (duplicate identity
  within an engagement is rejected; the same identity under a different engagement is a
  distinct node; deleting one engagement leaves another untouched; no scoped node
  carries a null `engagement_id`).
- **Query-time scoping** — `tests/test_for_engagement.py` (`for_engagement` returns
  only the current engagement's nodes).

## T8 capstone — deferred

The comprehensive end-to-end test that exercises *every* slice-1 capability
(templating, body params, response artifacts, declared-Principal/AuthContext
reconciliation, the keepalive lifecycle), the exporter-variety HAR corpus, and the
PRD user-story coverage matrix are the **T8 capstone**. They depend on T3–T6 being
in place and land once those tracers are complete. What's in CI today: the full unit
+ integration suite for everything merged so far, plus the isolation negative tests
above.
