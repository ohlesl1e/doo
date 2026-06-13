# doo

**Department of Offense** — a security testing copilot for black-box web application testing.

doo ingests passive testing data (Burp traffic, HAR files, recon output), builds a knowledge graph of the target, identifies coverage gaps, and dispatches bounded test agents under human supervision and policy constraints.

## Status

**Slices 1–4 complete — the MVP five-layer vertical is end-to-end.**

- **Slice 1 — ingestion + graph.** Drop in a HAR file and get an engagement-isolated Neo4j graph of the target: canonicalised hosts, templated endpoints, aggregated parameters, declared/discovered/anonymous principals, request/response bodies in object storage, and promoted values (`ObservedValue`) — provenance on every node, secrets hashed at the L2 boundary.
- **Slice 2 — coverage analysis.** Deterministic, read-only queries over the graph (`doo coverage`): C1 dead endpoints, C2/C2b presence- and content-differential authz gaps, C3 leak-to-input pivots, C4 capability-tier gaps. Surfaces gaps at query time; writes nothing back.
- **Slice 3 — the Planner (the first LLM).** `doo planner propose` turns coverage gaps into typed test **proposals** and `doo planner review` is the deterministically-prioritised human review queue. Deterministic candidate generators select targets (C1–C4, capability/tenant `TrustBoundary`s, and sink-shaped params); for gaps that need reasoning an LLM proposes a structured `TestCase` (enums + handle references, **never request bytes**); a deterministic Validator resolves/scopes/dedups it; survivors commit as content-addressed `TestCase`s at `review_status = proposed`. **Nothing is dispatched** — approved tests wait for slice 4.
- **Slice 4 — bounded agent execution (the first traffic).** `doo dispatch run` arms a budget-bounded run that drains `approved` tests through one Dispatcher gate (kill-switch lease → real OPA → budget → wire); a deterministic Executor builds each request (the LLM never composes bytes) and an Interpreter confirm-loop judges the result into a verdict — the fourth `TestCase` axis — committing a `Finding@proposed` when `vulnerable`. Adds the ADR-0044 liveness `dispatch_status` classifier, replay-hazard resolution + `doo dispatch review`, the `doo auth-helper` token-rotation sibling, C5/C5a/C5b boundary coverage, and Interpreter `follow_ups` back to the Planner. `doo finding review` is the human gate before reporting.

CI (lint + types + the full testcontainer suite) is in place. See [**Running doo**](#running-doo) below to run it.

## Design principles

1. **The LLM is at the end of the pipeline, not the middle.** Layers 1–3 work correctly without any LLM involvement. The LLM proposes and interprets; deterministic code parses, stores, validates, and executes.
2. **Black-box only.** Everything is an observation or an inference from observations. No declarative seeding from source code, swagger specs, or internal diagrams — when those exist, they enter through ingestion as discovered artifacts with provenance.
3. **Human-in-the-loop by default.** The system proposes; humans approve dispatch (at least for production targets). The kill switch lives outside the agent process — a signal the agent cannot suppress.
4. **Policy enforcement is defense-in-depth.** Rules of Engagement are checked at the planner (efficiency) AND at the dispatcher (correctness).
5. **Provenance and confidence are first-class.** Every node and edge knows where it came from and how certain it is.

## Architecture

Five layers plus cross-cutting observability:

```
L1 Ingestion   →   L2 Extraction   →   L3 Ontology   →   L4 ROE   →   L5 Action
Burp / HAR /       Parse, normalize,    Neo4j graph,      OPA +        Planner → Validator
recon → queue      enrich, extract      entity            Rego         → Executor → Interpreter
                   entities             resolution                      (narrow MCP tools)
```

Full breakdown in [`ARCHITECTURE.md`](ARCHITECTURE.md). Graph schema in [`ONTOLOGY.md`](ONTOLOGY.md). Domain language in [`CONTEXT.md`](CONTEXT.md). Decisions in [`docs/adr/`](docs/adr/).

## Build order

Build vertically through one slice before broadening:

1. ✅ **Ingestion + graph** — Burp/HAR → Neo4j, queryable.
2. ✅ **Coverage analysis** — deterministic queries over the graph (~60% of the value, ~10% of the risk).
3. ✅ **LLM-assisted hypothesis generation** — the Planner proposes, a deterministic Validator checks, a human approves; nothing dispatched.
4. ✅ **Bounded agent execution** — Executor + Interpreter; the first slice that sends traffic, under human arming + kill-switch + dispatcher-side OPA.

## Repository layout

Code:
- `src/doo/ids/` — typed identifier aliases (`EngagementId`, `PrincipalId`, ...).
- `src/doo/canonical/` — cross-cutting `Provenanced` / `Inferred` mixins (ADR-0005) and value objects (`HostRef`, `BlobRef`, `AuthContextCue`).
- `src/doo/events/` — layer-boundary contracts: `IngestionEnvelope` (L1→L2), `L2Event` discriminated union (L2→L3), `L3Event` discriminated union (L3→consumers), plus the slice-4 hedge contracts (`TestCase`, `Finding`, `ExecutedAsEdge`).
- `src/doo/setup/` — `EngagementConfig` Pydantic model and the idempotent loader (ADR-0019).
- `src/doo/ontology/` — Neo4j schema bootstrap (ADR-0017 constraints + indexes + property-existence).
- `src/doo/observability/` — `structlog` config and W3C trace-context id generators (ADR-0018).
- `src/doo/cli.py` + `cli_worker.py` — Typer CLI (`doo engagement start/status/keepalive`, `doo ingest har`, `doo worker run`).
- `src/doo/ingestion/` (L1 intake + L2 worker), `src/doo/extraction/` (HAR parser + response-artifact extractors), `src/doo/ontology/` (L3 commit, entity resolution, path templating), `src/doo/policy/` (Scope evaluator + deny-all Rego), `src/doo/infra/` (Redis/MinIO/Neo4j clients), `src/doo/engagement/` (kill-switch keepalive).

Design docs:
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — five-layer architecture, tech stack, build order, layer contracts.
- [`ONTOLOGY.md`](ONTOLOGY.md) — graph schema (six-step draft, all done).
- [`CONTEXT.md`](CONTEXT.md) — domain language.
- [`docs/adr/`](docs/adr/) — architecture decision records (0001–0025).
- [`docs/grill-queue.md`](docs/grill-queue.md) — open design decisions tracking.
- [`docs/agents/`](docs/agents/) — agent skill docs (issue tracker, triage labels, domain docs).

## Running doo

Drop a HAR in, get an engagement-isolated Neo4j graph of the target. There is no active testing yet — this is the ingestion → graph half of the pipeline.

### Prerequisites

- **Docker** — for the Neo4j / Redis / MinIO stack and the testcontainer-based tests.
- **Python 3.12** and a venv:

```sh
python -m venv .venv
.venv/bin/pip install -e '.[dev,llm]'
```

`dev` is the test/lint toolchain; `llm` pulls in `litellm` for `doo planner propose` against a real model. CI installs `.[dev]` only — the planner tests use a fake caller and don't need `litellm`. (Examples call binaries as `.venv/bin/doo`; activate the venv if you prefer bare `doo`.)

### 1. Start the stack

```sh
docker compose up -d --wait      # Neo4j (7474/7687), Redis (6379), MinIO (9000/9001)
```

Web UIs:
- **Neo4j Browser** — http://localhost:7474 — `neo4j` / `doo-dev-password`
- **MinIO Console** — http://localhost:9001 — `doo-dev` / `doo-dev-password`

### 2. Configure the connection env

The CLI reads `DOO_*` env vars, and its built-in defaults do **not** match the compose credentials — so set them, easiest via the committed template:

```sh
cp .env.example .env
```

`doo` auto-loads `.env` from the current directory, so running from the repo root needs no manual exports (an explicit `export` still wins).

### 3. Ingest a HAR → graph

```sh
# acme-test.yaml declares a Principal whose token is ${DOO_TEST_TOKEN_A}:
export DOO_TEST_TOKEN_A=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1dWlkLWFhYSIsImV4cCI6NDEwMjQ0NDgwMH0.g32AFQCk2wGfExJCjL61A7bgUXAqwvfY1AF0-w5I-K0

.venv/bin/doo engagement start --config tests/fixtures/yaml/acme-test.yaml
.venv/bin/doo ingest har --engagement acme-test tests/fixtures/har/comprehensive.har
.venv/bin/doo worker run --once     # drains the pipeline and builds the graph
```

`engagement start` is idempotent (diff-and-confirm on a material change; `--apply` skips the prompt). `ingest har` is **L1 only** — it queues the HAR; `worker run` (L2+L3) builds the graph and prints a summary, including a grouped report of any entries that failed to parse. Drop in your own capture with `--engagement acme-test path/to.har` — scope does not gate ingestion, so out-of-scope hosts land too. `doo worker run` (no `--once`) leaves a daemon running; `doo engagement keepalive <id>` runs the external kill-switch lease.

### Exploring the graph

In **Neo4j Browser** (http://localhost:7474):

```cypher
MATCH (n {engagement_id:'acme-test'}) RETURN labels(n)[0] AS label, count(*) ORDER BY label;
MATCH (e:Endpoint {engagement_id:'acme-test'}) RETURN e.method, e.path_template;
MATCH (:RequestObservation)-[:YIELDED_VALUE]->(v:ObservedValue) RETURN v.kind, v.value LIMIT 50;
```

Request/response bodies live in MinIO; the graph holds `BlobRef`s.

### Analyze coverage + plan tests (slices 2–3)

```sh
# Coverage: deterministic gaps over the graph (read-only).
.venv/bin/doo coverage c2 --engagement acme-test        # presence-differential authz gaps
.venv/bin/doo coverage c4 --engagement acme-test        # capability-tier gaps  (also: c1, c2b, c3)

# Planner: turn gaps into proposed TestCases (deterministic C1 needs no LLM; the
# LLM generators need a model — see "Planner LLM config" below).
.venv/bin/doo planner propose --engagement acme-test                    # all enabled generators
.venv/bin/doo planner propose --engagement acme-test -g c1              # one generator (C1 = no LLM)
.venv/bin/doo planner review  --engagement acme-test                    # prioritised review queue
.venv/bin/doo planner review  --engagement acme-test --approve <key> --actor you
```

`propose` selects targets deterministically, has the LLM propose a structured `TestCase` for gaps that need reasoning (the Validator rejects any hallucinated handle / out-of-scope target), and commits survivors at `review_status = proposed`. `review` is the deterministically-prioritised queue; approve/reject is recorded in a provenanced audit ledger. **Nothing is dispatched** — `approved` means "cleared for consideration," not "authorized to send" (slice 4).

**Planner LLM config** (only for the LLM generators; C1 is deterministic). The model is reached through litellm — a lazy dep pulled in by the `llm` extra (see setup above). The model is **config, not code** — set in `.env`:

```sh
DOO_PLANNER_MODEL=anthropic/claude-sonnet-4-6   # default: claude-opus-4-8
# Mode A — Anthropic directly:        ANTHROPIC_API_KEY=sk-ant-...
# Mode B — a provider URL + key:      DOO_PLANNER_API_BASE=https://gateway/v1 ; DOO_PLANNER_API_KEY=...  (model: openai/<name>)
```

Per ADR-0037 the exact context pack + LLM request/response are persisted to object storage for every proposal (replayability); `DOO_S3_*` (already set for ingestion) is reused.

### Dispatch + confirm + report (slice 4)

The first commands that **send traffic**. A dispatch run is the authorization unit (ADR-0042): one arming decision drains a budget-bounded selection of `approved` `TestCase`s, each through the Dispatcher gate (kill-switch lease → OPA → budget → wire). The kill-switch keepalive **must** be running in another terminal, and on `production` engagements only `arming=review` + `interpreter=confirm` is permitted.

```sh
# 0. In a SEPARATE terminal — the kill switch the dispatcher reads on every send.
.venv/bin/doo engagement keepalive acme-test

# (optional) token rotation sibling — proactive + reactive; holds refresh creds in
# ITS env, never the dispatcher's. Rotated material lands where the Executor reads it.
.venv/bin/doo auth-helper run --engagement acme-test --config engagement.yaml

# 1. Arm + drain a run (real OPA needs `opa` on PATH; --unsafe-stub-opa is staging-only).
.venv/bin/doo dispatch run -e acme-test -c engagement.yaml --select test_class=idor -n 20
#   per TestCase: deterministic constructor → Dispatcher gate → wire → EXECUTED_AS,
#   then the Interpreter confirm loop judges it (verdict = the 4th TestCase axis).

# 2. Triage refusals (hazard_unresolved / dispatcher_blocked); supply a CSRF source_hint
#    or accept the replay risk — the next run reads the override.
.venv/bin/doo dispatch review -e acme-test
.venv/bin/doo dispatch review -e acme-test --set-hint <key_hash> csrf_token /orders/new

# 3. Review proposed Findings (a `vulnerable` verdict commits one); only confirmed feed reporting.
.venv/bin/doo finding review -e acme-test
.venv/bin/doo finding review -e acme-test --confirm <finding_key> --actor you

# 4. What boundaries are still untested-to-verdict? (also c5a / c5b)
.venv/bin/doo coverage c5 --engagement acme-test
```

The LLM never composes request bytes (constructors do) and never sets `dispatch_status` (a deterministic classifier does, ADR-0013/0044). The Interpreter picks request *roles* from a closed per-`test_class` enum and may surface `follow_ups` — new hypotheses that go back through the Planner's Validator to `review_status=proposed` (`source=llm-interpreter`), never dispatched in-run (`confirm` mode). The Interpreter uses the same `DOO_PLANNER_*` model config as the Planner.

### Command reference

| Command | What it does |
|---|---|
| `doo engagement start --config <yaml> [--apply]` | Create/re-attach an engagement (idempotent; diff+confirm on material changes) |
| `doo engagement status <id>` | Print an engagement's properties + Scope hash |
| `doo engagement keepalive <id>` | Run the external kill-switch lease keeper |
| `doo ingest har --engagement <id> <har>` | L1: upload the HAR + queue an envelope |
| `doo worker run [--once] [--batch N]` | L2+L3: drain the streams into the graph |
| `doo coverage c1\|c2\|c2b\|c3\|c4\|c5\|c5a\|c5b --engagement <id>` | Deterministic coverage gaps (read-only; `--json` available). C5* are TrustBoundary test coverage |
| `doo planner propose --engagement <id> [-g <gen>]` | Select gaps → propose + validate + commit `TestCase`s (no dispatch) |
| `doo planner review --engagement <id> [--approve\|--reject <key> --actor <who>]` | Prioritised review queue; approve/reject into the audit ledger |
| `doo dispatch run -e <id> -c <yaml> [--select k=v -n N]` | Arm + drain a budget-bounded run: gate → send → `EXECUTED_AS` → confirm-loop verdict |
| `doo dispatch review -e <id> [--set-hint\|--ignore-hazard …]` | Triage refused/blocked TestCases; set hazard overrides the next run reads |
| `doo finding review -e <id> [--confirm\|--reject <key> --actor <who>]` | Review `proposed` Findings; only `confirmed` feed reporting |
| `doo auth-helper run -e <id> -c <yaml>` | Sibling process: rotate declared AuthContexts (proactive + reactive) |

### Troubleshooting

- **`AuthError … unauthorized`** — wrong/absent Neo4j password. The CLI default is `password`; compose uses `doo-dev-password`. Set `DOO_NEO4J_PASSWORD` (or `cp .env.example .env`).
- **`Cannot reach Neo4j …`** — the stack isn't up: `docker compose up -d --wait`.
- **A HAR ingested but no Host/Endpoint appeared** — `ingest har` only does L1; run `doo worker run --once` to build the graph.
- **`worker run` reports parse failures / `decode_error`** — the HAR isn't valid JSON (often a truncated export). Confirm with `python -m json.tool your.har > /dev/null`, then re-export. Malformed *entries* become `ParseFailure` nodes; the rest still ingest.
- **Large HARs are slow** — endpoint inference and value promotion run once at the end of the drain (resumable).

### Teardown

```sh
docker compose down -v     # -v also wipes the graph + blobs
```

### Running the tests

The suite uses testcontainers (it starts its own throwaway Neo4j/Redis/MinIO, so the compose stack isn't required) and an `opa` binary for the dual-path Scope test. See [`docs/contributing-testing.md`](docs/contributing-testing.md).

```sh
.venv/bin/pytest -q
```

## Tech stack

| Concern | Choice |
|---|---|
| Primary language | Python 3.12 |
| Burp integration | Kotlin/Java extension via Montoya API (later slice) |
| Queue | Redis Streams |
| Object storage | S3 or MinIO |
| Schemas | Pydantic v2 |
| Graph DB | Neo4j 5 |
| Policy engine | OPA + Rego (later slice) |
| LLM access | Anthropic API + local LiteLLM (later slice) |
| Tool protocol | MCP (later slice) |
| Observability | OpenTelemetry — correlation IDs from day 1, SDK deferred (ADR-0018) |

## Hard rules

- No LLM in extraction parsing, policy decisions, or request construction at execution time.
- Black-box only — no source-code or internal-diagram seeding.
- Human-in-the-loop for production targets. Auto mode only for staging.
- Kill switch lives outside the agent process.
- OPA checks happen twice — at planner and at dispatcher.
- Provenance and confidence on every node and edge. No exceptions.

## License

See [`LICENSE`](LICENSE).
