# doo

**Department of Offense** — a security testing copilot for black-box web application testing.

doo ingests passive testing data (Burp traffic, HAR files, recon output), builds a knowledge graph of the target, identifies coverage gaps, and dispatches bounded test agents under human supervision and policy constraints.

## Status

**Slice 1 complete** — the full HAR → graph pipeline. Drop in a HAR file and get an engagement-isolated Neo4j graph of the target: canonicalised hosts, templated endpoints, aggregated parameters, declared/discovered/anonymous principals, request/response bodies in object storage, and response artifacts — with provenance on every node and secrets hashed at the L2 boundary. CI (lint + types + the full testcontainer suite) is in place.

See **[`docs/running.md`](docs/running.md)** to run it.

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

1. **Ingestion + graph** — Burp/HAR → Neo4j, queryable.
2. **Coverage analysis** — deterministic queries over the graph (~60% of the value, ~10% of the risk).
3. **LLM-assisted hypothesis generation** — human approves before dispatch.
4. **Bounded agent execution** — only after 1–3 are solid.

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
- [`docs/running.md`](docs/running.md) — how to run the pipeline locally.
- [`docs/adr/`](docs/adr/) — architecture decision records (0001–0021).
- [`docs/grill-queue.md`](docs/grill-queue.md) — open design decisions tracking.
- [`docs/agents/`](docs/agents/) — agent skill docs (issue tracker, triage labels, domain docs).

## Quickstart

```sh
docker compose up -d --wait          # Neo4j + Redis + MinIO
.venv/bin/pip install -e '.[dev]'
cp .env.example .env                 # connection config; doo auto-loads it

# turn a HAR into a graph:
.venv/bin/doo engagement start --config tests/fixtures/yaml/acme-test.yaml
.venv/bin/doo ingest har --engagement acme-test tests/fixtures/har/comprehensive.har
.venv/bin/doo worker run --once
# then explore http://localhost:7474  (neo4j / doo-dev-password)
```

Full walkthrough, command reference, and troubleshooting: **[`docs/running.md`](docs/running.md)**.

Run the tests (testcontainers — no compose stack needed):

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
