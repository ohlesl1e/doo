# doo

**Department of Offense** — a security testing copilot for black-box web application testing.

doo ingests passive testing data (Burp traffic, HAR files, recon output), builds a knowledge graph of the target, identifies coverage gaps, and dispatches bounded test agents under human supervision and policy constraints.

## Status

Pre-MVP. Design is mostly settled; no code yet. The ontology is fully drafted, 11 ADRs are recorded, and the remaining open design questions are tracked in [`docs/grill-queue.md`](docs/grill-queue.md).


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

## Tech stack

| Concern | Choice |
|---|---|
| Primary language | Python |
| Burp integration | Kotlin/Java extension via Montoya API |
| Queue | Redis Streams |
| Object storage | S3 or MinIO |
| Schemas | Pydantic |
| Graph DB | Neo4j |
| Policy engine | OPA + Rego |
| LLM access | Anthropic API + local LiteLLM |
| Tool protocol | MCP |
| Observability | OpenTelemetry |

## Hard rules

- No LLM in extraction parsing, policy decisions, or request construction at execution time.
- Black-box only — no source-code or internal-diagram seeding.
- Human-in-the-loop for production targets. Auto mode only for staging.
- Kill switch lives outside the agent process.
- OPA checks happen twice — at planner and at dispatcher.
- Provenance and confidence on every node and edge. No exceptions.

## Repository layout

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — five-layer architecture, tech stack, build order.
- [`ONTOLOGY.md`](ONTOLOGY.md) — graph schema.
- [`CONTEXT.md`](CONTEXT.md) — domain language.
- [`docs/adr/`](docs/adr/) — architecture decision records (0001–0011).
- [`docs/grill-queue.md`](docs/grill-queue.md) — open design decisions before MVP code lands.
- [`docs/agents/`](docs/agents/) — agent skill docs (issue tracker, triage labels, domain docs).

## License

See [`LICENSE`](LICENSE).
