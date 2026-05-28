# Claude Code Project Context

## What this project is

A security testing copilot for black-box web application testing. It ingests passive testing data (Burp traffic, HAR files, recon output), builds a knowledge graph of the target, identifies coverage gaps, and dispatches bounded test agents under human supervision and policy constraints.

Used for two workflows:
1. **Internal product security research** against staging/VM images, findings → internal bug tracker.
2. **Bug bounty research** against external programs, findings → responsible disclosure, public blog post after patch + advisory.

The system always operates in black-box mode, even for internal testing, to simulate a real attacker.

## Key design documents

- `ARCHITECTURE.md` — five-layer architecture, tech stack, build order.
- `ONTOLOGY.md` — graph schema (work in progress; Step 1 drafted, Steps 2-6 pending).

**Read these before suggesting code changes.** They contain the decisions we've made and the rationale.

## Five-layer architecture (summary)

1. **Ingestion** — Burp extension, HAR uploads, recon tool output → queue. Starting with Redis Streams, not Kafka.
2. **Extraction** — parse, normalize, enrich, extract entities. Plain Python + Pydantic.
3. **Ontology** — entity resolution, graph construction in Neo4j. See `ONTOLOGY.md`.
4. **Rules of Engagement** — OPA + Rego. Enforced at both planner AND dispatcher (defense in depth).
5. **Action** — Planner (LLM) → Validator (deterministic) → Executor (MCP tools) → Interpreter (LLM).

Plus cross-cutting observability/audit via OpenTelemetry.

## Build order (do not skip ahead)

1. Ingestion + graph (Burp/HAR → Neo4j).
2. Coverage analysis (deterministic queries over the graph — ~60% of value, ~10% of risk).
3. LLM-assisted hypothesis generation (human approves before dispatch).
4. Bounded agent execution.

Build vertically through one slice before broadening. Do not scaffold all five layers in parallel.

## Hard rules

- **No LLM in extraction parsing, policy decisions, or request construction at execution time.** LLMs propose and interpret; deterministic code parses, validates, executes.
- **Black-box only.** No declarative seeding from source code, swagger handed over by devs, internal diagrams. Anything available enters through ingestion as a discovered artifact with provenance.
- **Human-in-the-loop for production targets.** Default to review mode. Auto mode only for staging.
- **Kill switch lives outside the agent process.** A signal the agent cannot suppress.
- **OPA checks happen twice** — at planner (efficiency) and at dispatcher (correctness).
- **Provenance and confidence on every node and edge.** No exceptions.

## Tech stack

| Concern | Choice |
|---------|--------|
| Primary language | Python |
| Burp integration | Kotlin/Java extension via Montoya API |
| Queue | Redis Streams |
| Object storage | S3 or MinIO |
| Schemas | Pydantic |
| Graph DB | Neo4j |
| Policy engine | OPA + Rego |
| LLM access | Anthropic API + local LiteLLM (org standard) |
| Tool protocol | MCP |
| Observability | OpenTelemetry |

## Conventions

- Use type hints everywhere.
- Pydantic models for all data crossing layer boundaries.
- One canonical representation per concept — multiple parsers, single output type.
- All LLM-generated graph contributions carry `source: "llm-<task>"` and a confidence score.
- Tests for policy decisions are unit tests on Rego, not integration tests.
- Bodies (request/response) live in object storage; graph nodes hold hashes and metadata.

## What to do at the start of a session

1. Read `ARCHITECTURE.md` and `ONTOLOGY.md`.
2. Check open questions in `ONTOLOGY.md` — three are still unresolved (Asset, TrustBoundary, Payload granularity).
3. Confirm which slice we're working on. If unclear, ask before generating code.

## What NOT to do

- Don't propose a Kafka deployment "for scalability" before Redis Streams is shown to be insufficient.
- Don't add LLM calls inside parsers, policy code, or the dispatcher.
- Don't have the LLM build HTTP requests as strings; it picks structured test cases, deterministic code constructs the request.
- Don't seed the graph with information from sources we wouldn't have in a real bug bounty engagement.
- Don't bypass the dispatcher's OPA check "because the planner already checked."
- Don't propose generic MCP tools like `execute_shell`. Tools are narrow: `send_http_request_within_scope`.

## Outstanding design work

The ontology is mid-design. Steps 2-6 not started:
- Relationship catalog
- Identity rules (path templating)
- Cross-cutting properties (provenance, confidence, time)
- Invariants
- Query patterns

Finish these before significant code investment in L3.

## Agent skills

### Issue tracker

Issues and PRDs live as GitHub issues in `ohlesl1e/doo`, managed via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Five canonical triage roles, each mapped to its same-named GitHub label. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
