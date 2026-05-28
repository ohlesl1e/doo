# Architecture

A security testing copilot for black-box web application testing. Ingests passive testing data (Burp traffic, HAR files, recon output), builds a knowledge graph of the target, identifies coverage gaps, and dispatches bounded test agents under human supervision and policy constraints.

## Design principles

1. **The LLM is at the end of the pipeline, not the middle.** Layers 1-3 work correctly without any LLM involvement. The LLM proposes and interprets; deterministic code parses, stores, validates, and executes.
2. **Black-box only.** Everything in the system is an observation or an inference from observations. No declarative seeding from source code, swagger specs handed over by the dev team, or internal architecture diagrams. Even when those exist, they enter through the ingestion pipeline as discovered artifacts with provenance saying so. This keeps behavior consistent between internal product testing and bug bounty work.
3. **Human-in-the-loop by default.** The system proposes; humans approve dispatch (at least for production targets). The kill switch lives outside the agent process.
4. **Policy enforcement is defense-in-depth.** ROE is checked at the planner (to avoid wasted work) AND at the dispatcher (to catch hallucinated or misconfigured tests).
5. **Provenance and confidence are first-class.** Every node and edge knows where it came from and how certain it is. The planner uses this to prioritize.

## Five-layer architecture

```
┌─────────────────────────────────────────────────────────────┐
│ L1: Ingestion                                               │
│   Burp extension, HAR uploads, recon tool output → queue    │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│ L2: Extraction                                              │
│   Parse → normalize → enrich → entity extraction            │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│ L3: Ontology                                                │
│   Entity resolution, graph construction, invariant checks   │
│   (Neo4j)                                                   │
└────────────────────────────┬────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
┌───────▼────────┐  ┌────────▼─────────┐  ┌──────▼──────────┐
│ Coverage       │  │ L4: ROE          │  │ L5: Action      │
│ analyzer       │  │ Policy engine    │  │ Planner →       │
│ (deterministic)│  │ (OPA)            │  │ Validator →     │
└────────────────┘  └────────┬─────────┘  │ Executor →      │
                             │            │ Interpreter     │
                             └───────────►│ (MCP tools)     │
                                          └─────────────────┘
```

### L1: Ingestion

**Purpose:** intake testing data for processing. Must support multiple sources and be extensible.

**Sources (initial):**
- Burp Suite proxy traffic (via custom extension using the Montoya API)
- HAR file uploads
- Recon tool output (nuclei JSON, ffuf, subfinder)
- Authenticated session data

**Transport decision: defer Kafka.** For a single-team tool with a small number of producers, Kafka is operational overhead without payoff. Start with one of:

- **Redis Streams** — pub/sub and replay with ~1% of Kafka's operational footprint, single container.
- **Queue + object store** — Burp/HAR blobs to S3/MinIO, message references on Redis or SQS, workers consume.
- **Postgres `LISTEN/NOTIFY`** — if throughput is genuinely modest, this removes infrastructure entirely.

Migrate to Kafka later if needed. The L1↔L2 interface is "event with payload reference" — keep the transport swappable.

**Burp integration:** the cleanest path is a Burp extension (Java/Kotlin via the Montoya API) that streams proxy traffic to an ingestion endpoint. Burp project file exports work too but are batch-oriented and lose real-time context.

### L2: Extraction

**Purpose:** transform raw input into canonical entities ready for the ontology layer.

**Sub-functions:**
1. **Parsing** — source-specific parsers (Burp items, HAR entries, nuclei findings) → structured request/response objects. Deterministic.
2. **Normalization** — different sources describing the same conceptual objects collapse to one canonical representation. Deterministic.
3. **Enrichment** — tech stack fingerprinting, auth mechanism detection, parameter type inference (UUID? sequential? JWT?), reflected-parameter detection. Mostly deterministic, with an LLM-assisted layer for fuzzy cases.
4. **Entity extraction** — pull out what will become graph nodes: endpoints, parameters, auth contexts, observed identifiers, cross-references.

**Tech:** plain Python. Pydantic for canonical schemas. Celery or Dramatiq for distributed work if it gets heavy. **No framework** — extraction logic changes constantly as sources are added; frameworks add friction.

**LLM use here is narrow and batched.** Examples: inferring parameter semantics ("is `tid` a tenant ID based on usage patterns?"), clustering similar endpoints. Core parsing stays deterministic — never let an LLM decide what your data is.

### L3: Ontology

**Purpose:** the world model. Entity resolution, graph construction, invariant enforcement.

**Tech: Neo4j.** Cypher is genuinely good for the queries we'll write, the visual exploration in Neo4j Browser is invaluable for debugging, and the ecosystem is mature. Alternatives considered:

- NetworkX: prototype-only, falls over past ~100k nodes.
- Postgres + recursive CTEs: works but graph traversal queries are painful.
- Memgraph: Cypher-compatible and faster, but smaller ecosystem.

**Storage discipline:** large blobs (full request/response bodies) live in object storage (S3/MinIO). The graph stores hashes, metadata, and references. Otherwise graph queries get slow and storage costs balloon.

**Schema:** see `ONTOLOGY.md`. The ontology is the contract between the deterministic pipeline and the LLM — its vocabulary defines what the planner can reason about.

**LLM use here is targeted:** entity resolution (is this the same endpoint as that one?), relationship inference (does this response field correspond to that endpoint's input?). All LLM-generated nodes/edges carry provenance marking them as inferred and confidence scores so they can be filtered or retracted.

### L4: Rules of Engagement

**Purpose:** encode and enforce per-engagement constraints. Different rules for internal staging vs. bug bounty production targets.

**Tech: Open Policy Agent (OPA) with Rego policies.**

**Policy categories:**
- **Scope policies** — per-program allowed hosts, paths, methods, prohibited payload classes, required headers (some BB programs require identifying headers). (Rate limits are *not* here — they are stateful, see below.)
- **Environment policies** — production vs. staging defaults, prod being maximally conservative.
- **Payload class policies** — independent of target: no destructive SQL, no payloads that could trigger emails/SMS to real addresses, no fork-bomb-style command injection probes.
- **Time policies** — some programs restrict testing hours.

**Two kinds of check (see ADR-0003):**

- **Policy decisions — pure OPA.** OPA/Rego evaluates a proposed request as a pure function of `input` (the proposed test, including its `PayloadClass` and the target's confidence) and `data` (static scope/program policy). No graph access — that is what keeps decisions reproducible and unit-testable.
- **Stateful guards — deterministic dispatcher code.** Live aggregates that can't be a pure function of one request — rate limits, per-engagement test budgets, duplicate-test dedup, the kill-switch lease — are enforced in the dispatcher against the graph/counter store, never in Rego.

Rule of thumb: anything the planner can snapshot into the proposal goes in OPA `input`; anything that's a live aggregate is a dispatcher guard.

**Enforcement points (defense in depth):**
- **Planner queries OPA** to avoid proposing tests that will be denied (efficiency).
- **Dispatcher queries OPA, then runs its stateful guards**, immediately before each request (correctness). If the planner is buggy or the LLM hallucinates a target, the dispatcher still blocks.

**No LLM involvement in this layer.** Policy decisions must be deterministic, auditable, and unit-testable: "given this request to this scope, the policy returns DENY."

### L5: Action

**Purpose:** propose, validate, execute, and interpret tests.

**Internal structure** (splitting the "LLM with MCP" framing into pieces):

```
Planner (LLM)     →    Validator (deterministic)    →    Executor (MCP tools)    →    Interpreter (LLM)
"propose tests"        "check OPA, graph,                "send within scope"          "interpret response,
                        duplicates"                                                    update graph"
```

- **Planner (LLM-driven):** given graph state, coverage gaps, and ROE constraints, propose structured test cases: `{test_class, target_node_id, parameters, justification}`. Output is structured — never free-form actions.
- **Validator (deterministic):** check each proposal against OPA, graph consistency, duplicate detection. Discard or modify.
- **Executor (deterministic, narrow MCP tools):** runs tests via tools like `send_http_request_within_scope`, not `execute_curl`. MCP server enforces ROE on every call.
- **Interpreter (LLM-driven):** judges responses, classifies anomalies, proposes follow-up tests or graph updates. Output feeds back to extraction.

**Why this split:** LLMs are good at proposing and interpreting, mediocre at executing reliably. Deterministic code on the execution path means a bad LLM output can't directly produce a bad request.

**Safety properties:**
- **Modes:** auto / review / dry-run. Default to review for production targets.
- **Kill switch outside the agent process** — a signal the agent can't suppress. Separate process holding a lease, feature flag the dispatcher checks, or similar. The agent must not be in charge of being able to stop itself.

## Cross-cutting: observability and audit

Not a sixth layer — a cross-cutting concern. Every layer emits structured events to a central log. OpenTelemetry is the obvious tool.

**Required capabilities:**
- Complete audit log of every request sent, with which policy decision allowed it.
- Replay — given an audit log, reconstruct what the agent saw and decided.
- Metrics on planner output: proposals/hour, accept rate, finding rate.

This matters disproportionately for bug bounty work: when something goes wrong, you need to explain to the program exactly what the tool did and why.

## Where LLMs help, ranked by leverage

1. **Planning (L5)** — proposing test cases from graph + coverage gaps. Highest leverage.
2. **Response interpretation (L5)** — judging anomalies, classifying findings.
3. **Entity resolution / enrichment (L2-L3)** — clustering similar endpoints, inferring parameter semantics. Narrow, batched.
4. **Triage / reporting (post-L5)** — summarizing findings for the bug tracker or disclosure report.

**Do NOT use LLMs for:** parsing inputs (L1/L2), policy decisions (L4), or directly constructing the requests sent (L5 execution).

## Build order

Build vertically, not horizontally. One thin slice through all relevant layers before broadening.

1. **Ingestion + graph** — Burp/HAR ingestion, graph construction, queryable. Useful on its own.
2. **Coverage analysis** — pure deterministic queries: "endpoints hit as admin but not as user," "parameters in responses but never fuzzed," "auth state transitions not exercised." Probably 60% of the value with 10% of the risk.
3. **LLM-assisted hypothesis generation** — feed graph subsets to an LLM, propose test ideas, human approves before dispatch.
4. **Bounded agent execution** — only after 1-3 are solid.

## Tech stack summary

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Language | Python (primary) | Ecosystem for security tooling and LLM integration |
| Burp integration | Java/Kotlin extension (Montoya API) | Native API for streaming proxy traffic |
| Queue / transport | Redis Streams (start) | Kafka-like semantics, minimal ops |
| Object storage | S3 or MinIO | Request/response bodies, large blobs |
| Canonical schemas | Pydantic | Validation, serialization |
| Worker framework | Celery or Dramatiq (if needed) | Distributed extraction work |
| Graph database | Neo4j | Cypher, ecosystem, visual exploration |
| Policy engine | OPA + Rego | Policy as code, version controlled |
| LLM access | Anthropic API + local LiteLLM | Already standard at the org |
| Tool protocol | MCP | Standard, supports narrow tool definitions |
| Observability | OpenTelemetry | Standard, cross-language |

## Open questions

- Burp extension language: Java vs. Kotlin (Montoya supports both; Kotlin is more pleasant)
- Worker framework: Celery vs. Dramatiq vs. just async Python (depends on throughput)
- Local LLM vs. Anthropic API split: which tasks go where based on sensitivity of the data being processed
- Whether to add a sixth layer for "reporting" or keep it as a thin consumer of the graph
