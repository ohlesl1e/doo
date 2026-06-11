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

**Kill-switch lease (MVP mechanism):**

- Backend: a Redis key (`engagement:{id}:lease`) with a TTL, piggybacking on the same Redis used for L1 streams.
- Lifecycle: the loader writes `value = "active"` with TTL (default `60s`). A separate **engagement-keepalive** process — started explicitly by the tester after setup, never auto-spawned by the loader — refreshes the lease every `30s`. The dispatcher reads the lease before each HTTP send as part of its stateful-guard sequence (per ADR-0003): missing, expired, or `value != "active"` → fail closed, deny the request.
- Tester kills by SIGTERM-ing the keepalive (lease expires within TTL), `DEL`-ing the key (instant), or `SET ... "killed"` (instant with an explicit reason logged).
- Trust split: **the agent process has read-only access to the lease key.** Only the keepalive can refresh it; only the tester (or ops) can delete or override. Enforced by Redis ACLs in deployed setups; honour-system in single-Redis dev. This is the same sibling-process trust pattern used by the auth helper (ADR-0014).
- Convention: production-target engagements drop TTL to `30s` / refresh `15s` or tighter. Too tight causes false kills on Redis latency spikes; 60/30 is balanced for staging.
- The mechanism choice (Redis) is reversible — file lock, etcd, or a dedicated watchdog all satisfy the trust split. What is not reversible is the trust split itself: kill-switch authority is outside the agent process, period.

**Engagement setup:** the `Engagement`, its `Scope`, declared `Principal`s + their `AuthContext`s, and the kill-switch lease parameters are configured from a YAML `EngagementConfig` loaded by a Pydantic-typed loader. The loader is the only declarative seam allowed under the "black-box only" hard rule — see ADR-0012 for what may and may not appear in it.

## Layer contracts (L1 → L2 → L3)

The boundaries between layers are Pydantic models with `extra = "forbid"`. Schema evolution is by stop-the-world deploy; no embedded `schema_version` field. Long-term audit is satisfied by re-running current parsers against historic blobs in object storage, not by replaying historic in-flight messages.

### L1 → L2: `IngestionEnvelope`

L1 puts one envelope on the `ingest` Redis Stream per arrival. L1 validates the envelope only; blob content is opaque at L1. Malformed blobs flow through and surface as `ParseFailure` observations from L2.

| Field | Type | Notes |
|---|---|---|
| `event_id` | `UUID` (uuid7) | Unique per emission; distinct from `idempotency_key`. |
| `trace_id` | `str` (W3C 16-byte hex) | One trace per arrival (per HAR file / Logger++ stream connection / agent batch). Generated at intake. Propagated through L2 and L3 events. See ADR-0018. |
| `span_id` | `str` (W3C 8-byte hex) | Root span for the intake operation. L2/L3 spans derive children. |
| `engagement_id` | `EngagementId` | Set by intake; envelope-required. |
| `source` | `Literal[...]` (closed) | Closed enum forces the "is this a tester-side fact?" conversation per ADR-0012 when adding sources. |
| `source_version` | `str \| None` | Tool version when known; free-string. |
| `blob_ref` | `str` | Object-storage key. |
| `blob_format` | `str` | `"har-1.2"`, `"burp-streamed-v1"`, `"nuclei-jsonl-v3"`, ...; selects parser at L2. |
| `blob_sha256` | `str` | Integrity + idempotency input. |
| `idempotency_key` | `str` | `sha256(f"{source}\|{blob_sha256}\|{engagement_id}")`. Collapses re-uploads within an engagement; the same blob in a different engagement is a different logical observation set. |
| `received_at` | `datetime` | UTC. |
| `producer_id` | `str` | L1 component instance (e.g. `"har-upload-cli"`, `"logger++-shim-1"`). |
| `bytes_size` | `int` | Lets L2 choose stream vs. whole-load. |

Producer-facing intake APIs (HTTP multipart for HAR, NDJSON for streamed events, ES bulk protocol for the Logger++ shim) are per-source. The intake handler is the only place that touches the wire format; it constructs the canonical envelope.

### L2 → L3: `L2Event` (tagged union)

Discriminator: `kind`. Three variants:

- **`RequestObservation`** (`kind = "request_observation"`) — one observed HTTP exchange. Carries provenance (`source`, `source_id`, `ingested_at`), event time (`observed_at`), confidence (per ADR-0005), the exchange (`method`, `HostRef`, `concrete_path`, `query_string`), parsed input lists (`headers`, `cookies`, `query_params`, `body_params`), body references (`BlobRef`), the response side, and an `AuthContextCue` (hashes only — never raw tokens, per ADR-0015).
- **`ResponseArtifact`** (`kind = "response_artifact"`) — one discrete thing extracted from a response (identifier, URL, hostname, email, error message, fingerprint, internal path, secret-shaped). Back-references its `RequestObservation` via `request_observation_id`. For `kind ∈ {secret_shaped, token}`: carries `value_hash` + `value_length` + `value_preview` only; otherwise carries the raw substring (per ADR-0015 and ADR-0009).
- **`ParseFailure`** (`kind = "parse_failure"`) — first-class observation of a blob L2 couldn't parse. Carries `envelope_event_id` back-ref, error kind/message, and a location hint. Becomes a `ParseFailure` node in the graph so audit can see what didn't make it through.

`AuthContextCue` shape: `bearer_token_hash`, `cookie_session_hashes`, `api_key_headers`, `basic_auth_user_hash`, `bearer_claims` (JWT decoded without verification), `is_anonymous`. Raw tokens are read by the dispatcher from a separate secret store keyed by AuthContext id, populated from env-var references at setup per ADR-0012.

`HostRef` shape: `scheme` (`http` / `https`), `canonical_hostname` (lowercased, IDN ToASCII, trailing dot stripped), `port` (None when equal to scheme default; explicit when non-default), `is_ip_literal`. Matches the canonicalisation rule in CONTEXT.md.

`BlobRef` shape: `key`, `sha256`, `content_type`, `size_bytes`, `encoding`.

Parameter aggregation is **not** L2's job — `Parameter` nodes are an emergent aggregate L3 builds across many `RequestObservation`s sharing the same `(endpoint_id, name, location)`.

### L3 commit interface

```
async def commit(event: L2Event) -> CommitResult
async def commit_batch(events: list[L2Event]) -> list[CommitResult]
```

`CommitResult` carries `commit_id`, `accepted` (false on idempotency hit), the lists of `nodes_created`/`nodes_updated`/`edges_created`/`edges_removed`, a `retemplating_triggered` flag, and the `events_emitted` refs.

Idempotency is keyed semantically on `(event_kind, source, source_id, engagement_id)` per ADR-0016 — distinct from L1's blob-hash key and from L2's emission `event_id`. Re-running L2 against historic blobs (parser bug-fix replay) is a no-op against existing commits.

Entity resolution at commit time: `Host` (canonicalisation-keyed), `AuthContext` (auth_hash-keyed, reconciled to declared Principal per ADR-0010), `Endpoint` (revisable inference per ADR-0004; may trigger re-templating), `Parameter` (aggregated by `(endpoint_id, name, location)`), `ObservedValue` (promoted per ADR-0009).

Read API is separate from the write API; consumers query Neo4j directly.

### L3 → consumers: `l3-events` stream

L3 emits **low-level structural events** on a separate Redis Stream `l3-events`, with consumer groups per subscriber (`planner`, `coverage`, `audit`). Consumers compose business meaning by filtering on `node_type` / `edge_type`.

Event kinds (discriminator `kind`):

- `node_created` — `node_type`, `node_id`, `properties` snapshot.
- `node_updated` — `node_type`, `node_id`, `changed_properties` (name → `{old, new}`).
- `edge_created` — `edge_type`, `from_node`, `to_node`, `properties`.
- `edge_removed` — `edge_type`, `from_node`, `to_node`, `reason ∈ {retemplating, reconciliation, retraction}`.
- `reconciliation` — multi-step atomic merge (per ADR-0010 for Principals, the same mechanic for Tenants and Assets per ADR-0008 / ADR-0011): `survivor_id`, `retracted_id`, `reason`. Emitted as one event because consumers need it atomically.

All events carry `commit_id` for lineage; the chain is `l3-event → commit → L2 event → L1 envelope → raw blob in object storage`. Full provenance traversal.

Every `L2Event` and every `l3-events` payload also carries `trace_id` (W3C 16-byte hex) and `span_id` (W3C 8-byte hex). The intake-side `trace_id` propagates unchanged through L2 and L3; each layer derives a child `span_id` for its phase. Structured-log lines across L1/L2/L3 include the same IDs. The OpenTelemetry SDK is not enabled in slice 1; the conventions are in place so that turning it on later is a configuration change, not a data migration. See ADR-0018.

### Engagement scoping

Every node mutated by L3 carries an `engagement_id` matching the inbound `L2Event.payload.engagement_id`. L3 enforces this at commit time: scoped nodes must not be created with a different engagement_id, and edges between scoped nodes must agree on engagement_id. Edges from a scoped node to a shared structural node (`Engagement`, `Scope`) are the only cross-class connections allowed. See ADR-0017 for the full model, including Neo4j uniqueness constraints and query conventions.

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

## Build order (the slices)

Build vertically, not horizontally — one thin slice through all relevant layers before broadening. **Ontology (L3) is not a separate slice:** the bulk of it was built in slice 1, and each later slice extends it only when a consumer needs a new inference (e.g. `TrustBoundary` lands in slice 3 because the planner needs it). Do not scaffold a layer ahead of its consumer.

This is the canonical definition of what lands in each slice. The coverage queries are labelled C1–C5 (see the canonical query set under "L3 → consumers" / `ONTOLOGY.md` Step 6).

### Slice 1 — Ingestion + graph ✅ shipped

Burp/HAR → L1 intake → L2 extraction → L3 graph, queryable on its own. Builds the bulk of the ontology: `Host` / `Endpoint` / `Parameter` / `RequestObservation` / `Principal` / `AuthContext` / `ObservedValue` / `Tenant`, entity resolution, endpoint re-templating, identity reconciliation, plus the engagement loader and the kill-switch lease. Decisions: ADRs 0001–0032 (G1, G2 closed; G3 write-path timing settled by ADR-0022; G4 blob layout settled by the `blobs.py` key scheme).

### Slice 2 — Coverage analysis ✅ shipped

A **pull / ephemeral** deterministic query library (`doo coverage`) + CLI, also consumed by the slice-3 planner as a shared library (ADR-0034). Writes nothing back — gaps derive at query time. ~60% of the value, ~10% of the risk; **no LLM.** Queries shipped:

- **C1** — in-scope `Endpoint`s never hit (any `HIT`; vacuous on purely-passive data until a discovery source exists).
- **C2** — reached as `Principal` A but not B (2xx-"reached", deliberately asymmetric from C1; ADR-0033).
- **C2b** — role-differentiated 200s: ≥2 principals reach 2xx with differing `response_body_sha256`/`response_size_bytes` (BOLA/IDOR hotspots).
- **C3** — cross-endpoint leak-to-input pivots.

Decisions: ADRs 0033 (authz-coverage semantics), 0034 (shared library), 0035 (scope patterns are glob, not regex).

### Slice 3 — LLM-assisted hypothesis generation ✅ shipped

The first slice with an LLM. **Planner** (`doo planner propose`): pluggable deterministic candidate generators select targets — `c1` (dead endpoints, no LLM), `c2`/`c2b`/`c3`/`c4`, capability + tenant `TrustBoundary`s, and `sink` (sink-shaped params) — and for gaps that need reasoning the LLM proposes a structured `PlannerProposal` (enums + pack-local handle references, **never request strings**). A deterministic **Validator** resolves the target, enforces scope via the shared `is_in_scope` helper (ADR-0038; deny-all Rego left to the slice-4 dispatcher), resolves the `payload_spec` to a real `payload_hash`, and commits a content-addressed `TestCase` (ADR-0007) at `review_status = proposed`. `doo planner review` is the deterministically-prioritised human review queue with a provenanced audit ledger (ADR-0040). **Nothing is dispatched** — `approved` = "cleared for consideration," not authorization. Pulled in the remaining ontology piece — **`TrustBoundary` inference** (capability + tenant) — and the **C4** coverage query. Shipped across tracers S2a/S2b/S3/S4/S5/S6 per ADRs 0036–0041: gap-driven generators (0036); the typed context-pack→`PlannerProposal` contract, three payload resolvers `none`/`observed_value`/`configured`, and replayability persistence (0037); planner-side `is_in_scope` (0038); capability+tenant boundary inference with boundary tests as authz replays of evidence (0039); the `review_status` lifecycle + ledger (0040); structured `hold` + deterministically-detected `replay_hazards`, neither in `key_hash` (0041). The LLM is config-not-code (litellm; default Claude, per-engagement provider override).

### Slice 4 — Bounded agent execution

**Executor** (narrow MCP tools, dispatcher-side OPA + stateful guards, kill-switch) → **Interpreter** (LLM judges responses, proposes follow-ups). Adds `EXECUTED_AS` edges + `dispatch_status` (ADR-0013), at which point **C5** (`TrustBoundary`s with no *executed* `TestCase`) and executed-vs-proposed coverage become meaningful. Reporting / disclosure templates also land here. Only after 1–3 are solid.

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
