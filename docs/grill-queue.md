# MVP Grill Queue

Design decisions still open before the MVP slice (L1 ingestion + L3 graph + L2 coverage, per `ARCHITECTURE.md` build order) can be implemented confidently.

Items are split into three buckets:

1. **Grill** — real design ambiguity. Worth a `/grill-with-docs` pass against the current `CONTEXT.md` + `ONTOLOGY.md` + ADRs before code lands. Each will likely produce an ADR.
2. **Pick a default and move** — has a conventional answer that's good enough for MVP. Worth writing down briefly but not grilling.
3. **Defer** — punt until after the first slice lands; revisit when the implementation forces the question.

## Worth grilling

### G1. Engagement / Scope / declared-Principal setup format ✅ resolved

Closed 2026-05-28. Outputs: **ADR-0012** (setup boundary is tester-side facts only; YAML + Pydantic loader), **ADR-0013** (`dispatch_status` on `EXECUTED_AS`; `auth_invalid` is untested for coverage), **ADR-0014** (auth helper is a sibling process; agent never mints credentials). Kill-switch lease mechanism documented in `ARCHITECTURE.md` L5. `CONTEXT.md` updated with `dispatch_status` term and `Principal.known_signals` / `tier` properties. Auth helper YAML field (`refresh:`) deferred until slice 3 per ADR-0014.

### G2. Layer-boundary Pydantic contracts ✅ resolved

Closed 2026-05-30. Outputs: **ADR-0015** (L2 is the secrets-hashing boundary; raw tokens never enter L3), **ADR-0016** (L3 commit idempotency is keyed semantically on `(event_kind, source, source_id, engagement_id)`). `ARCHITECTURE.md` gained a "Layer contracts (L1 → L2 → L3)" section sketching the `IngestionEnvelope`, the `L2Event` tagged union (`RequestObservation` / `ResponseArtifact` / `ParseFailure`), the L3 commit interface, and the `l3-events` low-level structural events stream. `CONTEXT.md` gained the `ParseFailure` term. Pydantic models are described as types-and-fields in `ARCHITECTURE.md`; concrete `.py` definitions land with slice-1 code.

### G3. Entity-resolution timing and the write path

**Why grill.** Sync-on-write (latency on every ingest, strong consistency for queries) vs. async batch (cheap ingest, eventual consistency, harder reasoning). Re-templating triggers — every N observations, every N minutes, on-demand from query failure? Decides the shape of the writer service and where transactions live.

Defaults can work but the trade-offs are real and should be deliberate.

**Order: grill during early L1+L2 prototyping** — more concrete than abstract, benefits from a working prototype to test against.

### G4. Body and secret blob layout

**Why grill.** Bodies go to object storage with hashes in the graph (already decided). But the *access pattern* isn't:
- Key format — engagement/source/hash, or content-addressed only?
- Retention rules and cleanup.
- Access control for high-entropy `kind = secret` values (per ADR-0009 the full value should *only* live in the originating observation in object storage).
- How ADR-0009's secrets-handling composes with body-on-disk: a JWT in a body is a secret too.

Decide once before any real bytes flow.

**Order: grill alongside G3.**

## Pick a default and move

Worth writing down (in `ARCHITECTURE.md` or a new `DECISIONS.md`), but not worth a grill.

| Decision | Default | Notes |
|---|---|---|
| Worker framework | Plain `asyncio` for MVP | Promote to Dramatiq when throughput demands |
| Neo4j local dev | Single-node Docker container | `neo4j:5-community` |
| Object storage local dev | MinIO container | Bucket per Engagement |
| Repo layout | `src/{ingestion,extraction,ontology,coverage,policy,...}/` | Mirrors the five layers |
| Confidence decay function | `confidence * exp(-age_days / half_life)`, default half-life 30d | Configurable per `source` |
| Test strategy | Pytest unit + Neo4j testcontainer for integration + HAR fixture corpus + Rego unit tests | Per CLAUDE.md "tests for policy decisions are unit tests on Rego" |
| OPA deployment | Sidecar process; bundle generated from `Scope` nodes | Per ADR-0003 |
| Burp extension language | Kotlin | More pleasant Montoya API surface (per `ARCHITECTURE.md` open question) |

## Defer

Until after slice 1+2 lands; revisit when the implementation forces the question.

- **Burp extension.** HAR-first MVP — drop a HAR file into ingestion, see it land in the graph. No Java/Kotlin yet. For continuous capture later, **Logger++** (existing Burp extension) is the planned integration point: it ships auto CSV export and a live Elasticsearch-stream output. The integration is a small HTTP shim that speaks the ES bulk-index protocol and pipes the indexed documents into L1 ingestion as raw observations — Logger++ thinks it's writing to ES, we get streaming Burp traffic with zero custom Burp code. A custom Montoya extension is only justified if Logger++'s exported document shape lacks something we need; revisit then.
- **OpenTelemetry SDK + collector + exporters.** Refined to "OTel-ready, OTel-not-yet" per ADR-0018: `trace_id` / `span_id` ride in `IngestionEnvelope`, `L2Event`, and `l3-events` from slice 1; structured logs include the same IDs; the SDK and exporters are deferred until slice 2-3 when distributed tracing pays off.
- **Reporting / disclosure templates.** L5 territory (slice 4).
- **Bounded agent execution.** L5 territory (slice 4).
- **TestTemplate** (cross-Engagement test catalog) — deferred per ADR-0007.
- **PayloadClass as a node** (currently a tag) — promote only if class-to-class relationships emerge.
- **Audit log store** beyond Neo4j edges — promote when query/audit needs outgrow what provenance + `DERIVED_FROM` can answer.
- **Cross-engagement inference priors.** Per ADR-0017 a fresh `Engagement` against the same target starts cold (re-templating, re-inferring `ParameterSemantic`s, etc.). When this re-discovery cost becomes painful, add explicit opt-in prior loading in the engagement YAML — e.g. `prior_engagements: [{id: acme-2026-q2, use_for: [endpoint_templates, parameter_semantics, tenant_inferences], confidence_decay: 0.5}]`. Loader does a one-time inference-import with `source = "prior_engagement:<id>"` and decayed confidence so fresh evidence in the new engagement can override. Explicit opt-in keeps the Q1-of-G1 setup-boundary discipline intact (ADR-0012): the tester is declaring their own prior work, which is tester-side knowledge.
- **Incremental re-templating (continuous-mode performance).** ADR-0022 deferred endpoint re-templating to a per-drain `flush`, which makes the offline-HAR (`--once`) workload O(N). A debounced `flush` in *continuous* mode still re-templates the whole growing cohort each tick (→ O(N²/K)). Two graded fixes, both behind the `flush` seam so callers don't change: (1) a within-`flush` fast path that skips the `template_paths` re-run when a cohort gained no new *distinct* concrete path and just attaches the new observations' `HIT`s; (2) full incremental templating — maintain the trie and recompute only the affected sub-tree per new distinct path, writing only diffs (~O(N log N)). Revisit when Logger++ streaming capture lands or cohorts get large enough that continuous-mode flush latency bites.

## Suggested grilling order

1. ~~**G1** — Engagement / Scope / declared-Principal setup~~ ✅ closed 2026-05-28.
2. ~~**G2** — Layer-boundary Pydantic contracts~~ ✅ closed 2026-05-30.
3. **Start L1 + L3 code** against G1 + G2 outputs.
4. **G3** — write-path timing (grill against the prototype, not abstractly).
5. **G4** — blob layout (grill alongside G3).

After all four resolve, the MVP slice (ingest a HAR, see it in the graph, run the coverage queries C1–C5) should be buildable without further design grilling — implementation gaps will surface their own questions, but they're code questions, not design ones.
