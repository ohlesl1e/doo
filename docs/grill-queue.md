# Grill Queue

Tracker for design decisions that want a `/grill-with-docs` pass before code lands, plus the running list of deliberate deferrals.

**The slices themselves are defined in `ARCHITECTURE.md` → "Build order (the slices)"** — that is the canonical roadmap. Current status: **slice 1 (ingestion + graph) and slice 2 (coverage C1/C2/C2b/C3) are shipped**; **slice 3 (LLM-assisted hypothesis generation / the Planner) is next**. This file no longer gates an "MVP slice" — it tracks what is still worth grilling and what is parked.

Items are split into three buckets:

1. **Grill** — real design ambiguity. Worth a `/grill-with-docs` pass against the current `CONTEXT.md` + `ONTOLOGY.md` + ADRs before code lands. Each will likely produce an ADR.
2. **Pick a default and move** — has a conventional answer that's good enough for MVP. Worth writing down briefly but not grilling.
3. **Defer** — punt until after the first slice lands; revisit when the implementation forces the question.

## Worth grilling

### G1. Engagement / Scope / declared-Principal setup format ✅ resolved

Closed 2026-05-28. Outputs: **ADR-0012** (setup boundary is tester-side facts only; YAML + Pydantic loader), **ADR-0013** (`dispatch_status` on `EXECUTED_AS`; `auth_invalid` is untested for coverage), **ADR-0014** (auth helper is a sibling process; agent never mints credentials). Kill-switch lease mechanism documented in `ARCHITECTURE.md` L5. `CONTEXT.md` updated with `dispatch_status` term and `Principal.known_signals` / `tier` properties. Auth helper YAML field (`refresh:`) deferred until slice 3 per ADR-0014.

### G2. Layer-boundary Pydantic contracts ✅ resolved

Closed 2026-05-30. Outputs: **ADR-0015** (L2 is the secrets-hashing boundary; raw tokens never enter L3), **ADR-0016** (L3 commit idempotency is keyed semantically on `(event_kind, source, source_id, engagement_id)`). `ARCHITECTURE.md` gained a "Layer contracts (L1 → L2 → L3)" section sketching the `IngestionEnvelope`, the `L2Event` tagged union (`RequestObservation` / `ResponseArtifact` / `ParseFailure`), the L3 commit interface, and the `l3-events` low-level structural events stream. `CONTEXT.md` gained the `ParseFailure` term. Pydantic models are described as types-and-fields in `ARCHITECTURE.md`; concrete `.py` definitions land with slice-1 code.

### G3. Entity-resolution timing and the write path ✅ resolved (in slice 1)

Resolved by the slice-1 implementation, never needed a formal grill. The write path is **async**: L1 → Redis Streams → L2/L3 workers, with entity resolution at commit and endpoint re-templating deferred to a per-drain `flush` at the settle point (**ADR-0022**). No mid-drain reader exists, so eventual-within-a-drain consistency is acceptable. Continuous-mode `flush` performance is a tracked deferral (see Defer: incremental re-templating).

### G4. Body and secret blob layout ✅ resolved (in slice 1)

Resolved by the slice-1 `blobs.py` implementation. Key layout is engagement-scoped + content-addressed: `engagement/{id}/source/{kind}/{sha256}.{ext}` for HAR blobs and a parallel body-key scheme. Secrets never store the full value — `kind ∈ {secret, token, opaque_token}` carry `value_hash` + length + preview only (**ADR-0009 / 0015 / 0024**), so the "JWT in a body is a secret too" case is handled at the L2 extraction boundary. Retention/cleanup is left to object-store lifecycle policy (not yet needed).

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

## Slice 2 scope (coverage analysis)

Grilled 2026-06-06. The coverage analyzer is **pull / ephemeral**: a library of
deterministic Cypher queries plus a CLI that reads the graph at a settle point,
returns Pydantic result models, and writes nothing back. Gaps are derived at
query time (same discipline as `is_in_scope`, ADR-0020, and confidence decay,
ADR-0005) — never materialised as `CoverageGap` nodes. The `l3-events`
`coverage` consumer group stays reserved for a future live-coverage view
(Logger++ streaming), not slice 2.

**In scope: C1, C2, C2b, C3.** Buildable against today's graph; the "60% of
value" set (dead endpoints, auth-presence-differential, auth-content-differential,
leak-to-input pivots).

C2 success semantics are settled in **ADR-0033**: "reached as P" requires a 2xx
observation (asymmetric from C1, which counts any `HIT`); C2 surfaces
present-as-A-but-not-B (B's 401/403 count as *not reached* so bypass candidates
are not suppressed); **C2b** is the content-differential query (≥2 principals
reach 2xx but `response_body_sha256`/`response_size_bytes` differ) — the handle
on role-differentiated 200s. Coverage surfaces per-principal evidence
`(status, size, body_sha256)`, it does not adjudicate soft-200.

Slice-2 prerequisites (per ADR-0033): promote `response_body_sha256` to a
top-level node property; confirm `response_size_bytes` is queryable.

**Deferred: C4, C5** (see Defer section). Their substrate doesn't exist yet:
C4 needs inferred capability-tier `TrustBoundary` nodes (an L3 *write-path*
feature, not a coverage query); C5 additionally needs `TestCase` nodes, which
first exist in slice 4.

## Defer

Until after slice 1+2 lands; revisit when the implementation forces the question.

- **C4 (auth-state transitions never exercised) → slice 3.** Needs capability-tier
  `TrustBoundary` nodes, which nothing infers yet. That inference (drawing
  boundaries between an actor's `AuthContext`s from passive evidence) is an L3
  ontology write-path feature the **slice-3 planner pulls in** (it wants boundaries
  as first-class, test-targetable nodes). Once they exist, C4 falls out as a
  passive coverage query — no active testing required. Build it *with* the planner,
  not speculatively ahead, so the boundary granularity matches a real consumer.
- **C5 (`TrustBoundary`s with no *executed* `TestCase`) → slice 4.** Needs
  `TrustBoundary` nodes *and* `EXECUTED_AS` edges to mean "untested boundary".
  `TestCase` nodes are created (proposed) in slice 3, but they only carry
  `EXECUTED_AS` once the dispatcher runs (slice 4) — so "no executed test" is the
  meaningful reading and it lands in slice 4. ("No *proposed* test" is a weaker
  slice-3 variant; pick the semantics when grilling slice 4.)
- **Passive login-redirect / 3xx classification (ADR-0033).** Slice-2 C2/C2b
  treat success as 2xx only; 3xx is not-reached. A passive login-redirect
  classifier (the dispatch-side detector from ADR-0013, reused for passive
  observations) would let redirect-following count as reached. Conservative
  2xx-only only reduces leads, so safe to defer.
- **Principal/tenant-aware C3 (leak-to-input).** Slice-2 C3 is principal-agnostic:
  cross-*endpoint* pivot (value in endpoint X's response → input to a different
  in-scope endpoint Y), ranked by shape specificity then confidence; target
  endpoint must be `is_in_scope`, source endpoint need not be (ADR-0020);
  temporality ignored. The high-value refinement — value leaked *to* Principal A
  appears as input *under* Principal B, or tenant 42's id used by tenant 43 (the
  IDOR/BOLA jackpot) — layers principal-awareness on C3 and overlaps C7; defer.
- **Per-engagement `success_match`/`failure_match` (ADR-0033).** Soft-200
  disambiguation for apps that always 200 with a body-level success flag —
  tester-declared string/regex (ADR-0012-legal), the sqlmap `--string` pattern.
  Defer until a real always-200 target forces it.

- **Burp extension.** HAR-first MVP — drop a HAR file into ingestion, see it land in the graph. No Java/Kotlin yet. For continuous capture later, **Logger++** (existing Burp extension) is the planned integration point: it ships auto CSV export and a live Elasticsearch-stream output. The integration is a small HTTP shim that speaks the ES bulk-index protocol and pipes the indexed documents into L1 ingestion as raw observations — Logger++ thinks it's writing to ES, we get streaming Burp traffic with zero custom Burp code. A custom Montoya extension is only justified if Logger++'s exported document shape lacks something we need; revisit then.
- **OpenTelemetry SDK + collector + exporters.** Refined to "OTel-ready, OTel-not-yet" per ADR-0018: `trace_id` / `span_id` ride in `IngestionEnvelope`, `L2Event`, and `l3-events` from slice 1; structured logs include the same IDs; the SDK and exporters are deferred until slice 2-3 when distributed tracing pays off.
- **Reporting / disclosure templates.** L5 territory (slice 4).
- **Bounded agent execution.** L5 territory (slice 4).
- **TestTemplate** (cross-Engagement test catalog) — deferred per ADR-0007.
- **PayloadClass as a node** (currently a tag) — promote only if class-to-class relationships emerge.
- **Audit log store** beyond Neo4j edges — promote when query/audit needs outgrow what provenance + `DERIVED_FROM` can answer.
- **Cross-engagement inference priors.** Per ADR-0017 a fresh `Engagement` against the same target starts cold (re-templating, re-inferring `ParameterSemantic`s, etc.). When this re-discovery cost becomes painful, add explicit opt-in prior loading in the engagement YAML — e.g. `prior_engagements: [{id: acme-2026-q2, use_for: [endpoint_templates, parameter_semantics, tenant_inferences], confidence_decay: 0.5}]`. Loader does a one-time inference-import with `source = "prior_engagement:<id>"` and decayed confidence so fresh evidence in the new engagement can override. Explicit opt-in keeps the Q1-of-G1 setup-boundary discipline intact (ADR-0012): the tester is declaring their own prior work, which is tester-side knowledge.
- **Incremental re-templating (continuous-mode performance).** ADR-0022 deferred endpoint re-templating to a per-drain `flush`, which makes the offline-HAR (`--once`) workload O(N). A debounced `flush` in *continuous* mode still re-templates the whole growing cohort each tick (→ O(N²/K)). Two graded fixes, both behind the `flush` seam so callers don't change: (1) a within-`flush` fast path that skips the `template_paths` re-run when a cohort gained no new *distinct* concrete path and just attaches the new observations' `HIT`s; (2) full incremental templating — maintain the trie and recompute only the affected sub-tree per new distinct path, writing only diffs (~O(N log N)). Revisit when Logger++ streaming capture lands or cohorts get large enough that continuous-mode flush latency bites.

## Grilling order / history

1. ~~**G1** — Engagement / Scope / declared-Principal setup~~ ✅ closed 2026-05-28 (ADR-0012/0013/0014).
2. ~~**G2** — Layer-boundary Pydantic contracts~~ ✅ closed 2026-05-30 (ADR-0015/0016).
3. ~~**Slice 1** — L1 ingestion + L3 graph~~ ✅ shipped (ADRs 0001–0032).
4. ~~**G3 / G4** — write-path timing & blob layout~~ ✅ resolved by the slice-1 implementation (ADR-0022; `blobs.py` key layout) — never needed a formal grill.
5. ~~**Slice 2** — coverage C1/C2/C2b/C3~~ ✅ shipped 2026-06-08 (ADR-0033/0034/0035).
6. **Next — Slice 3: LLM-assisted hypothesis generation (the Planner).** Likely grill targets:
   - graph → LLM **context selection & windowing** (coverage output is the natural input);
   - the structured **proposal schema** (`{test_class, target_node_id, parameters, justification}`) + the deterministic Validator;
   - **planner-side OPA** against the still-skeletal Rego (write the real host/path/payload rules, or stub deliberately);
   - **`TrustBoundary` inference** granularity (unblocks **C4**);
   - **`TestCase`** node creation & dedup (ADR-0007);
   - **local LiteLLM vs Anthropic API** split by data sensitivity (standing `ARCHITECTURE.md` open question);
   - where slice 3 **stops** (propose + validate + human-review, with dispatch deferred to slice 4).

Slice 4 (bounded execution) then brings `EXECUTED_AS` / `dispatch_status`, **C5**, executed-vs-proposed coverage, and reporting.
