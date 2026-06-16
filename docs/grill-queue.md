# Grill Queue

Tracker for design decisions that want a `/grill-with-docs` pass before code lands, plus the running list of deliberate deferrals.

**The slices themselves are defined in `ARCHITECTURE.md` → "Build order (the slices)"** — that is the canonical roadmap. Current status: **slices 1–3 are shipped**; **slice 4 (bounded agent execution — Executor + Interpreter) is grilled (ADR-0042–0047) and is the build target.** This file tracks what is still worth grilling and what is parked.

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
| Planner LLM provider | Claude (`claude-opus-4-8`) via the LiteLLM gateway | Planner is the highest-leverage reasoning task; code against one gateway client so provider is config, not code. Per-engagement `llm.provider` override to a **local** model for internal engagements under org data-policy (opt-in); BB-external defaults to the API. Resolves the `ARCHITECTURE.md` "local vs API split" open question for the planner. |

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
- **Cap / rank C2 candidates before the LLM call (ADR-0036).** `C2Generator`
  makes one synchronous proposing call per `run_c2` row. C2 emits one row per
  *ordered* principal pair × endpoint where A reached and B did not — on a real
  engagement (`fap-hd`, 5 principals, 74 endpoints) that's 306 rows ⇒ 306
  sequential LLM calls (~45 min on a slow gateway). Most of that fan-out is
  redundant: the same endpoint surfaces once per non-reaching principal, and the
  `(anon, X)` direction is rarely an authz lead. Options to grill: (a) collapse
  C2 rows by endpoint and let the LLM pick the attacker from the full
  per-principal evidence (the C2b pack shape already does this); (b) apply the
  ADR-0036 deterministic prioritiser *before* proposing and truncate top-N; (c)
  drop ordered pairs where the A side is `anon`. Per-gap progress logging + a
  configurable per-call timeout landed 2026-06-11 so the run is observable and
  bounded; the fan-out itself is unchanged. Revisit alongside slice 4 (the same
  cap will gate dispatch volume).

- **Burp extension.** HAR-first MVP — drop a HAR file into ingestion, see it land in the graph. No Java/Kotlin yet. For continuous capture later, **Logger++** (existing Burp extension) is the planned integration point: it ships auto CSV export and a live Elasticsearch-stream output. The integration is a small HTTP shim that speaks the ES bulk-index protocol and pipes the indexed documents into L1 ingestion as raw observations — Logger++ thinks it's writing to ES, we get streaming Burp traffic with zero custom Burp code. A custom Montoya extension is only justified if Logger++'s exported document shape lacks something we need; revisit then.
- **OpenTelemetry SDK + collector + exporters.** Refined to "OTel-ready, OTel-not-yet" per ADR-0018: `trace_id` / `span_id` ride in `IngestionEnvelope`, `L2Event`, and `l3-events` from slice 1; structured logs include the same IDs; the SDK and exporters are deferred until slice 2-3 when distributed tracing pays off.
- **Reporting / disclosure templates + `disclosure_status` transitions.** Designed (ADR-0045 reserves the axis); deferred past slice-4 MVP — build after the first real `confirmed` Finding exists to template *from*.
- **Sink-class execution** (`ssrf` / `open-redirect` / `path-traversal` constructors + `check_callback` tool + callback receiver). Designed (ADR-0043); deferred past slice-4 MVP — needs a callback-receiver integration (Interactsh or self-hosted), its own infra piece. Slice-4 MVP is authz-replay only.
- **`freelance` interpreter mode.** Designed (ADR-0042: staging-only, behind the `InterpreterMode` seam); ships post-MVP.
- **Payload-synthesis library** (SQLi/XSS/… fuzz lists → a fourth `payload_spec` resolver). The slice-3 resolvers (`none` / `observed_value` / `configured`) cover the MVP authz classes; fuzz lists need their own grill (payload-class policy, dedup, OPA `payload_class` rules per environment).
- **Role/ownership `TrustBoundary` inference.** Still deferred (per ADR-0039) — C2/C2b already cover the principal-differential surface; revisit when a consumer needs the boundary as a first-class node.
- **Planner→OPA wire** (replace planner-side `is_in_scope` with a real OPA call). ADR-0046 keeps the dispatcher's OPA authoritative; the planner stays on the shared helper until drift is observed.
- **Per-engagement LLM provider/model wiring.** The `EngagementConfig.llm` block (`provider: gateway|local`, `model`) exists in the schema and the per-engagement **local-override** intent is real (org data-policy: internal engagements may route structural/claims data to an on-network LiteLLM, BB-external defaults to the API — see "Pick a default and move"). But nothing reads `cfg.llm` at runtime: `planner/cli.py` and `dispatch/cli.py` both build the `LiteLLMCaller` from `DOO_PLANNER_*` env only, so editing `llm.model` in the YAML has no effect. Grill the wiring separately: precedence (does YAML `llm.model` override `DOO_PLANNER_MODEL`, or only fill in when the env is unset?), what `provider: local` resolves to concretely (a pinned `DOO_PLANNER_API_BASE`?), planner-only vs planner+interpreter, and whether it earns its own ADR (the `LLMConfig` docstring currently mis-cites ADR-0037, which is silent on provider routing). Surfaced 2026-06-13 while documenting the engagement config (#95).
- **Executor as an MCP server / third-party MCP behind the Executor.** Slice-4 MVP uses a native tool-use loop (ADR-0043 amendment); Executor functions have MCP-ready signatures so hosting them over MCP later (process isolation, egress-isolated host) is a transport swap. Third-party MCP servers (Burp's, hexstrike-ai) are a candidate **wire-send backend** *inside* `send_http_request_within_scope` — never handed straight to the Interpreter (would bypass kill-switch/OPA/guards/`dispatch_status`). Revisit when egress isolation or Burp-replay fidelity is wanted.
- **TestTemplate** (cross-Engagement test catalog) — deferred per ADR-0007.
- **PayloadClass as a node** (currently a tag) — promote only if class-to-class relationships emerge.
- **Audit log store** beyond Neo4j edges — promote when query/audit needs outgrow what provenance + `DERIVED_FROM` can answer.
- **Cross-engagement inference priors.** Per ADR-0017 a fresh `Engagement` against the same target starts cold (re-templating, re-inferring `ParameterSemantic`s, etc.). When this re-discovery cost becomes painful, add explicit opt-in prior loading in the engagement YAML — e.g. `prior_engagements: [{id: acme-2026-q2, use_for: [endpoint_templates, parameter_semantics, tenant_inferences], confidence_decay: 0.5}]`. Loader does a one-time inference-import with `source = "prior_engagement:<id>"` and decayed confidence so fresh evidence in the new engagement can override. Explicit opt-in keeps the Q1-of-G1 setup-boundary discipline intact (ADR-0012): the tester is declaring their own prior work, which is tester-side knowledge. **Slice-3 addition (grilled 2026-06-08):** prior-loading must also import prior **review decisions** (approvals/rejections + their `disposition`, ADR-0040), not just inferences — so a `permanent`-rejected `TestCase` in Acme-Q1 doesn't re-surface in Acme-Q2 and prior approvals can pre-rank. Without this, engagement-scoped content-addressing forces a full human re-review every campaign against the same program.
- **Cookie `auth_hash` asymmetry (declared vs L2).** L2's `_normalize_cookie_value` (`extraction/har.py:480`) strips the `%22…%22` / `"…"` wrapper before `compute_auth_hash`, so the canonical cookie credential is the bare value. The declared-side callers — `setup/loader.py:277`, `dispatch/auth_helper.py:210`+`:284`, `dispatch/secrets.py:87`, `dispatch/executor/liveness.py:103` — hash verbatim. A target that needs the quoted form on the wire forces the `refresh.command` script to emit `"<jwt>"` (the Executor's `_splice_auth` sends `material.raw` as-is), which then hashes differently from ingested traffic → phantom-twin `AuthContext`/`Principal`. Fix: lift the normalizer to `canonical/`, apply it at all **five** declared-side hash sites (hash-only — `material.raw` stays wire-form), extend the loader's JWT decode to `kind: cookie`. Tracked as **#103** (`ready-for-agent`); wants a short ADR-0026/0027 amendment. The related `_match_declared_principal` resolver gap (no path for non-`sub`/`email` claims; no retroactive reconcile) was **split to #104** and grilled 2026-06-15 → **ADR-0048** (declared-credential `identity_claims` as priority-0; retroactive sweep at `engagement start` + flush). Surfaced 2026-06-15.
- **Batch approve/reject in `planner review`.** Single-key `--approve <key>` / `--reject <key>` is deliberate (ADR-0040: each decision is a per-key provenanced ledger event with explicit `--actor`), but reviewing a large planner run is tedious. Tension: batch convenience vs. rubber-stamping the human gate. Mitigant: `approved` is only "cleared for dispatch *consideration*" — dispatch still re-checks OPA + needs fresh arming (ADR-0042). Candidate shapes, increasing risk: (1) **multi-key** — make `--approve`/`--reject` repeatable `list[str]`, shared `--actor`/`--reason`, still one ledger event per key (trivially safe, no ADR needed); (2) **filtered batch** — `--where test_class=… --approve-matching`, with mandatory TTY confirm + count preview, refuses on non-TTY (attestation becomes "I reviewed this *class*"; needs an ADR-0040 amendment); (3) **asymmetric** — batch for `--reject` only (conservative direction), `--approve` stays single-key. In all shapes `--actor` stays required with no default (no `$USER` fallback — the agent runs as `$USER` too, so an ambient default would let automation forge the attester). Surfaced 2026-06-15.
- **Incremental re-templating (continuous-mode performance).** ADR-0022 deferred endpoint re-templating to a per-drain `flush`, which makes the offline-HAR (`--once`) workload O(N). A debounced `flush` in *continuous* mode still re-templates the whole growing cohort each tick (→ O(N²/K)). Two graded fixes, both behind the `flush` seam so callers don't change: (1) a within-`flush` fast path that skips the `template_paths` re-run when a cohort gained no new *distinct* concrete path and just attaches the new observations' `HIT`s; (2) full incremental templating — maintain the trie and recompute only the affected sub-tree per new distinct path, writing only diffs (~O(N log N)). Revisit when Logger++ streaming capture lands or cohorts get large enough that continuous-mode flush latency bites.

## Grilling order / history

1. ~~**G1** — Engagement / Scope / declared-Principal setup~~ ✅ closed 2026-05-28 (ADR-0012/0013/0014).
2. ~~**G2** — Layer-boundary Pydantic contracts~~ ✅ closed 2026-05-30 (ADR-0015/0016).
3. ~~**Slice 1** — L1 ingestion + L3 graph~~ ✅ shipped (ADRs 0001–0032).
4. ~~**G3 / G4** — write-path timing & blob layout~~ ✅ resolved by the slice-1 implementation (ADR-0022; `blobs.py` key layout) — never needed a formal grill.
5. ~~**Slice 2** — coverage C1/C2/C2b/C3~~ ✅ shipped 2026-06-08 (ADR-0033/0034/0035).
6. ~~**Slice 3 — LLM-assisted hypothesis generation (the Planner).**~~ ✅ grilled 2026-06-08 (ADR-0036–0041, incl. a second-order review pass amending 0036/0037/0040). Decisions:
   - **Control model** — gap-driven, *not* graph-survey: deterministic **candidate generators** select targets (C1–C4 first, sink-params / C6 assets pluggable), the LLM proposes a test per target. Optional LLM **ranking** (axis 2, default off) orders the deterministic set. LLM target-selection ("freelance" / model B) is a named, off-by-default mode **deferred to slice 4**, barred from production-auto. (ADR-0036)
   - **Planner I/O contract** — a typed, bounded **context pack** per candidate (≤2-hop projection, response **bodies out** — hashes only; targets/auth as pack handles, not Neo4j ids); output is a typed `PlannerProposal` of **enums + references, never request bytes**. The deterministic Validator resolves `payload_spec` → bytes → `payload_hash`. Slice-3 payloads are always resolvable at propose time (empty sentinel for authz replays, observed-value-by-hash for C3); synthesised-payload classes (SQLi/SSRF fuzz) are out until the slice-4 library. Committed node is a real content-addressed `TestCase` — **no `TestProposal` type**. (ADR-0037)
   - **Planner-side policy** — uses the shared Python **`is_in_scope`** helper (query-time consumer, like coverage), *not* OPA; deny-all Rego left untouched; payload-class/time/env enforcement is the **slice-4 dispatcher** OPA's job. (ADR-0038)
   - **`TrustBoundary` inference** — **capability + tenant only**; role/ownership deferred (C2/C2b already cover principal-differential access). Boundary tests are **authz replays of an evidencing observation** (endpoint read from `DERIVED_FROM`, preserving the target XOR). Granularity-bounded (capability = same-Principal AuthContexts with a claim delta; tenant = pairs sharing ≥1 Endpoint). Write-path, at flush. Unblocks **C4** (lands in the shared coverage library, ADR-0034). (ADR-0039)
   - **TestCase review lifecycle** — `review_status: proposed | approved | rejected`, orthogonal to `status` and `dispatch_status`. Validator-discarded proposals are logged (OTel), never committed; human-**rejected** ones are kept (audit + no re-propose). No `PlannerRun` node. CLI: `doo planner propose` / `doo planner review`. (ADR-0040)
   - **Execution model** — deterministic per-candidate loop (one bounded LLM call per candidate); agentic tool-use deferred to the slice-4 Interpreter (corollary of ADR-0036, no separate ADR).
   - **LLM provider** — Claude via the LiteLLM gateway, per-engagement local override (see "Pick a default and move").
   - **Where slice 3 stops** — propose + validate + human-review; **nothing dispatches**. C4 lands here; C5 + `EXECUTED_AS` + dispatch stay in slice 4.
   - **Second-order review pass (8 gaps grilled):** review decisions are provenanced **audit-ledger** events, not graph nodes; `approved` = "cleared for *consideration*", not dispatch authorisation (slice 4 needs a fresh gate) (ADR-0040). Rejection carries `disposition` (`permanent`/`defer`) + a re-surface predicate so content-addressing isn't a forever-veto (ADR-0040). **Authz-replay fidelity** — `hold` (LLM) + `replay_hazards` (deterministic) on the proposal, `replay_invalid` dispatch_status in slice 4; unresolved hazard ⇒ **untested, never "enforced"** (ADR-0041). Review queue gets **mandatory deterministic prioritisation** + top-N; **C1 proposes deterministically** (no LLM) (ADR-0036). Planner decisions are **replayable, not reproducible** — full pack + LLM request/response persisted to object storage (ADR-0037). **C4** sharpened to the capability-tier C2 differential (evidence-gated; tenant coverage broader). **`sink_params`** generator committed to slice 3 (single canonical probe, no fuzz library) so gap-driven isn't blind to sink surface (ADR-0036). `expected_yield` (priority) split from `confidence` (validity) (ADR-0037). Cross-engagement review-decision import folded into the prior-loading deferral.

7. ~~**Slice 4 — bounded agent execution (Executor + Interpreter).**~~ ✅ grilled 2026-06-12 (ADR-0042–0047). Decisions:
   - **Dispatch authorization unit** — a **dispatch run**: a human-armed, budget-bounded drain over a *selection predicate* of `approved` `TestCase`s. Two **orthogonal** mode axes: `arming ∈ {review, auto}` (does a human press go?) × `interpreter ∈ {confirm, freelance}` (may the agent expand the target set?). New `Engagement.environment ∈ {staging, production}` constrains the matrix — on production the **only** legal combo is `review + confirm`. The C2 fan-out cap is the run's selection, not a planner hack. (ADR-0042)
   - **Executor contract** — `send_http_request_within_scope(testcase_id, role)` where `role` is a closed **per-`test_class` enum** (`primary` / `baseline_victim` / `baseline_negative` / …); one deterministic constructor per `(test_class, role)`. The role enum *is* the `confirm`-mode boundary. **Hazard resolution lives inside `primary`** (per-`kind` resolver registry mirroring the slice-3 detectors), not as an Interpreter role; an unresolvable hazard ⇒ Executor **refuses send** and surfaces `hazard_unresolved` to a dispatch-side review queue — never silently untested. (ADR-0043)
   - **Authz `dispatch_status` disambiguation** — amends ADR-0013: an authz-test 4xx is the *expected negative*, so it is disambiguated by a per-`AuthContext` **liveness probe** (declared `liveness_endpoint`, cached per window) — probe 4xx → `auth_invalid`; probe 2xx → `ok` (boundary held) or `replay_invalid`. Optional per-engagement `auth_invalid_match` / `replay_invalid_match` body patterns short-circuit. (ADR-0044)
   - **Interpreter output** — a typed `InterpreterVerdict` (forced tool call): `verdict ∈ {vulnerable, not_vulnerable, inconclusive}` + evidence refs + `follow_ups`. Recorded as the **fourth axis** on `TestCase`. `vulnerable` ⇒ deterministic commit of a `Finding` at `finding_status = proposed`; human confirms via `doo finding review` (ADR-0040 ledger pattern). `Finding` lifecycle is **two-axis**: `finding_status` (internal confidence — MVP) × `disclosure_status` (external pipeline — reserved). Finding identity is *soft* content-addressed; merge/split via `retracted` + `MERGED_INTO`. Full confirm-loop transcript persisted (ADR-0037 replayability applied). (ADR-0045)
   - **OPA `input` shape** — the concrete request + test context (`path` *and* `path_template`, `payload_class`, `request_role`, `environment`, `now`, …); `data` bundle **generated from the `Scope` node** (ADR-0003 reaffirmed) so planner-side `is_in_scope` and dispatcher-side Rego agree by construction. (ADR-0046)
   - **C5 = executed-to-verdict** — a boundary is *tested* only when a targeting TestCase has `dispatch_status = ok` **and** `interpreter_verdict ∈ {vulnerable, not_vulnerable}`; `inconclusive` is **untested** (fail-closed). C5a (no proposed) / C5b (no approved) are sibling sub-queries. (ADR-0047)
   - **Where slice-4 MVP stops** — ships: dispatch run + both `arming` values; **authz-class** request constructors only; Dispatcher gate (kill-switch + generated OPA + rate/budget guards); hazard resolvers `csrf_token`/`nonce`/`timestamp` + `hazard_unresolved` surfacing; liveness-probe classifier; Interpreter confirm loop + verdict + Finding@proposed; `doo dispatch run|review` + `doo finding review`; C5/C5a/C5b; auth-helper sibling process (ADR-0014); the new `EngagementConfig` fields. **Deferred:** `freelance` mode (seam only); **sink-class** constructors + `check_callback` + callback receiver; payload-synthesis library; `disclosure_status` transitions + reporting/disclosure templates; role/ownership `TrustBoundary` inference; planner→OPA wire.

8. **Next — Slice-4 PRD + tracers.** `/to-prd` over ADR-0042–0047, then `/to-issues`. First vertical: arm a run on `fap-hd` staging → one IDOR `primary` + `baseline_victim` through the full Dispatcher gate → Interpreter verdict → `Finding` at `proposed` → human confirms.
9. **After slice 4 — grill third-party MCP behind the Executor.** Burp's MCP server / hexstrike-ai as the `executor.send` wire backend (replay fidelity, Burp session reuse) and/or hosting the Executor itself over MCP for process/egress isolation. Constraint already fixed (ADR-0043 amendment): never exposed straight to the Interpreter. Questions to grill: which third-party tools are gate-safe to wrap; whether MCP-server-hosted Executor is the right isolation boundary vs. a plain subprocess; how third-party tool output enters the graph with provenance.
