# Security Testing Copilot

The domain language of the black-box testing knowledge graph (the "ontology"). These terms are the contract between the deterministic pipeline and the LLM planner — the planner can only reason about concepts named here.

## Language

### The observation / inference split

Every fact in the graph is either something we **observed** or something we **inferred** from observations. They are always separate node types, never merged, so an inference can be retracted without losing the underlying observation. The established pairs:

| Observation (what literally appeared) | → | Inference (what we think it means) |
| --- | --- | --- |
| **RequestObservation** | → | **Endpoint** |
| **Parameter** | → | **ParameterSemantic** |
| **RequestObservation** (its inline value occurrences) | → | **ObservedValue** / **Asset** |

### Target surface

**Host**:
A network identity — a hostname or IP plus port, canonicalized for identity (lowercased, ToASCII for IDN, trailing dot stripped, default port stripped, non-default kept). IP literals are never resolved against hostnames; they are distinct Hosts.
_Avoid_: Server, Origin, Domain (those are operational notions; `Host` is the canonical network-identity term).

**Endpoint**:
An inferred `(method, host, path-template)` the planner reasons about. The template is a revisable inference, not a value frozen at ingest.
_Avoid_: Route, URL.

**RequestObservation**:
A single observed HTTP exchange — its concrete path, the AuthContext used, the source (Burp / agent / nuclei), and references to the request/response bodies. The observation layer for Endpoints.
_Avoid_: Request, Hit.

**path template**:
A path with variable positions replaced by named parameters — `/orgs/{org_id}/projects`. An inferred, revisable property of an Endpoint.

**concrete path**:
The literal path exactly as observed — `/orgs/42/projects`. Stored on the RequestObservation; never re-templated.

**self-reference value**:
A path-parameter value such as `me`, `current`, or `self` that denotes "the current Principal" rather than an explicit id. Flagged because it is authz-relevant: `/users/me` vs `/users/123` is an IDOR signal.

**Parameter**:
A named input position to an `Endpoint` — its location (`path` / `query` / `header` / `body` / `cookie`), name, observed types, and observed value patterns. Observation layer; the counterpart of `ParameterSemantic`.
_Avoid_: Argument, Input, Field.

**ParameterSemantic**:
An inferred meaning for a `Parameter` — e.g. "this `org_id` is probably a tenant identifier." Inference layer; created when extraction's enrichment recognizes a pattern, with `confidence` reflecting how sure. Distinct from `Parameter` because inference is separate from observation.
_Avoid_: ParameterType, ParameterMeaning.

**value candidate** (inline, not a node):
A raw value occurrence extracted from a response — an identifier, URL, email, internal hostname, structured secret (JWT / AWS / Stripe), or generic high-entropy `opaque_token` — recorded *inline* on the `RequestObservation` that surfaced it (its `value_hash`, `kind`, location, extractor, and `role = "output"`), with provenance. The catch-all observation grain; replaces the retired `ResponseArtifact` node (ADR-0023). Most stay inline forever; the interesting ones are promoted to an `ObservedValue` by the flush-time promotion pass. A response's **technology fingerprint** (`Server` / `X-Powered-By`) and **5xx error excerpt** are one-per-response diagnostics, recorded as `RequestObservation` properties (`server_fingerprint`, `error_excerpt`) — never values, never promoted.
_Avoid_: ResponseArtifact (retired), Asset (that is the inferred lead).

**Asset**:
An inferred backend resource that is referenced but not yet directly addressable — a leaked bucket name, an internal hostname, a database identifier — treated as a testing lead. The inference layer; created by a promotion step that carries confidence.
_Avoid_: value candidate / ObservedValue (those are the observation grain and the cross-context value node), Lead, Resource.

**ParseFailure**:
A first-class observation that L2 could not turn a particular blob (or a particular entry within one) into a `RequestObservation`. Carries provenance back to the originating L1 envelope, the error kind (`malformed_blob`, `schema_mismatch`, `missing_required_field`, `decode_error`), an error message, and a location hint. Becomes a node in the graph so audit can see what didn't make it through — failure is never silently dropped. Re-extraction with a fixed parser may supersede a `ParseFailure` (the new commit produces real observations; the prior `ParseFailure` is marked `status = "retracted"`).
_Avoid_: error, dead-letter (those name infrastructure; `ParseFailure` is the domain term for "we observed an input we couldn't interpret").

**ObservedValue**:
A *promoted* value found in observations — an identifier, URL, email, hostname, JWT, or secret-shaped string — tracked as a node so cross-context matches ("this value leaked in a response also appears as a request input to another `Endpoint`") become a single graph traversal. Inference layer; reached directly from the `RequestObservation`s that yielded or sent the value (the inline value candidates), via `YIELDED_VALUE` / `SENT_VALUE` edges (ADR-0023 amends ADR-0009; no intermediate `ResponseArtifact`). Only **promoted** values become nodes — promotion fires on the shape-allowlist (`kind ∈ {secret, internal_hostname, email}`), on multiplicity ≥2, on leak-to-input, or on LLM proposal; junk strings (single-occurrence list ids / URLs) stay inline candidate occurrences. An **`opaque_token`** — a generic high-entropy blob (ETag, content hash, signed-URL token) with no recognised structure — is **secret-for-storage but not on the shape-allowlist** (ADR-0024): stored hash-only like a secret, yet it promotes only on multiplicity ≥2 or leak-to-input, never on shape. This decouples secrecy-for-storage (`kind ∈ {secret, token, opaque_token}`) from promotion-worthiness; `secret` is reserved for the high-precision structured detectors (JWT / AWS / Stripe). For `kind ∈ {token, secret, opaque_token}`, the node stores **`value_hash` + length + first-N chars only** — never the full value. The graph is not a credential store.
_Avoid_: Token, Value (unqualified — those are the inline observations; `ObservedValue` is the promoted entity).

### Identity & access

**Principal**:
An identity the tester controls or observes — "test user A," "admin account," "anonymous." The actor, not the credential. **Declared** Principals (tester-controlled, set at engagement setup per ADR-0012) carry an explicit `tier = "declared"` flag. Their **primary reconciliation signal** is the `identity_claims` decoded from each declared `AuthContext`'s own credential (the loader and auth-helper persist these on the AC node; ADR-0048) — a discovered credential whose claims agree on the highest-priority shared claim attaches to the declared Principal with no config. The optional `known_signals` property is the **opaque-token fallback**: out-of-band identifiers the tester observed during warm-up (JWT `sub`, `/me` user-id, identifying headers, email) for when the declared credential has no decodable claims. Plus an optional `liveness_endpoint` (`{method, path}` known to 2xx for this Principal; ADR-0044) used by the Executor to disambiguate authz-test 4xx from a dead credential. Discovered Principals carry `tier = "discovered"` and no `known_signals`.
_Avoid_: User, Account, Identity.

**AuthContext**:
A specific authenticated state belonging to a Principal — a bearer token, session cookie, or API key — with a validity window and observed capabilities.
_Avoid_: Session, Credential, Token (those are kinds of AuthContext, not the concept).

**Tenant**:
An inferred multi-tenancy unit — an organisation, workspace, or account namespace — that a Principal belongs to. Evidenced by URL positions (`/orgs/{org_id}`), headers (`X-Org-Id`), JWT claims on the AuthContext, response-body fields. An inference-layer node like `Asset`/`TrustBoundary`, with `DERIVED_FROM` edges to its evidence and the standard cross-cutting fields.
_Avoid_: Organization, Workspace, Account (those are domain-specific spellings; `Tenant` is the canonical abstract term).

**TrustBoundary**:
An inferred line across which authorization is expected to change; the planner proposes boundary-violation tests against it. A node (never an edge), in the inference layer. The `BETWEEN` endpoint is **polymorphic by `kind`**:
- _identity boundary, `kind = tenant`_ — drawn between **Tenant**s.
- _identity boundary, `kind = role` / `ownership`_ — drawn between **Principal**s.
- _capability boundary_ — drawn between **AuthContext**s of the same Principal (OAuth scope, MFA step-up, token freshness).
_Avoid_: Permission, Scope (Scope is the engagement boundary, a different concept).

### Testing & policy

**TestCase**:
A proposed or executed test — a class (IDOR, SSRF, auth-bypass), a target (an Endpoint+Parameter or a TrustBoundary), a payload, and an expected-vs-observed outcome. Content-addressed and Engagement-scoped (ADR-0007); the same content commits to the same node.
_Avoid_: Probe, Attack.

**review_status**:
The human-review lifecycle state of a `TestCase`, introduced in slice 3 (ADR-0040): `proposed` (the LLM planner created it and the deterministic Validator passed it — awaiting human review), `approved` (a human cleared it as a **vetted hypothesis, cleared for dispatch *consideration*** — *not* dispatch authorisation: slice-4 production dispatch needs a fresh, mode-gated gate at dispatch time, plus the dispatcher's authoritative OPA re-check, since approval is never a policy bypass), `rejected` (a human declined it; the node is **kept**, never deleted, so it is neither re-surfaced to the planner nor dispatched, and the decision stays auditable). Orthogonal to `status` (`active`/`retracted`, a lineage/merge flag) and to `dispatch_status` (the per-`EXECUTED_AS` execution-outcome enum, slice 4) — three axes answering three different questions. The review *decision* itself (actor / timestamp / reason) is a provenanced **audit-ledger** event, not a graph node — tester identity stays out of the black-box target model (ADR-0012); the node carries only the denormalised current `review_status` + `reviewed_by` / `reviewed_at` / `review_reason`. Validator-*discarded* proposals (out of scope, unresolvable `target_ref`, graph-inconsistent) are never committed; they live only in the planner-run audit log, not the graph.
_Avoid_: status (overloaded — that is the active/retracted lineage flag), state.

**Engagement**:
A specific testing campaign within a `Scope` — its own kill-switch, budget, time window, and audit boundary. A `TestCase` belongs to exactly one Engagement; the same logical test re-run in a different Engagement is a new `TestCase` node, not an additional edge. Carries `environment ∈ {staging, production}` — a tester-declared fact (ADR-0012-legal) that gates which dispatch modes are representable: `arming = auto` and `interpreter = freelance` both require `environment = staging` (CLAUDE.md hard rule: human-in-the-loop for production).
_Avoid_: Campaign, Run, Session.

**dispatch run**:
The unit of slice-4 dispatch authorization (ADR-0042): a human-armed, budget-bounded drain over a *selection predicate* of `review_status = approved` `TestCase`s — e.g. "top-50 by `expected_yield` where `generator ∈ {c2, c2b}`." One arming decision → one run; the run has its own `trace_id`, a request budget (max sends, max wall-clock), and is what the kill-switch lease actually kills. **Arming is not the same as approval** (ADR-0040): slice-3 `approved` curates the candidate pool; arming a run is the fresh, dispatch-time consent to send a specific selection from it. Two orthogonal mode axes govern a run: `arming ∈ {review, auto}` (does a human press go?) and `interpreter ∈ {confirm, freelance}` (once going, may the agent expand the target set?). On `environment = production` the only legal combination is `review + confirm`.
_Avoid_: batch, job (those are infrastructure words; a dispatch run is the *consent boundary*).

**request role**:
The closed, per-`test_class` enum the Interpreter passes to the Executor's `send_http_request_within_scope` tool — e.g. for `idor`: `primary` (the test itself), `baseline_victim` (same held object under the owner's auth, to diff bodies), `baseline_negative` (held identifier swapped to a known-nonexistent value, to rule out "any id 200s"). The Executor owns one deterministic **request constructor** per `(test_class, role)`; the Interpreter's only authority is *which role to send next* — it never composes a URL, header, or body (hard rule). **Replay-hazard resolution lives inside the `primary` constructor** (per-`kind` resolver registry — `csrf_token` fetch-and-splice, `nonce` strip, `timestamp` refresh; ADR-0043), not as a role: the LLM is not in the warmup-retry loop. An unresolvable hazard means the Executor **refuses the send** and records run outcome `hazard_unresolved`, surfacing the TestCase in the dispatch-side review queue for the human to supply the missing hint or accept the `replay_invalid` risk — it does not silently become "untested." The role enum is also the `confirm`-mode boundary: any request not expressible as a role for *this* TestCase is by definition a different test → back to `proposed`.
_Avoid_: variant, transform (a transform DSL was rejected — it is request construction by another name).

**Dispatcher** vs **Interpreter** (the two halves of slice-4 execution):
The **Dispatcher** is the deterministic per-request gate every outbound HTTP send passes through — kill-switch lease check → OPA (the authoritative ROE check, ADR-0003) → stateful guards (rate limit, budget, dedup) → wire. It sets `dispatch_status` (ADR-0013). The **Interpreter** is the per-`TestCase` LLM agent that drives a bounded **confirm loop**: ≤N narrow-tool calls against the Executor (the MCP server hosting `send_http_request_within_scope` etc., with the Dispatcher behind every send) to reach a verdict on the *one approved hypothesis it was handed* — it may send baseline/comparison/hazard-warmup requests for that TestCase, but in `confirm` mode it may **not** pivot to a different target or test class (those become new `proposed` `TestCase`s, back through review). `freelance` mode (staging-only, post-MVP) lets the Interpreter mint and dispatch new `TestCase`s in-run — still through Validator + Dispatcher, never bypassing the deterministic gates; what it skips is the *human review* hop. **MVP transport is a native tool-use loop** (multi-turn `tools=[…]`, our code dispatches on `tool_name`), not an MCP server — Executor functions have MCP-ready signatures so that's a later transport swap; third-party MCP servers (Burp, hexstrike-ai) sit *behind* the Executor as a wire-send backend, never exposed straight to the Interpreter (they'd bypass the gate).
_Avoid_: using "dispatcher" and "executor" interchangeably — the Executor is the request constructor + narrow-tool host; the Dispatcher is the gate sequence inside its send path.

**Scope**:
The boundary of an engagement — which `Host`s, methods, path patterns, payload classes, rate limits, and time windows are allowed. Rules live as properties on the Scope node and are the **single source of truth** from which OPA's `data` bundle is generated (ADR-0003, gap #1). An `Engagement` runs `UNDER_SCOPE` exactly one Scope. **Identity is the content hash of the rule document** (ADR-0017), so two engagements declaring identical rules collapse to one `Scope` node; this is the de-facto program-level abstraction (Acme's published rules are one `Scope` shared by multiple campaigns). **Evaluated at dispatch and at query-time only, never at intake** (ADR-0020) — passive observations of out-of-scope hosts are recorded with full provenance; the agent simply may not actively probe them.
_Avoid_: Allowlist, Program, Boundary (those are subsets or sibling concepts).

**Finding**:
A vulnerability the Interpreter's confirm loop demonstrated — severity, `vuln_category`, `REFERENCES` to the `TestCase`(s) that demonstrated it, `AFFECTS` to the `Endpoint`(s) and/or `TrustBoundary` (polymorphic, M:N — one Finding can affect both), `DERIVED_FROM` to the evidencing agent-sent `RequestObservation`s. Inference layer; `source = "llm-interpreter"`. **Two orthogonal lifecycle axes** (ADR-0045, mirroring TestCase's multi-axis discipline): `finding_status ∈ {proposed, confirmed, rejected}` — **internal confidence** (Interpreter commits at `proposed`; a human moves to `confirmed`/`rejected` via `doo finding review`, recorded in the finding ledger; only `confirmed` feeds reporting) — and `disclosure_status ∈ {unreported, reported, acknowledged, fixed, published, wont_fix}` — the **external pipeline**, reserved in MVP (default `unreported`, transitions ship with reporting). Plus the universal `status` for merge lineage. Identity is **soft content-addressed** (`finding_key` over `(engagement_id, vuln_category, primary_affected_id)`) so two TestCases proving the same bug converge to one Finding; human-driven merge/split via `status = retracted` + `MERGED_INTO` (the Principal/Tenant mechanic).
_Avoid_: Vulnerability, Issue, Bug (`Finding` is what the system has *demonstrated*; "vulnerability" is the abstract category, tracked as `vuln_category`).

**interpreter verdict**:
The Interpreter's structured per-`TestCase` output (forced tool call, ADR-0045): `verdict ∈ {vulnerable, not_vulnerable, inconclusive}`, the `EXECUTED_AS` evidence refs, justification, and optional `follow_ups` (new `PlannerProposal`s → back to `proposed`). Recorded denormalised on the TestCase (`interpreter_verdict` / `interpreted_at`) as the **fourth orthogonal axis** alongside `status` / `review_status` / `dispatch_status` — so coverage distinguishes *tested-clean* (`ok` + `not_vulnerable`) from *tested-inconclusive* from *untested*. `vulnerable` triggers a `Finding` commit at `finding_status = proposed`; the other two write nothing beyond the verdict.
_Avoid_: result, outcome (overloaded with `dispatch_status`).

**PayloadClass**:
The controlled-vocabulary category of a payload (`destructive-sql`, `ssrf-callback`, `benign-probe`...) that the ROE layer reasons about. Carried on every TestCase. A tag/enum, not a node — promoted to a node only if we ever need to reason about relationships *between* classes.
_Avoid_: PayloadType, Category.

**Payload**:
The concrete input bytes sent in one TestCase — a property/reference on that test's execution (in object storage if large), always tagged with a PayloadClass. Not a shared, deduplicated graph node.
_Avoid_: a node per payload string.

**dispatch_status**:
A low-cardinality enum carried on every `EXECUTED_AS` edge from a `TestCase` to a `RequestObservation`, recording whether the bytes that went out actually exercised the intended test path. Values: `ok` (request completed; response is genuine test evidence), `auth_invalid` (the AuthContext's *credential itself* is dead — the test did not really run), `replay_invalid` (an authz replay that failed on a replay-hazard — stale CSRF/nonce/signature — rather than on authorization; treated as **untested**, never as "boundary enforced", per ADR-0041), `rate_limited` (rate guard blocked send), `dispatcher_blocked` (OPA deny, kill-switch lease miss, or other guard), `transport_error` (network failure). For **non-authz** classes a 401/403/login-redirect under a non-anonymous AuthContext is `auth_invalid` (ADR-0013). For **authz** classes (`idor`/`bola`/`auth-bypass`/`privilege-escalation`/`boundary-violation`) a 4xx on `primary` is the *expected negative*, so it is **disambiguated by a liveness probe** (ADR-0044): a known-allowed request under the same AuthContext (the Principal's `liveness_endpoint`, declared or inferred) — probe 4xx → `auth_invalid`; probe 2xx → the test 4xx is genuine → `ok` (boundary held) or `replay_invalid` (unverified hazard). Optional per-engagement `auth_invalid_match` / `replay_invalid_match` body patterns short-circuit the probe. Coverage queries (C1–C5) filter to `dispatch_status = "ok"` when computing "tested and clean" — a `TestCase` whose only executions are non-`ok` is treated as **untested**. Set by deterministic dispatcher code (ADR-0013/0044), never by the Interpreter.
_Avoid_: result, outcome (those names conflate the deterministic dispatch classification with the LLM-driven response interpretation).

**normalization discrepancy**:
A signal raised when two concrete paths that canonicalize to the same Endpoint return materially different responses — evidence of case/slash/encoding-sensitive backend handling, and a candidate auth-bypass or path-traversal bug.
_Avoid_: Duplicate, Collision.

**coverage gap**:
A deterministically-derived absence in what the target has been exercised against — surfaced by the coverage analyzer (slice 2) as **candidates**, never verdicts. The analyzer is **pull / ephemeral**: it reads the graph at a settle point and computes gaps at query time (like `is_in_scope` and confidence decay), writing nothing back — there is no `CoverageGap` node. Slice-2 queries: C1 (in-scope Endpoints never hit), C2 / C2b (authz coverage, see **reached**), C3 (leak-to-input pivot). **C4** (capability-tier analog of C2 — strong `AuthContext` reached an endpoint the weak one of the same Principal never did) lands in slice 3 once capability `TrustBoundary` inference exists, in the same shared library. **C5** (`TrustBoundary`s not **executed-to-verdict**, ADR-0047) lands in slice 4: a boundary is *tested* only when a `TARGETS_BOUNDARY` TestCase has an `EXECUTED_AS` with `dispatch_status = "ok"` *and* `interpreter_verdict ∈ {vulnerable, not_vulnerable}` — `inconclusive` is untested (fail-closed). Weaker sub-queries C5a (no *proposed* test — planner blind spot) / C5b (no *approved* test — review backlog) sit alongside.
_Avoid_: Finding (a gap is an untested *candidate*, not a confirmed vuln).

**reached** (as a Principal):
For authz-coverage queries (C2/C2b, ADR-0033), an Endpoint is *reached* by a Principal only when an observation under that Principal's AuthContext returned **2xx** — a request alone is not enough. This is deliberately asymmetric from C1's "hit", which counts *any* `HIT` edge (a 401 still proves an endpoint is not dead). **C2** surfaces reached-as-A-but-not-as-B (B's 401/403 count as *not reached*, so a possibly-bypassable boundary is not suppressed). **C2b** surfaces Endpoints reached by ≥2 Principals whose responses differ by body hash/size — the handle on role-differentiated 200s where BOLA/IDOR lives. The **soft-200** case (200 + denial in the body) is not adjudicated deterministically; coverage carries per-Principal evidence `(status, size, body_sha256)` and leaves the call to a human or the slice-3 interpreter.
_Avoid_: hit (reserved for C1's any-request sense), accessed.

### Provenance, confidence, time

These three concerns are recorded uniformly on *every* node and *every* edge (see ADR-0005 and `ONTOLOGY.md` Step 4).

**provenance**:
Where a fact came from — the tool/method that produced it (`source`) plus a within-source identifier (`source_id`) and the time we recorded it (`ingested_at`). Lets any node be navigated back to the original artifact.
_Avoid_: Origin, Author.

**confidence**:
A `[0,1]` score on every fact. Observations sit at `1.0` *when parser validation was clean* (lower when the parser flagged ambiguity); inferences sit below. Consumers decay confidence by age at query time — it is **never re-written for decay** in storage.
_Avoid_: Probability, Likelihood (those imply calibration we don't always have).

**confidence method**:
The *kind* of confidence — `heuristic`, `manual`, `llm-self-reported`, or `calibrated`. Carried alongside the number so queries can discount LLM scores in aggregate without sniffing source-name strings.
_Avoid_: ConfidenceSource.

**event time** (`first_seen` / `last_seen`):
When the *fact* existed in the world — earliest and latest evidence. For an inference, the min/max over its contributing observations, not the time it was computed.

**transaction time** (`ingested_at`):
When *we* recorded the fact. Diverges from event time whenever older artifacts are uploaded (e.g., a HAR file from last week).

**status**:
`active` or `retracted`. Retraction is a flag, not a delete — orphaned nodes from a merge (Principal-merge, Asset-merge, Tenant-merge) are kept for audit and lineage. Planner queries filter to `status = "active"` by default; auditors / replay can see the retracted set explicitly.

**DERIVED_FROM**:
An explicit edge from every inference to each observation that fed it. Makes lineage a graph traversal, not a stored property.

## Relationships

- An **ObservedValue** (or the `RequestObservation` that yielded it) may **evidence** one or more **Assets** (an Asset can be evidenced by several).
- A **RequestObservation** is grouped under an **Endpoint** by a revisable `HIT` inference — concrete path on the observation, template on the Endpoint. Re-templating re-groups these edges; it never moves observations.
- An **AuthContext** belongs to exactly one **Principal**; a Principal has many AuthContexts.
- A **Principal** **`OF_TENANT`** zero or more **Tenant**s; cardinality is **M:N** (multi-org membership is normal).
- A `TrustBoundary` with `kind = tenant` is drawn between **Tenant**s; `role` / `ownership` between **Principal**s; capability-tier between **AuthContext**s of one Principal. The `BETWEEN` endpoint type is polymorphic by `kind` (refines ADR-0002 via ADR-0008).
- A **TestCase** may target a **TrustBoundary**; a **Finding** may attach to the **TrustBoundary** it violated. (Both require TrustBoundary to be a node — a Neo4j relationship cannot be an endpoint of another relationship.)
- A **TestCase** carries exactly one **PayloadClass** (the thing the ROE layer evaluates); its concrete **Payload** is a property/reference, not a shared node.
- A **Finding** references the **TestCase**(s) that demonstrated it.
- Every inference node (**Endpoint**, **Asset**, **ParameterSemantic**, **TrustBoundary**, …) has **`DERIVED_FROM`** edges back to each observation that fed it. Lineage is the traversal of those edges.
- A **TestCase** **`EXECUTED_AS`** zero or more **RequestObservation**s (with `source = "agent"`). Cardinality 0..N — retries and parameter sweeps add edges, they do not create new TestCases. A TestCase with no `EXECUTED_AS` edge is proposed-but-not-executed; with ≥1, it has run.
- A **TestCase** **`IN_ENGAGEMENT`** exactly one **Engagement**. Same content + same Engagement → same node; different Engagement → different node (the Engagement id is part of the TestCase identity hash).
- An **AuthContext** **`OF_PRINCIPAL`** exactly one **Principal**; a Principal has zero or more AuthContexts.
- A **RequestObservation** **`YIELDED_VALUE`** zero or more **ObservedValue**s — one edge per promoted value occurrence surfaced in the response; the edge properties `location` and `extractor` record where in the response it was found and which versioned rule found it. Non-promoted value occurrences stay inline on the observation (`value_candidates`), not edges (ADR-0023).
- A **RequestObservation** **`SENT_VALUE`** zero or more **ObservedValue**s; the edge property `parameter_name` records *which* parameter carried the value.
- An **Asset** may **`SAME_VALUE_AS`** an **ObservedValue** when both refer to the same underlying string (ADR-0011). Optional, M:N, used for cross-pivot queries between lead-status and cross-context-value views.
- An **Endpoint** **`HAS_PARAMETER`** zero or more **Parameter**s; each Parameter has exactly one Endpoint. Enables `ParameterSemantic -DERIVED_FROM-> Parameter`.
- A **TestCase** has **exactly one** of `TARGETS_ENDPOINT` (to an Endpoint, route-level test), `TARGETS_PARAMETER` (to a Parameter node, parameter-level test), or `TARGETS_BOUNDARY` (to a TrustBoundary). Three-way XOR, matching the three-way XOR in the TestCase identity hash.
- A **Finding** **`AFFECTS`** one or more **Endpoint**s and/or **TrustBoundary**s (polymorphic, M:N, **not** XOR — a single Finding can affect both, e.g. a cross-tenant data leak affecting specific Endpoints *and* the tenant boundary). Plus the existing `REFERENCES` to TestCase(s).
- An **Asset** may be **promoted** to a **Host** or **Endpoint** once it becomes reachable.
- Promotion is an inference: it carries provenance and confidence, and is retractable. The evidencing **RequestObservation**s (and their inline value candidates) survive retraction.
- A technology fingerprint and a 5xx error excerpt stay inline `RequestObservation` properties forever — they are never values and never promoted to an **ObservedValue** or **Asset**.

## Identity rules

- **Engagement scoping (per ADR-0017).** Every observation- and inference-layer node carries `engagement_id` as the first component of its identity tuple, scoping it to one `Engagement`. The only nodes whose identity does *not* include `engagement_id` are `Engagement` itself and `Scope`. The identity tuples in the rest of this section show the engagement-independent portion; the full identity of each scoped node is `(engagement_id, ...stated tuple...)`.
- **Scope identity** = `content_hash = sha256(canonicalized(rule_document))`. Two engagements declaring identical Scope rules collapse to one `Scope` node; `Scope` is reusable across `Engagement`s and is the de-facto "program-level" abstraction (the published bug-bounty rules shared by all campaigns against that program).
- **Endpoint identity = `(method, host, path-template)`.** The query string is excluded — query inputs are `Parameter`s (location=query), not part of path identity.
- **Canonicalization before templating:** strip trailing slash; lowercase host and drop default port (keep non-default); RFC 3986 percent-encoding normalization; **preserve path case**. The raw concrete path is always kept on the `RequestObservation`.
- **Normalization discrepancy:** two raw paths that canonicalize to the same Endpoint but return materially different responses raise a discrepancy signal — they are not silently merged, because the difference may be a vulnerability.
- A path position becomes a **parameter** by **multiplicity** (≥2 distinct values with the rest of the path fixed), with a **value-shape prior** for the cold-start single-observation case and a **confidence** that rises as evidence accumulates.
- **Version segments** (`v\d+`) stay literal even under multiplicity.
- A position may be **both** a parameter and host literal sibling routes — `/users/{user_id}` and `/users/settings` coexist, and the **literal match wins** (router precedence).
- **TestCase identity** is content-addressed: `key_hash = sha256(canonicalized(engagement_id, test_class, target_endpoint_id?, target_parameter_id?, target_trust_boundary_id?, payload_class, payload_hash, auth_context_id))`, unique-indexed. The target is a **three-way XOR**: exactly one of `target_endpoint_id` (route-level test), `target_parameter_id` (parameter-level test; the Parameter node carries its Endpoint via `HAS_PARAMETER`), or `target_trust_boundary_id` (boundary test). The other two normalize to null and fall out of the hash. `payload_hash` is over the concrete bytes the dispatcher will send (sentinel `sha256("")` for no-payload tests; never SQL null). Engagement is part of the identity, so cross-Engagement re-runs are distinct nodes.
- **Principal identity** is **two-tier and revisable** (ADR-0010). *Declared* Principals (the ones we control) carry a manual label set at engagement setup, with `source = "manual"`, `confidence = 1.0`. *Discovered* Principals (actors observed in passive traffic) are identified by the strongest available stable signal — in priority order: JWT `sub` claim, observed user-id from `/me`/`/whoami` responses, stable `X-User-*` header, email tied to the AuthContext, or a synthetic fallback (low confidence, flagged `unmerged`). A discovered Principal's `identity_key` is a **unified, source-agnostic claim key** (ADR-0030): `discovered:{claim}:{value}` over the first present of a single account-unique-first priority — `sub` (issuer-scoped, `discovered:sub:{iss}:{value}`) → `uid` → `user_id` → `uuid` → `_id` → `username` → `uname` → `preferred_username` → persistent/emailAddress SAML `NameID`, then **`email` last** (person-level), never a `transient` NameID. The same key is produced wherever the identity is seen — a bearer/cookie JWT, a response header (`X-User-*`), a self-endpoint (`/me`, `/userinfo`, …) body, or an SSO login exchange (ADR-0031: OIDC id_token / SAML assertion, bound to the issued credential) — so all of an actor's evidence **converges to one Principal**. It falls back to `discovered:{auth_hash}` (synthetic) only when no claim is observable (a fully opaque credential with no SSO/`/me` identity). Every claim value is account-unique (globally unique per user; `sub` issuer-scoped), so keying is merge-safe; `email` is **always also recorded as an `observed_alias`** (human-readable label, but a last-resort key since one email can own multiple accounts). A tester may pin the key with engagement config `auth.identity_key` (ADR-0032, authoritative override). Only low-confidence synthetic Principals are upgraded/re-keyed; two already-distinct Principals are never merged. Declared and discovered **reconcile via the same priority** (ADR-0048): priority-0 compares the discovered credential's `identity_claims` against each declared `AuthContext`'s own decoded `identity_claims` over the same ADR-0030 list (with `auth.identity_key` first), walk-and-intersect with stop-on-first-disagreement; `known_signals` is the lower-priority opaque-token fallback. The reconciliation runs **forward** (at resolve time, per incoming credential) and **retroactively** (at `engagement start` and at flush, sweeping existing claim-keyed discovered Principals against declared state) — no phantom twins in either declare-then-ingest or ingest-then-declare order. Merging two synthetics later proven the same is `OF_PRINCIPAL` edge re-pointing, not node surgery; the orphan is marked retracted, not deleted. **Anonymous is a singleton per `Engagement`** — one anonymous `AuthContext`, one anonymous `Principal`.
- **AuthContext identity** = `auth_hash = sha256(token_kind || ":" || token_value)`, where `token_kind ∈ {bearer, cookie, api_key, basic_auth, anonymous}`. The raw `token_value` is **never persisted** to the graph — only the hash, parsed claims, observed capabilities, and validity window (same secrets-handling discipline as ADR-0009). Token rotation = new AuthContext, same Principal. For cookie auth, only **session-credential cookies** feed the identity — app/UI-state cookies (pagination, filters, view flags) are excluded so they cannot fragment the AuthContext (ADR-0026). A cookie is a session credential if its value is opaque/credential-shaped (include-biased: anything not confidently app-state) or if it is named in the engagement's `session_cookie_names` allowlist; a JWT-shaped cookie always qualifies.
- **Session cookie** vs **app/UI-state cookie** — a *session cookie* carries the credential that identifies the actor (opaque/high-entropy, or JWT, or tester-declared); an *app/UI-state cookie* carries client view state (pagination, filters, layout flags) and is identity-irrelevant. Only the former contributes to `AuthContext` identity (ADR-0026).
- **Host identity** = `(scheme, canonical_hostname, port)`. Canonicalization: lowercase hostname, ToASCII for IDN, strip trailing dot, strip default port (`:443` https / `:80` http), keep non-default ports. IP literals stay distinct from hostnames. **Host is engagement-scoped** (per ADR-0017): two engagements observing the same hostname produce two `Host` nodes, because discovery in one engagement does not flow into another.
- **Tenant identity** = `(kind, normalized_value)` with `kind ∈ {org_id, workspace, account_namespace, subdomain, …}`. When two Tenants are later proven the same (alternate identifiers — URL position *and* JWT claim — pointing at one tenant), **merge via `OF_TENANT` edge re-pointing**; orphan marked retracted (same mechanic as Principal-merge).
- **Asset identity** = `(kind, normalized_value)` with `kind ∈ {internal_hostname, bucket_name, database_id, signed_url, internal_path, …}`. Distinct from `ObservedValue` (they coexist by ADR-0011) and linked by an optional `SAME_VALUE_AS` edge when both nodes refer to the same string.

## Example dialogue

> **Dev:** "`internal-billing-prod.corp.example` showed up in three different 500 bodies. Three nodes or one?"
> **Domain expert:** "Three value occurrences — three real observations, recorded inline on the three `RequestObservation`s with their own provenance, and (because the hostname clears the shape-allowlist) promoted to **one `ObservedValue`** deduped by `value_hash`, with three `YIELDED_VALUE` edges. One **Asset**, evidenced by that value, because we *infer* they point at the same backend resource. If we later reach it, that Asset gets promoted to a **Host**."

## Flagged ambiguities

- **"Asset" vs the value-observation grain** — the original entity catalog let both claim "internal hostname in an error message." Resolved in two steps: first that the observation layer is a per-extraction **ResponseArtifact** node and **Asset** is the inference lead; then (ADR-0023) that the per-extraction node was the wrong grain — a real 72 MB HAR minted 277k of them — so the raw value occurrence is now recorded **inline** on the `RequestObservation` (a *value candidate*), and only promoted ones become **`ObservedValue`** nodes. **Asset** stays the curated inference lead. The "dumping ground" is now an inline array, not 277k nodes.
- **What a TrustBoundary is drawn between** — "Principal" alone made capability differences within one Principal (OAuth scope, MFA step-up) invisible, which the "auth state transitions not exercised" coverage query needs. Resolved: two tiers — _identity_ boundaries between **Principal**s, _capability_ boundaries between **AuthContext**s of the same Principal.
- **How explicit Payloads should be** — the draft leaned "maximalist" (a node per payload string) on the belief that OPA evaluates graph state. It doesn't — OPA evaluates the proposed request (see ADR-0003). Resolved: the first-class concept is **PayloadClass** (a tag carried on the request); the **Payload** instance is a property/reference; a reusable payload library is deferred until we build one.
- **The mixed path position** — `/users/123`, `/users/me`, `/users/settings` route off one position but are three things. Resolved: literal sub-routes (`settings`) are their own **Endpoint**s and win over the parameter; `me`/`current`/`self` are **self-reference values** of `{user_id}`, flagged for IDOR. Because **Endpoint** identity is a revisable inference (ADR-0004), early mis-templating self-corrects without node surgery.
- **Decaying confidence** — the obvious move is to lower stored `confidence` as facts age. Resolved: confidence is set at creation and **never re-written for decay**; consumers compute effective confidence = f(stored, age) at query time. Keeps the graph append-mostly and the audit trail intact (ADR-0005).
- **Inbound vs outbound traffic** — tempting to model agent-sent requests as a separate `Execution` entity. Resolved: both are `RequestObservation`s, distinguished only by `source` (ADR-0006). Coverage queries see one unified observation set; a `source` filter separates active from passive only when a query actually needs it.
- **One TestCase per proposal, or per content?** A synthetic-id-per-proposal model would mean "one proposal = one node," but it leaves dedup as a separate equality-on-many-fields query and fills the graph with near-duplicates. Resolved: TestCases are content-addressed (ADR-0007). The LLM may re-propose the same test verbatim; commit is a no-op. The cross-Engagement reuse case ("the test we know how to run, regardless of run") is a deferred concept — `TestTemplate`, not the same as TestCase.
- **Where tenant lives** — tempting to make `tenant_id` a flat property on `Principal`. Resolved: `Tenant` is a first-class **inference** node (ADR-0008), evidenced by URL positions, headers, JWT claims, and response fields; `Principal -OF_TENANT-> Tenant` is many-to-many. This refines ADR-0002 — `kind = tenant` `TrustBoundary`s are drawn between `Tenant`s, not `Principal`s.
- **Value matching: inline or node?** Inline indexing is cheaper but leaves no place to attach provenance, confidence, or findings to a value. Resolved: promoted values become `ObservedValue` nodes (ADR-0009); shape-/multiplicity-filtered, with secrets stored as hash+length+preview only. Junk strings stay inline on the originating observation. Cross-context queries (C3, leak-to-input) are graph traversals through the value node.
- **Declared vs discovered Principals as phantom twins** — naïve handling creates a separate "discovered" Principal whenever an AuthContext surfaces in traffic, even when that AuthContext is one we set up. Resolved: declared and discovered reconcile through the same identifier-priority list (ADR-0010); when a discovered signal matches a declared Principal's known signal, the AuthContext attaches to the declared node.
- **Asset vs ObservedValue — unify or coexist?** Both can refer to the same underlying string (a leaked hostname is naturally either). Resolved: **coexist** (ADR-0011) with an optional `SAME_VALUE_AS` edge. They carry different semantic intent — `ObservedValue` = "seen across contexts" (C3); `Asset` = "lead worth testing" (C6) — and the queries that use them differ. Unification was rejected because it trades a node-type filter for a property filter without simplifying anything materially. A two-step `Asset PROMOTED_FROM ObservedValue` chain was also rejected as an unpaid-for hop.
