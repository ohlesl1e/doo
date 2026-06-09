# The planner's I/O is a typed contract; slice-3 proposals carry only resolvable payloads

The Planner's input and output are both **typed, deterministic contracts**, not a
graph firehose in and free-form actions out. Two halves:

## Input: the context pack (per candidate)

For each deterministically-selected candidate (ADR-0036), deterministic code
assembles a **typed, bounded "context pack"** — a fixed-depth (≤2-hop) projection
around the candidate, serialised as a Pydantic view, never raw Cypher or raw node
payloads. It carries: the candidate gap with its coverage evidence; the target
`Endpoint` `(method, path_template)`; its `Parameter`s + `ParameterSemantic`s
(with confidence); the relevant `Principal`/`AuthContext`/`Tenant` context; and a
*small bounded sample* of concrete `RequestObservation` exemplars. Effective
confidence is decayed at assembly time (ADR-0005).

**Response bodies stay out** — hashes/sizes/metadata only, consistent with the
storage discipline (bodies live in object storage) and ADR-0015 (raw tokens never
leave L2). The slice-4 Interpreter is where bodies are pulled.

**Determinism is selection + assembly + validation; the LLM step is not.** The
pack is *deterministically assembled* (`code_version`-stamped), so at a frozen
settle point the same graph state + candidate yields a byte-identical pack — a
within-run caching nicety. But query-time confidence decay runs against "now" and
in continuous mode the graph never freezes, so byte-identity is **not** a durable
cross-time property; and the **LLM output is never reproducible** (sampling, model
updates) — intentionally, that is *why* the LLM is bounded on both sides. The
guarantee we make is therefore **replayability, not reproducibility**: re-running
need not yield the same proposals, but any past decision is fully inspectable
because its inputs and outputs are **persisted**.

**Persist the decision as object-storage artifacts** (engagement-scoped, like the
`blobs.py` G4 layout): for each LLM-proposing call, store the exact serialised
context pack, the full LLM request (prompt + params + model id + `code_version`),
the raw LLM response, and the parsed proposals — keyed by run/candidate and
referenced from `TestCase.source_id`. Recomputing the pack later would fail (the
graph has mutated); persistence is what makes the ARCHITECTURE "explain exactly
what the tool did and why" requirement real. A multi-KB pack does not belong in an
OTel span attribute — the span carries the artifact key, not the artifact.

Targets and auth contexts appear in the pack as **stable handles**; the LLM
echoes a handle, never a raw Neo4j id, and the validator rejects any handle not
present in the pack it was given (kills hallucinated targets).

## Output: PlannerProposal

The LLM emits **enums + references, never request bytes** (hard rule: no LLM
request construction):

```
PlannerProposal {
  test_class        closed enum (idor, bola, auth_bypass, privilege_escalation,
                    cross_tenant, forced_browsing, leak_replay, ...)
  target_ref        pack handle -> resolves to exactly one of
                    target_endpoint_id / target_parameter_id /
                    target_trust_boundary_id (the ADR-0007 three-way XOR)
  auth_context_ref  pack handle ("send as this AuthContext")
  payload_class     closed ROE enum (benign-probe, ssrf-callback, ...)
  payload_spec      NOT bytes: {none} | {observed_value: value_hash}
                    | {configured: <engagement config key>}  (sink_params: the
                    tester-configured callback URL / canonical probe, ADR-0036)
  hold              authz-replay intent: refs kept verbatim from the evidence
                    observation (object-id / ownership / tenant ref), by
                    Parameter/role — never bytes (ADR-0041)
  replay_hazards    deterministically-detected replay-breakers in the evidence
                    observation (csrf/nonce/signature/timestamp) — set by code,
                    not the LLM (ADR-0041)
  justification     free text; must cite the candidate gap
  expected_outcome  what would confirm the vuln (for the slice-4 Interpreter)
  expected_yield    [0,1] uncalibrated hunch the test reveals a real issue —
                    a PRIORITY score, distinct from `confidence` (see below)
}
```

**`expected_yield` is distinct from `confidence`.** A `TestCase` is an inference
node and must carry the cross-cutting `confidence`, but "how sure are we this test
is *true*?" is meaningless. `confidence` keeps its ontology-wide meaning —
**validity / well-formedness** (a validator-passed `TestCase` sits high, set
deterministically) — so cross-node confidence aggregation stays coherent.
`expected_yield` is the *separate* priority hunch (`confidence_method =
"llm-self-reported"`; heuristic, derived from the gap, for deterministic
generators). The review queue is ordered by `expected_yield x gap/boundary
criticality x decay`, **discounted by the target inference's effective
confidence** (ADR-0036) — a test against a shaky inferred boundary should not
outrank one against a solid target.

`hold` / `replay_hazards` carry the authz-replay strategy (ADR-0041): `hold` is
the LLM-proposed security intent, `replay_hazards` is a deterministic annotation
warning that a naive replay would false-negative. Neither is in the `key_hash` —
the transformation is a derivable execution strategy, not an identity component.

Deterministic validator code resolves `payload_spec` to concrete bytes and
computes `payload_hash`. The committed node is a **real, content-addressed
`TestCase`** (ADR-0007) — there is **no `TestProposal` node type**. "Proposed" is
simply a `TestCase` with no `EXECUTED_AS` edge, exactly as the ontology already
defines it.

## Why slice-3 payloads are always resolvable at propose time

Every slice-3 candidate generator produces a payload knowable *now*:

- **C1 (dead endpoint)** -> benign probe, no bytes -> `payload_hash = sha256("")`
  (ADR-0007 sentinel).
- **C2 / C2b / C4 / TrustBoundary** -> **authz replays** ("send under a different
  `AuthContext`"); the test is the auth swap, no injection payload -> sentinel.
- **C3 (leak-to-input)** -> send a concrete **already-observed `ObservedValue`**
  (its `value_hash` is in the graph now).

- **`sink_params` (ADR-0036)** -> a **single canonical probe**: the
  tester-configured callback URL or a fixed marker (`payload_spec: {configured}`),
  propose-time-known -> real `payload_hash`.

The only case needing a payload-**synthesis** library is a **variant sweep** (50
SQLi payloads) — *not produced by any slice-3 generator*. So slice 3 needs three
payload resolvers — empty, observed-value-by-hash, and configured-value — and
`test_class`es requiring *swept* synthesised payloads are out of the enabled set
until the slice-4 library exists. This is an alignment, not a limitation: C1–C4
are authz/pivot leads and `sink_params` uses single canonical probes; neither
fuzzes.

## Considered Options

- **Placeholder `payload_hash` filled in at dispatch** (rejected): breaks
  ADR-0007 content-addressing — identity would churn when slice 4 supplies real
  bytes, and distinct intended tests could collide on the placeholder.
- **A `TestProposal` node that becomes a `TestCase` at dispatch** (rejected): a
  new node type + migration for a state the ontology already expresses as
  "`TestCase` with no `EXECUTED_AS`."
- **Let the LLM emit payload bytes / a full request** (rejected): violates the
  no-LLM-request-construction hard rule and the reproducibility of the pack.
- **Raw Neo4j ids as targets** (rejected): fragile, hallucination-prone, and
  leaks internal ids into the prompt; pack-local handles resolved by the
  validator are safe.
