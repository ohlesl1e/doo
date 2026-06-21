# The slice-3 planner is gap-driven: deterministic generators select targets, the LLM proposes tests

The slice-3 Planner does **not** survey the graph and pick what to test. Target
selection is **deterministic**; the LLM proposes a test *for an already-selected
target*. This keeps the LLM at the end of the pipeline (design principle 1), not
in the prioritisation seat in the middle.

## The selection seam

Selection is a **pluggable set of deterministic candidate generators**, not
hardcoded to the coverage C-queries:

- The slice-2 coverage queries (C1, C2, C2b, C3) are the first generators, plus
  **C4** (capability-tier analog of C2, ADR-0033) once `TrustBoundary` inference
  lands in this slice.
- A **`sink_params`** generator also ships in slice 3 (committed, not speculative —
  it is what makes the gap-driven decision honest rather than blind to surface no
  coverage query encodes, e.g. `callback_url` on an otherwise-clean endpoint).
  Detection is deterministic: a `Parameter` whose `ParameterSemantic` ∈
  {`url_sink`, `redirect_target`, `file_path`, …} (name + value-shape heuristics).
  Its tests use a **single canonical probe**, not a variant sweep — the
  tester-configured callback URL (ADR-0012-legal, propose-time-known → real
  `payload_hash`) or a fixed marker — so it needs no payload-synthesis library.
  Caveat: its payload classes (`ssrf-callback`, …) are governed by the OPA payload
  denylist, enforced authoritatively by the **slice-4 dispatcher** (ADR-0038);
  slice 3 only *proposes* (nothing dispatches), so this is safe.
- Further generators (C6 strong-evidence `Asset`s, …) can be added later, **without
  ever moving the LLM into target selection.** Each generator is deterministic,
  auditable, and unit-testable; each candidate carries a named reason.
- `planner.candidate_generators` config enables/disables generators. Every
  setting is fully deterministic.

Each emitted proposal traces back to the deterministic candidate (and thus the
coverage gap / generator) that produced it — the provenance story that matters
for bug-bounty disclosure ("why did the tool propose this?").

A generator **may filter its coverage input** when a row is semantically void as
an attacker hypothesis — coverage stays exhaustive (ADR-0033: "all active
principal pairs"), the generator decides relevance. First instance:
`C2Generator` drops rows where the reached side is the anonymous singleton
(`evidence_a.is_anonymous`), since "send as a more-privileged actor what anon
already gets" inverts the authz direction (#137); the coverage CLI still emits
those rows. Filtered rows are logged (`planner.generator.<id>.skip_*`), never
silently dropped.

## Deterministic vs LLM-proposing generators

A generator either **proposes deterministically** or **proposes via the LLM**:

- **Deterministic-proposing** — the gap has nothing to reason about. C1 (dead
  endpoint -> "send a benign GET") emits a `TestCase` directly
  (`test_class = forced_browsing`, `payload = none`), **no LLM call**,
  `source = "deterministic-c1"`, `confidence_method = "heuristic"`. Routing it
  through the model would pay tokens to rubber-stamp a mechanical probe.
- **LLM-proposing** — C2b, C3, capability/tenant boundaries, where `test_class` /
  `hold` / expected-outcome are genuine reasoning. These go context-pack -> LLM ->
  `PlannerProposal` (ADR-0037), `source = "llm-planner"`.

Both pass the Validator and land `review_status = proposed`. Provenance cleanly
separates machine-obvious probes from reasoned hypotheses (and the deterministic
benign-probes are the natural first candidates for slice-4 auto-approval on
staging). Pipeline: `generator -> (deterministic TestCase | context-pack -> LLM ->
proposal) -> Validator -> prioritised review queue`.

## Review-queue prioritisation is mandatory and deterministic

Gap-driven breadth (C1–C4 + sink-params) can yield hundreds of candidates, and the
human approves all of them — so review is the system's throughput wall. The
defence is **deterministic** prioritisation, always on: order the queue by
`expected_yield` x gap/boundary criticality (tenant > capability > C2b > C2 > C1)
x decay, **discounted by the target inference's effective confidence** (don't let a
test against a shaky inferred boundary outrank one against a solid target). Shown
top-N per session so the human is never handed an undifferentiated pile.
`expected_yield` is the proposal's priority hunch, distinct from `confidence`
(validity) — see ADR-0037.

## Optional LLM ranking (axis 2)

`planner.llm_ranking: on|off` (default **off** for the first tracer — for
**cost/scope control, not reproducibility**: the LLM's *output* is never
reproducible regardless, so ranking-off buys simplicity, not determinism) lets the
LLM **re-rank** the candidate set. It is optional polish *on top of* the mandatory
deterministic ordering above; what is proposable is still exactly the deterministic
set, and a human reviews the order regardless.

## LLM target selection (model B) is deferred to slice 4

Letting the LLM propose targets **not** in the candidate set (graph-survey /
"freelance") is a real capability — it can surface attack surface no deterministic
generator encodes (the classic `callback_url`-on-an-otherwise-clean-endpoint
case) and do emergent cross-node reasoning. But it costs unbounded context,
run-to-run non-reproducibility, and a diluted audit trail. It is therefore a
**named, off-by-default mode, not a slider position** — deferred to slice 4. When
built, freelance proposals will carry `source = "llm-freelance"`, low confidence,
and **production-auto-dispatch will never honour them** — a freelance `TestCase`
requires explicit human approval to reach the dispatcher, enforced in code, not
by a flag default. The genuine emergent-reasoning use case also has a more
natural home in the slice-4 **Interpreter**, which proposes follow-ups from
observed responses (gated, never silently re-prioritising).

## Considered Options

- **Graph-survey / model B (LLM picks targets)** (rejected for slice 3): puts the
  LLM in the prioritisation seat the architecture rejects; unbounded context;
  same graph yields different picks run-to-run; no deterministic reason to cite
  in a disclosure. LLMs handed a large graph also anchor on salient/large nodes
  and are *worse* than deterministic coverage at systematic completeness ("did we
  hit every in-scope endpoint").
- **A continuous `determinism: 0.0–1.0` knob** (rejected): untestable middle
  values, and it silently crosses the architectural line into model B without an
  explicit decision. Replaced by discrete, separately-tested modes on orthogonal
  axes (generators; ranking; — later — freelance).
- **Build freelance in slice 3 as the cheap experiment** (considered, rejected):
  attractive because nothing dispatches in slice 3, so model B's *safety* cost is
  zero and it would be the cheapest place to learn whether B earns its keep. Set
  aside to keep slice 3 focused on a reproducible spine; revisit in slice 4.
