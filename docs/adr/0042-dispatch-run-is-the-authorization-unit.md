# The dispatch run is the authorization unit; two orthogonal mode axes; production is `review + confirm` only

ADR-0040 established that `review_status = approved` is **not** dispatch
authorization — it was given when sending cost nothing. Slice 4 needs the fresh,
dispatch-time gate that ADR left open. This ADR defines it.

## The unit of authorization is a **dispatch run**

A dispatch run is a human-armed, budget-bounded drain over a **selection
predicate** of `approved` `TestCase`s (e.g. "top-N by `expected_yield` where
`generator ∈ {c2, c4}`"). One arming decision → one run. The run carries its own
`trace_id`, a request budget (max sends, max wall-clock), and is the thing the
kill-switch lease actually kills. CLI: `doo dispatch run --engagement X
[--select …] [--limit N]`.

This gives slice-3 approval a real job (curate the pool) distinct from slice-4
arming (consent to send a specific selection now), and gives the C2 fan-out cap
(grill-queue deferral) a natural home — it is the run's selection, not a
planner-side hack.

## Two orthogonal mode axes, not one

`auto` vs `review` was being treated as one knob; it is two:

- **`arming ∈ {review, auto}`** — does a human press go? `auto` skips the arm
  prompt; the run still drains a selection of *approved* tests.
- **`interpreter ∈ {confirm, freelance}`** — once going, may the agent expand the
  target set? `confirm`: the Interpreter may only send requests that confirm/refute
  the one approved `TestCase` it was handed (baseline, body-compare, hazard-warmup).
  `freelance`: the Interpreter may mint and dispatch *new* `TestCase`s in-run —
  still through Validator + Dispatcher (OPA + stateful guards), never bypassing the
  deterministic gates; what it skips is the *human review* hop.

These are independent: `auto + confirm` (unattended but obedient) and
`review + freelance` (attended but wandering) are both coherent.

## `environment` constrains the matrix

A new tester-declared `Engagement.environment ∈ {staging, production}` field
(ADR-0012-legal: it is a fact about the tester's setup, not the target's
internals) gates which combinations are representable:

| | `arming: review` | `arming: auto` |
|---|---|---|
| `interpreter: confirm` | ✅ prod default | staging only |
| `interpreter: freelance` | staging only | staging only |

On `environment = production` the **only** legal combination is `review + confirm`.
Rationale: the kill-switch and run budget are *containment*, not *consent*; on a
production target, consent means a human saw the test. A human *arming* a freelance
run does not satisfy that — they will not see what it actually sends.

## MVP scope

Slice-4 MVP builds **`confirm` only**. `freelance` is a named, designed-for mode
behind the same `InterpreterMode` seam (so adding it is a strategy swap, not a
refactor) but ships post-MVP. The `arming` axis ships in MVP (both values; `auto`
refuses to start on `environment = production`).

## Considered Options

- **Per-`TestCase` re-approval as the gate** (rejected): makes slice-3 approval
  redundant (approve twice), and at 300+ tests/engagement it is operationally
  unworkable. The run-level gate keeps the human decision count proportional to
  *intent* ("test the C2 set now"), not to test count.
- **Mode-gated only — `auto` drains everything approved** (rejected): collapses
  the two axes into one and loses the selection predicate. The tester cannot say
  "the C2 set, not the SSRF set, and only top-50."
- **Allow `review + freelance` on production** (rejected): a human arming a run
  whose target set the agent will then expand is not meaningfully human-in-the-loop
  for the expanded part. CLAUDE.md's hard rule is read strictly.
- **Single send→judge per `TestCase`, no confirm loop** (rejected): cannot do
  ADR-0041 hazard-refresh (needs ≥2 requests), cannot disambiguate soft-200
  without a baseline, and turns every confirmation into a multi-round-trip through
  human review.

## Consequences

- `EngagementConfig` gains `environment: staging | production` (required, no
  default — forcing the tester to state it) and an optional `dispatch:` block
  (`arming`, `interpreter`, default budget). Loader **rejects** illegal
  combinations at load time, not at dispatch time.
- The Interpreter is a per-`TestCase` bounded agent (≤N tool calls; N is a run
  parameter). Its tool surface and the meaning of "same hypothesis" in `confirm`
  mode are settled in the follow-on ADR.
- `freelance` reuses the slice-3 Validator + commit path for in-run proposals
  (content-addressed `TestCase`, ADR-0007), so an Interpreter-minted test is
  graph-visible and auditable exactly like a Planner-minted one — `source =
  "llm-interpreter"` instead of `"llm-planner"`.
- A dispatch run is an observability record (OTel span, structured log on
  `trace_id`) plus a row in a **dispatch ledger** sibling to the review ledger
  (ADR-0040) — `{engagement_id, run_id, actor, armed_at, selection, budget,
  mode}` — not a graph node, for the same ADR-0040 reason: tester identity stays
  out of the target model.
