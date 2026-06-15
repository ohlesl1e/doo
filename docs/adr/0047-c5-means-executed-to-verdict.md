# C5 means executed-to-verdict; `inconclusive` is untested

C5 ("`TrustBoundary`s with no executed `TestCase`") was deferred to slice 4
pending `EXECUTED_AS` (grill-queue). With TestCase now carrying four orthogonal
axes (ADR-0045), "executed" is underspecified. This ADR fixes the predicate.

## Decision

A `TrustBoundary` is **tested** for C5 iff it has ≥1 `TARGETS_BOUNDARY` `TestCase`
with ≥1 `EXECUTED_AS` edge where `dispatch_status = "ok"` **and** the TestCase's
`interpreter_verdict ∈ {vulnerable, not_vulnerable}`. Otherwise it surfaces in C5.

`inconclusive` counts as **untested** — same fail-closed logic as
`replay_invalid` / `auth_invalid` (ADR-0013/0041): if the tool could not decide,
the boundary is not cleared. The bytes going out is necessary but not sufficient.

The weaker readings live as sibling sub-queries in the shared coverage library
(ADR-0034): **C5a** = boundaries with no *proposed* TestCase (planner blind spot)
and **C5b** = boundaries with no *approved* TestCase (review backlog). C5 proper
is the dispatch-and-judge gap.

## Considered Options

- **`inconclusive` counts as tested** (rejected): would let a boundary drop out of
  C5 because the Interpreter shrugged. A human can read the transcript, but C5's
  job is to surface *where to look* — a shrug is exactly where to look.
- **`ok` execution alone is sufficient** (rejected): an `ok` send with no verdict
  (Interpreter crashed, run killed) would clear the boundary. Same false-clear.

## Consequences

- C5 depends on `interpreter_verdict`, so it is only meaningful after the first
  dispatch run — before that, every boundary is in C5 (correct: nothing tested).
- "Executed-vs-proposed coverage" (ARCHITECTURE.md slice-4 line) is C5 vs C5a.
