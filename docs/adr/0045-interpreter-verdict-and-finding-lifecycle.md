# Interpreter emits a structured verdict; `Finding` has a two-axis lifecycle

The confirm loop (ADR-0042/0043) ends with the Interpreter holding the `primary`
response, baselines, blob reads, and callback checks for one `TestCase`. This ADR
fixes what it emits and how a `Finding` comes to exist — applying the ADR-0040
"LLM proposes, deterministic code commits at `proposed`, human confirms"
discipline to the output side.

## The Interpreter's output is a typed `InterpreterVerdict`

A forced tool call (same mechanism as the Planner, ADR-0037) whose schema is:

- `verdict ∈ {vulnerable, not_vulnerable, inconclusive}`
- `evidence_refs` — the `EXECUTED_AS` edge ids (i.e. the agent-sent
  `RequestObservation`s) that demonstrate the verdict
- `justification`, `observed_vs_expected`
- on `vulnerable`: `proposed_severity`, `vuln_category`, `affected_refs`
  (Endpoint / TrustBoundary handles)
- `follow_ups` — zero or more `PlannerProposal`s for genuinely-new tests the
  loop surfaced (in `confirm` mode these go to `review_status = proposed`, back
  through human review; in `freelance` they may dispatch in-run, ADR-0042)

Deterministic code records the verdict on the **TestCase** (`interpreter_verdict`,
`interpreted_at`, `interpreter_justification`, denormalised like `review_status`)
so coverage can distinguish *tested-clean* (`ok` + `not_vulnerable`) from
*tested-needs-re-look* (`ok` + `inconclusive`) from *untested* (no `ok`
execution). The verdict is the **fourth orthogonal axis** on TestCase, alongside
`status` / `review_status` / `dispatch_status`.

## `Finding` lifecycle: `finding_status` now, `disclosure_status` reserved

On `verdict = vulnerable`, deterministic code commits a `Finding` node at
**`finding_status = proposed`** with `source = "llm-interpreter"`,
`confidence_method = "llm-self-reported"`, `REFERENCES` → the demonstrating
TestCase(s), `AFFECTS` → the resolved Endpoint(s)/TrustBoundary, and
`DERIVED_FROM` → the `evidence_refs` observations. A human review step
(`doo finding review`) moves it to `confirmed | rejected`, recorded in a
**finding ledger** (sibling of the review and dispatch ledgers — same
actor/timestamp/reason audit shape, tester identity out of the graph per
ADR-0040). Only `confirmed` Findings feed reporting.

`finding_status` answers **internal confidence**. The **external disclosure
pipeline** (`unreported → reported → acknowledged → fixed → published`, plus
`wont_fix`) is a **separate, reserved axis** `disclosure_status` — the property
exists in MVP (default `unreported`), transitions ship with reporting. A
second-reviewer sign-off is then a *ledger rule* ("first `disclosure_status`
transition requires a different `actor` than the `confirmed` one"), not a new
state. Two axes, two questions — the ADR-0040 lesson applied forward.

`not_vulnerable` and `inconclusive` write nothing beyond the TestCase verdict —
the absence of a Finding *is* the record; the verdict is the audit trail.

## Finding identity is content-addressed but soft

`finding_key = sha256(engagement_id, vuln_category, primary_affected_id)` for
commit-time dedup, so two TestCases proving the same IDOR add `REFERENCES` edges
to one Finding rather than minting two. But "is this the same bug?" is ultimately
human judgement content-addressing cannot fully make, so **human-driven
merge/split** uses the established mechanic: `status = retracted` on the loser +
a `MERGED_INTO` edge (the Principal/Tenant pattern, ADR-0010), and a confirmed
Finding may be manually split by committing a second with a distinct
`primary_affected_id`. The hash is a dedup convenience, not an identity prison.

## Considered Options

- **Interpreter commits `Finding` directly** (rejected): a TestCase is a
  hypothesis (cheap to be wrong); a Finding is a claim that feeds external
  disclosure (expensive to be wrong). LLM-self-reported confidence is not
  disclosure-grade.
- **Human writes `Finding` by hand from a verdict report** (rejected): loses the
  structured `REFERENCES`/`AFFECTS`/`DERIVED_FROM` lineage the Interpreter already
  computed, and makes Finding provenance a free-text field.
- **One lifecycle enum spanning confidence *and* disclosure** (rejected): conflates
  two questions, exactly the trap ADR-0040 avoided on TestCase. A `confirmed` bug
  the program marked `wont_fix` would be unrepresentable.
- **No verdict on TestCase; only Findings persist** (rejected): coverage could not
  distinguish "tested, clean" from "tested, inconclusive" from "untested," and the
  C5 query (boundaries with no *executed-and-judged* test) needs that grain.

## Consequences

- TestCase gains denormalised `interpreter_verdict` / `interpreted_at` /
  `interpreter_justification`; full verdict (incl. `evidence_refs`) lives in the
  dispatch ledger keyed by `(run_id, key_hash)`.
- `Finding` gains `finding_status`, `disclosure_status` (reserved), `finding_key`
  (unique-indexed), and the standard `status` for merge lineage.
- Three sibling CLI surfaces with the same ADR-0040 ledger shape:
  `doo planner review` (TestCases), `doo dispatch review` (run outcomes +
  `hazard_unresolved`), `doo finding review` (Findings).
- The Interpreter's `follow_ups` reuse the slice-3 Validator + commit path
  verbatim — `source = "llm-interpreter"` instead of `"llm-planner"`, otherwise
  identical (content-addressed, scope-checked, `proposed`).
- **Replayability** (ADR-0037 applied to the Interpreter): the full confirm-loop
  transcript — every tool call, every response, the final verdict tool-use — is
  persisted to object storage keyed by `(run_id, key_hash)`, so any `Finding` can
  be traced to the exact bytes and reasoning that produced it.
