# TestCase review lifecycle: `review_status`, commit only valid, keep rejected

Slice 3 commits `TestCase` nodes but dispatches nothing; human review sits in the
middle. The ontology's `status` (`active`/`retracted`) is a lineage/merge flag and
`dispatch_status` (on `EXECUTED_AS`, slice 4) is an execution outcome — neither
captures *review* state. This ADR adds the review lifecycle.

## `review_status` is a third, orthogonal axis

`review_status: proposed | approved | rejected` on `TestCase`, independent of
`status` and `dispatch_status` — three axes, three questions (lineage / human-gate
/ execution-outcome). A rejected `TestCase` stays `status = active`; it was not
merged away, a human just declined it.

## What persists, what doesn't

The Planner emits `PlannerProposal`s (not nodes, ADR-0037). The deterministic
Validator then:

- **invalid** (out of scope via `is_in_scope`; unresolvable `target_ref` /
  hallucinated handle; graph-inconsistent) → **discarded, logged in the
  planner-run audit (OTel), never committed.** Deterministically invalid, so it
  re-rejects identically next run — nothing to persist; keeps the graph free of
  invalid tests.
- **dedup hit** (content-addressed, ADR-0007) → no-op commit by construction.
- **valid + new** → commit, `review_status = proposed`.

Human review moves `proposed → approved | rejected`. **Rejected nodes are kept**
(`review_status = rejected`): human judgement is not deterministically
reproducible, so persistence is what stops re-surfacing it and preserves the audit
trail ("the tool proposed this; a human declined").

## The review decision is a provenanced audit event, not a graph node

The tester approving/rejecting a test is **engagement-operational metadata, not a
target fact.** The graph is the black-box model of the *target* (`Principal` /
`AuthContext` are the *target's* actors); putting tester identity into it would be
the boundary violation ADR-0012 polices. So review decisions live in the
**audit/observability substrate**: an append-only **review ledger** keyed by
`(engagement_id, key_hash)` recording `{actor, timestamp, decision, reason,
prior_status -> new_status}`, on the same `trace_id` lineage as everything else
(ADR-0018). The `TestCase` node carries only the *denormalised current* state —
`review_status` plus `reviewed_by` / `reviewed_at` / `review_reason` for
convenience queries; the full history (including approve-then-rescind) is the
ledger's. This gives disclosure-grade audit ("a named person authorised this at
time T, for this reason") that a bare enum on the node would have thrown away.

## Rejection durability: `disposition` + a re-surface predicate

A `TestCase`'s `key_hash` is over `(test_class, target, payload, auth)` — **not**
its justification or evidence (ADR-0007). So a naive "don't re-propose anything
already rejected" would make rejection a **forever-veto**: a test declined against
weak evidence stays suppressed even after the evidence materially changes
(confidence rose, a new principal appeared, the endpoint re-templated). Putting
evidence in the hash is not an option — it would explode identity. So durability
lives *outside* identity:

- The rejection ledger event carries a **`disposition`**: `permanent`
  (`wont_fix` / `not_applicable` — a genuine non-issue, never re-surface) or
  `defer` (`not worth it yet`). **Default `defer`** — the safe default is "do not
  permanently blind yourself"; permanent suppression is a deliberate human choice.
- The event **snapshots the evidence state at rejection** — effective (decayed)
  confidence and an evidence marker (max `last_seen` / `DERIVED_FROM` count on the
  target/boundary).
- The planner's dedup-against-rejected is therefore a **predicate, not a presence
  check**. On a `key_hash` match to a rejected node: `permanent` stays suppressed
  always; `defer` **re-surfaces only if** effective confidence has risen
  materially above the snapshot *or* new `DERIVED_FROM` evidence has appeared since
  the rejection — presented flagged *"previously rejected at T for reason R;
  re-surfaced because X changed"* so the human sees the delta, not a blind re-ask.

The node stays `rejected` until a human re-decides; re-surfacing is a read over the
ledger + current graph, no graph mutation.

## `approved` is "cleared for dispatch *consideration*", not dispatch authorisation

A slice-3 approval is made when the cost of "yes" is zero — **nothing dispatches.**
It must **not** be read by the slice-4 dispatcher as authorisation to send traffic
at a production target. `review_status = approved` means *"vetted hypothesis,
cleared for dispatch consideration."* Production dispatch in slice 4 requires a
**fresh, mode-gated authorisation at dispatch time** (human-in-the-loop-for-
production + kill-switch principle) — a separate gate from this field, plus the
dispatcher's authoritative OPA re-check (ADR-0003; approval is never a policy
bypass). Slice 4 must not conflate "approved to exist" with "approved to send."

## No `PlannerRun` node

A planner run is an observability record (OTel span + structured log on the
`trace_id`, ADR-0018), not a domain entity — consistent with deferring an
audit-log store beyond Neo4j edges. The committed `TestCase` carries the lineage:
`source = "llm-planner"`, `source_id = <run/request id>`, `code_version = <prompt
version>`, `confidence_method = "llm-self-reported"`.

## Review surface

A CLI mirroring `doo coverage`: `doo planner propose` (run → commit `proposed`
`TestCase`s) and `doo planner review` (list `proposed` with justification / gap /
target / expected-outcome; approve or reject, individually or by run). No bespoke
UI in slice 3; it is review-only by construction since nothing dispatches. The
auto/review/dry-run modes are slice-4 concerns.

## Considered Options

- **Overload `status` or `dispatch_status` for review state** (rejected):
  conflates three independent questions; a rejected-but-active test would be
  unrepresentable.
- **Persist validator-discarded proposals as nodes** (rejected): they are
  deterministically invalid (re-derivable), so the graph gains only noise; the run
  log already captures them for audit.
- **Keep proposals ephemeral; commit only on approval** (rejected): loses the
  rejected-test audit trail and the signal that stops the planner re-proposing a
  human-declined test.
