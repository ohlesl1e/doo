# Endpoint re-templating is deferred to a per-drain `flush`, not run per observation

Endpoint inference (path templating, `HIT` regrouping, `Parameter` aggregation) runs **once per ingestion drain**, against the cohorts that gained new evidence — not on every committed `RequestObservation`. The L3 commit of an observation writes the observation and its non-inference edges and stops; a separate `flush` step does the re-templating.

## Why

The slice-1 implementation called `retemplate_cohort` from `CommitOrchestrator.commit` for **every** `RequestObservation`. Each call re-read the entire `(engagement_id, method, host_id)` cohort, re-ran `template_paths` over the full corpus, and re-`MERGE`d every `Endpoint` plus re-pointed every `HIT` edge — even when the cohort was already stable. That is **O(N²)** in both reads and writes over a host's observations. A real ~1,900-request Burp HAR took minutes-to-hours to drain (the enumeration shape `/users/1 … /users/1900`, all distinct, all collapsing to `/users/{user_id}`, is the worst case: every observation is a new distinct path that triggers a full cohort re-scan).

The fix rests on two facts:

- **Endpoint identity is a *revisable* inference (ADR-0004).** The contract is that the inference *converges* as evidence accumulates, not that the graph is fully refined after every single observation. `template_paths` is a pure function of the cohort's set of distinct concrete paths, so one pass at the end of a drain yields a graph **identical** to N incremental passes.
- **Slice 1 has no mid-drain reader.** Nothing consumes the graph while ingestion is in flight — coverage analysis (slice 2), LLM hypothesis generation (slice 3), and the dispatcher (slice 4) all read at a *settle point* after ingestion (or, for agent traffic per ADR-0006, between action cycles). So the window where an observation exists but its `Endpoint`/`HIT` lags has no observer.

## Decision

Split the commit into two primitives:

- **`commit(RequestObservation)`** writes the observation node + `ON_HOST` + `OBSERVED_UNDER` + any `ResponseArtifact`s (`YIELDED`). It does **not** create the `Endpoint`, `HIT`, or `Parameter` nodes. The observation is left **un-HIT**.
- **`flush()`** finds every `(engagement_id, method, host_id)` cohort containing **≥1 un-HIT observation** and re-templates it (the existing `retemplate_cohort`, essentially unchanged). This attaches `HIT`s, creates/retracts `Endpoint`s (ADR-0001 retraction discipline preserved), and aggregates `Parameter`s.

A cohort is therefore "dirty" iff it has an un-HIT observation — a fact **derived from the graph**, not tracked in memory. This makes recovery trivial: there is nothing to persist.

Trigger points:

- **`doo worker run --once`** — `flush()` once, after the drain. The enumeration case becomes one `template_paths` pass + one batch of `HIT` attaches = **O(N)**.
- **`doo worker run` (continuous)** — `flush()` on a debounce (every K commits) and on graceful shutdown.
- **worker startup** — `flush()` to re-template anything a crashed run left un-HIT.

## Considered Options

- **Keep strong per-observation consistency, add fast-path skips** (rejected): duplicate-path detection and "fits an existing template" skips help common traffic but leave the all-distinct enumeration case at O(N²) — every observation is a new distinct path that still forces a cohort re-scan. Doesn't solve the actual problem.
- **Incremental templating now** (deferred, not rejected): maintain the templating trie and recompute only the affected sub-tree per new distinct path, writing only diffs (~O(N log N), and the only thing that also fixes *continuous* streaming over a large cohort). This is a real change to the pure `template_paths` algorithm and its test surface. It is the long-term ceiling-raiser, deferred behind the `flush` seam so it can replace `flush`'s internals later without touching callers.
- **Batch flush per drain** (chosen): O(N) for the offline-HAR workload that is slice 1, with no change to the templating algorithm itself — `retemplate_cohort` is simply called from `flush` instead of from `commit`.

## Consequences

- **O(N²) → O(N)** for a `--once` drain. The 1,900-request HAR drains in one cohort pass instead of 1,900.
- **Reversible to strong consistency** cheaply: `flush` is a seam. Strong = call `flush` after each commit; eventual = call it per drain. The granularity is a caller-side policy knob, not a rewrite — important if a later slice grows a mid-drain reader.
- **Eventual within a drain:** an observation exists un-HIT until `flush`. Acceptable in slice 1 (no mid-drain reader); the boundary condition to revisit is live/streaming capture (Logger++) paired with a live coverage view — mitigated by the debounce keeping lag to seconds plus an explicit on-demand flush.
- **`l3-events` timing:** `NodeCreated`/`NodeUpdated` for `Endpoint`s and `Parameter`s now emit at `flush`, not at observation commit. Observation-level events (`RequestObservation`, `ResponseArtifact`, `ParseFailure`) still emit at commit. Consumers already treat `l3-events` as eventually-consistent structural facts.
- **Idempotency (ADR-0016) is unchanged:** the observation commit's semantic key still collapses re-deliveries, and `flush` is `MERGE`-based, so re-running a drain re-templates idempotently.
- **Known follow-up (deferred behind the seam):** in continuous mode a debounced `flush` re-templates the whole (growing) cohort each time → O(N²/K). The next step is a within-`flush` fast path (skip the `template_paths` re-run when a cohort gained no new *distinct* path, just attach the new observations' `HIT`s), and ultimately incremental templating. Tracked in `docs/grill-queue.md`.
- This ADR amends the *implementation timing* of ADR-0004, not its identity model: `Endpoint` identity is still `(engagement_id, method, host_id, path_template)` and still a revisable inference; only the moment of revision moves from per-observation to per-flush.
