"""The slice-3 Planner spine (issue #60, ADRs 0036–0041).

Proven end-to-end on C1 with **no LLM**: a deterministic candidate generator
selects in-scope dead endpoints, proposes a `forced_browsing` test directly, the
deterministic Validator resolves + checks it, a content-addressed `TestCase`
commits at `review_status = proposed`, and a human reviews the prioritised queue
(approve / reject) with each decision recorded as a provenanced audit-ledger
event. Nothing is dispatched in this slice (slice 4 owns execution).

This package is the reusable machinery every later slice plugs into:

- `models`     — `Candidate`, `PlannerProposal`, review/ledger Pydantic types.
- `generators` — `CandidateGenerator` interface + registry + the C1 generator.
- `validator`  — the deterministic correctness core (scope/XOR/payload/dedup).
- `commit`     — content-addressed `TestCase` identity + idempotent commit.
- `review`     — the review lifecycle + append-only audit ledger.
- `prioritize` — the deterministic review-queue prioritiser.
- `service`    — orchestrates `propose` and `review`.
- `cli`        — `doo planner propose` / `doo planner review`.
"""

from __future__ import annotations
