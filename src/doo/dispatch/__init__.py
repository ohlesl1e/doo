"""Slice 4 — bounded agent execution (Executor + Interpreter).

The dispatch package owns the **first code path that sends traffic** (PRD #85).
A tester arms a **dispatch run** (ADR-0042: the authorization unit) over a
selection of `approved` `TestCase`s; per TestCase the **Executor** constructs the
request deterministically (ADR-0043: per-`(test_class, role)` constructors), the
**Dispatcher** gates it (kill-switch lease → OPA → budget guards → wire), and the
result is recorded as a `RequestObservation(source="agent")` plus an
`EXECUTED_AS` edge carrying `dispatch_status` + `request_role` + `run_id`.

S1 (this tracer) builds the spine end-to-end with **no LLM** — proven against one
`idor` `primary` send. The Interpreter (S5), real Rego (S2), hazard resolvers
(S3), and the liveness-probe classifier (S4) plug into the seams left here.

Hard rules in force (CLAUDE.md):
- No LLM in request construction; constructors are pure deterministic functions.
- The Dispatcher's OPA check is authoritative; the planner's `is_in_scope` is not
  bypassable (ADR-0046).
- The kill switch lives outside this process (`engagement/keepalive`); this
  package only **reads** the lease.
"""
