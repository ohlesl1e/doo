# Dispatch outcome is recorded on `EXECUTED_AS`; `auth_invalid` is untested for coverage

Every `EXECUTED_AS` edge from a `TestCase` to a `RequestObservation` carries a `dispatch_status ∈ {ok, auth_invalid, rate_limited, dispatcher_blocked, transport_error}`. Coverage queries (C1–C5) filter to `dispatch_status = "ok"` when computing "tested and clean." A `TestCase` whose only executions are non-`ok` shows up as **untested** — i.e. a coverage gap — not as a clean result. This kills the false-negative path where an expired token returns 401 and the planner records "no vulnerability here."

The classification of `dispatch_status` is **deterministic**: 401, 403, or known login-redirect 3xx patterns when the request was sent under a non-anonymous `AuthContext` → `auth_invalid`; rate-limit guard hit before send → `rate_limited`; OPA deny or kill-switch lease miss → `dispatcher_blocked`; network failure → `transport_error`; otherwise `ok`. The Interpreter (LLM) does **not** decide `dispatch_status`, matching the hard rule that LLMs do not make policy or routing decisions.

Why on the edge and not the `TestCase`: the same TestCase may run multiple times (retries, parameter sweeps, post–auth-rotation re-runs per ADR-0010 / ADR-0014). Per-execution status preserves the audit trail of each attempt while letting aggregation decide whether the TestCase as a whole has been exercised. Why a property and not a separate node type: status is a low-cardinality enum with no identity, history, or relationships of its own.

## Considered Options

- **Only create `EXECUTED_AS` when the run was clean** (rejected): loses the audit trail of bytes that actually went out, and conflicts with ADR-0006 — every observed request is a `RequestObservation` regardless of source or outcome.
- **Status on the `TestCase` node** (rejected): drops per-execution granularity; cannot represent "ran 5×: 3 ok, 2 auth_invalid."
- **Distinct relationship types per status** (rejected): `EXECUTED_AS_OK` / `EXECUTED_AS_AUTH_INVALID` / ... explodes the relationship vocabulary for a property every query reads, with no upside.

## Consequences

- Coverage queries (C1–C5) gain a uniform filter: `WHERE r.dispatch_status = "ok"`. The C-query documentation must show this filter explicitly.
- A long-running engagement with rotating tokens produces `TestCase`s with mixed `ok` / `auth_invalid` history across executions. Aggregation logic for "has this test ever run cleanly?" becomes a `MAX` over the edge property.
- Adding a new `dispatch_status` value is a backwards-compatible enum extension; coverage queries default to treating unknown values as non-`ok` (fail closed).
- The Interpreter reads `dispatch_status` to skip its own response analysis on non-`ok` executions — there is nothing to interpret in a 401 that did not carry the test payload.
