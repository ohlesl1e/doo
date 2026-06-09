# Slice-3 planner-side policy filtering uses the Python `is_in_scope` helper, not OPA

ADR-0003 says the planner queries OPA (efficiency) and the dispatcher queries OPA
(correctness). In slice 3 the dispatcher does not exist yet, and the Rego is the
slice-1 **deny-all skeleton** (`default allow := false`, no `allow` rule). Wiring
the planner to that Rego would deny every proposal.

**Decision:** the slice-3 planner does its policy filtering through the existing
Python **`is_in_scope`** helper (ADR-0020) — the *same* query-time scope evaluator
the coverage library already uses (C3 requires its target endpoint be in scope).
The deny-all Rego is left untouched; the real host/path/payload Rego rules remain
slice-4 work, where the dispatcher (OPA's actual consumer) lands.

This is consistent with ADR-0020's established split: **query-time** scope
evaluation uses the Python helper; **dispatch-time** uses OPA/Rego. The planner is
a query-time consumer, exactly like coverage — so it uses the same shared helper,
no new code path, no drift (the ADR-0034 shared-library discipline).

## Boundaries stated explicitly (not papered over)

- **Slice-3 planner-side policy = scope only.** `is_in_scope` covers
  host/method/path-glob (ADR-0035). It does **not** cover `payload_class_denylist`,
  time, or environment policy — those live in the fuller OPA policy and are
  enforced authoritatively by the **slice-4 dispatcher**. Acceptable for slice 3
  because proposals carry benign payload classes (authz replays, observed-value
  sends) unlikely to hit a denylist — but it is a real gap, named here.
- **The planner→OPA wire is not exercised in slice 3.** ADR-0003's "planner
  queries OPA" is met *in intent* (the efficiency filter runs via the helper the
  OPA bundle is generated to mirror) but **not literally**. Nobody should later
  assume that path is tested. Defense-in-depth is intact: the authoritative OPA
  check is still the dispatcher's, in slice 4.
- Every `PlannerProposal` carries `payload_class` regardless, so when the slice-4
  dispatcher Rego lands, the same proposal is re-checked authoritatively. The
  planner check was only ever the early filter.

## Considered Options

- **Write the real Rego rules now (pull slice-4 policy forward)** (rejected):
  creates a second policy implementation to keep in lockstep with `is_in_scope`
  *before* the dispatcher that specifically needs OPA exists — maintenance burden
  with no consumer.
- **Stub the planner-side check out entirely** (rejected): forfeits the genuine
  efficiency win when `is_in_scope` is already shared, tested, and sitting right
  there.
