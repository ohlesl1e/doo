# C2 authz-coverage semantics: response-status as proxy, body-metadata differential, deferred success-matcher

The C2 family answers "what can principal A do that we have not shown principal B can do?" — the authz-coverage signal. Slice 2 splits it into two complementary deterministic queries and fixes the success criterion deliberately, because HTTP status is a noisy proxy for "did this principal actually access the resource."

## Decision

**"Reached as principal P" requires a *successful* observation, not merely a request.**

```
reached(e, P) := ∃ r : (r)-[:HIT]->(e),
                       (r)-[:OBSERVED_UNDER]->(:AuthContext)-[:OF_PRINCIPAL]->(P),
                       r.response_status ∈ 200..299
```

This is intentionally **asymmetric from C1**. C1 ("is this endpoint dead?") counts *any* `HIT` edge — a 401 still proves the endpoint exists. C2 ("differential access") counts only 2xx, because the question is different.

**C2 — presence differential.** `C2(A, B) = { e : reached(e, A) ∧ ¬reached(e, B) }`.
- The **A side** needs genuine 2xx success: A's access is what we want to replicate as B, so a 401-to-A is a worthless lead. Filtering A to 2xx raises precision.
- The **B side** "not reached" folds together "B never sent a request" *and* "B sent one and was blocked (401/403/404/5xx)". Both are bypass/IDOR test candidates. Counting B's 401 as a hit would **suppress** exactly the lead we want — the boundary may be bypassable. This extends ADR-0013's "401/403/known-login-redirect = the test did not really run / untested" from agent `EXECUTED_AS` edges to passive observations.

**C2b — content differential.** Endpoints `reached` (2xx) by **≥2 principals** whose responses **differ** by `response_body_sha256` or `response_size_bytes`. This is the deterministic black-box handle on *role-differentiated 200s* — apps where every principal gets 200 but the body is rendered per role/account. C2's presence query is blind to these (both principals "reached"); C2b surfaces them, and that is where BOLA/IDOR lives. Pure metadata comparison — **no body parsing**.

**Slice-2 scope:** 2xx-only is the success set. 3xx is treated as not-reached — we have no passive login-redirect classifier (ADR-0013's detector lives only in dispatch code), and being conservative on the A side only *reduces* leads (safe). Redirect-following / login-redirect classification is a documented refinement, not slice 2.

**No `dispatch_status` filter in slice-2 C2/C2b** — that property lives on `EXECUTED_AS` (agent traffic, slice 4). Slice-2 queries run over passive `HIT` edges. The filter becomes relevant once agent traffic exists.

## Coverage surfaces evidence; it does not adjudicate

Coverage is a candidate-surfacer, not an oracle — deterministic Cypher, no LLM, no app-specific body parsing (consistent with the L1-3-no-LLM hard rule). The **soft-200** case (200 + "access denied" in the body) cannot be adjudicated deterministically without app knowledge, and silently trusting status would produce the dangerous false-negative (mark B "reached", suppress the lead). So C2/C2b result rows carry per-principal **evidence** — `(status, response_size_bytes, response_body_sha256)` — rather than collapsing to a boolean. A human or the slice-3 LLM interpreter adjudicates the ambiguous cases; coverage's only obligation is to *not hide them*.

## Considered Options

- **Status-agnostic C2 (hit = any HIT, symmetric with C1)** (rejected): a 401-to-B counts as "reached" and suppresses a bypass candidate — a false negative in the most security-relevant direction. The user grilling caught this.
- **Parse response bodies to classify success/failure in the query** (rejected for slice 2): app-specific, fragile, and edges into semantic interpretation that belongs to the LLM layer, violating the no-LLM-in-L1-3 discipline if automated deterministically per-app.
- **Per-engagement `success_match`/`failure_match` config knob** (deferred, not rejected): for apps that *always* 200 with a body-level success flag, the tester declares a string/regex that the `reached` predicate consults — tester-side knowledge (ADR-0012-legal, same class as `session_cookie_names`/`identity_key`), deterministic, the sqlmap `--string` pattern. Deferred because zero-config 2xx + C2b cover most cases; revisit when a real target always-200s.

## Consequences

- Two slice-2 prerequisites: (1) promote `response_body_sha256` to a top-level node property (currently buried in the `response_body_ref` JSON string) so C2b compares hashes without JSON-extracting in Cypher; (2) confirm `response_size_bytes` is written as a queryable node property.
- C2/C2b run over **all active principal pairs** (declared + discovered tiers + anonymous), with A and B **pinnable** from the CLI (`--as admin --not-as anon`). Post identity-v2 collapse (ADR-0030) the principal count is small, so the N² pairing is cheap.
- C1 and C2 deliberately use different "hit" definitions; the C-query documentation must state this so a future reader does not "fix" C2 to match C1.
- The 3xx/login-redirect refinement and the `success_match` config knob are tracked deferrals in `docs/grill-queue.md`.
