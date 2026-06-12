# Authz-test `dispatch_status` is disambiguated by a liveness probe (amends ADR-0013)

ADR-0013's classifier — "401/403/login-redirect under a non-anonymous AuthContext
→ `auth_invalid`" — was written before authz replays were the dominant test class.
For an authz test, a 403 under the attacker's auth is the **expected negative**
("boundary held"), not "test didn't run." Under ADR-0013 as written, every clean
authz negative is misfiled `auth_invalid`, polluting the ADR-0014 reactive-refresh
trigger and hiding genuine "boundary held" results from the Interpreter.

## Decision: a per-`AuthContext` liveness probe disambiguates the 4xx

When an authz-class test's `primary` send returns 401/403/login-redirect, the
Executor sends a **liveness probe** under the *same* `AuthContext`: a
known-allowed request (e.g. `GET /me`) declared per-Principal as
`liveness_endpoint` in the engagement YAML (ADR-0012-legal — it is the tester's
own warm-up knowledge), defaulting to the first observed self-endpoint
(`/me`/`/userinfo`/…, ADR-0031) if undeclared. Then:

- probe **4xx** → token is dead → test `dispatch_status = auth_invalid`; emit the
  ADR-0014 reactive-refresh event.
- probe **2xx** → token is live → the test 4xx is genuine evidence. If the
  TestCase carried `replay_hazards` the resolver could not fully verify (or the
  response body matches a declared `replay_invalid_match`) →
  `dispatch_status = replay_invalid`; else → `dispatch_status = ok` and the
  Interpreter judges "boundary held."

The probe result is **cached per `(AuthContext, window)`** (default 60s) so a run
of N authz tests under one attacker token costs ~1 probe per window, not N. The
probe is a real Dispatcher send (kill-switch → OPA → guards → wire →
`RequestObservation` with `source = "agent"`, role tagged `liveness`), counted
against the run's request budget.

## Optional per-engagement body-match override

Targets whose 4xx bodies are reliably distinguishable may declare
`auth_invalid_match` / `replay_invalid_match` regex patterns (the sqlmap
`--string` shape; ADR-0012-legal). When declared, body-match runs **before** the
probe and short-circuits it — cheaper when it works, and the probe remains the
fallback for bodies that don't match either pattern.

## ADR-0013 is amended, not replaced

The original rule stands for **non-authz** test classes (sink probes, leak
replays) where a 4xx under the test's own auth still means "didn't reach the
test path." The amendment is: **for authz-class tests** (`idor` / `bola` /
`auth-bypass` / `privilege-escalation` / `boundary-violation`), a 4xx on
`primary` is *not* immediately `auth_invalid` — it is disambiguated as above.
The classifier remains deterministic; the Interpreter still never sets
`dispatch_status`.

## Considered Options

- **Response-body heuristics only** (rejected as the *primary* mechanism):
  fragile, target-specific, and silent when the body is empty or generic. Kept as
  an optional declared override that short-circuits the probe.
- **Let the Interpreter classify** (rejected): `dispatch_status` feeds coverage
  filters and the auth-helper's reactive trigger — both must be reproducible.
  Violates the ADR-0013 / hard-rule split.
- **Accept the ambiguity — every authz 4xx is `ok`** (rejected): a dead attacker
  token would then read as "every boundary held," a systematic false negative
  across the whole run, and the ADR-0014 reactive refresh would never fire.

## Consequences

- `EngagementConfig` Principal gains optional `liveness_endpoint`
  (`{method, path}`); engagement-level optional `auth_invalid_match` /
  `replay_invalid_match`.
- The Executor's `primary` constructor for authz classes gains a post-send
  classification step that may issue one more (cached) request. The probe is *not*
  a request role — the Interpreter never asks for it.
- A run against a target with no self-endpoint and no declared `liveness_endpoint`
  falls back to **`ok` on authz 4xx** (the least-bad default: it over-reports
  "boundary held" rather than spuriously triggering refresh storms), and the
  dispatch-side review queue flags the engagement once: "no liveness endpoint —
  authz negatives are unverified."
- ADR-0013's `dispatch_status` enum is unchanged; only the *classification rule*
  for authz tests is amended.
