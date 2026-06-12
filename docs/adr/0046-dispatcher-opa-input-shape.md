# Dispatcher OPA `input` is the concrete request + test context; bundle generated from `Scope`

ADR-0003 fixed OPA as a pure `f(input, data)`; ADR-0038 deferred the real Rego to
slice 4. The Dispatcher now exists (ADR-0042/0043) and gates **every** wire send —
`primary`, baselines, hazard-warmup, liveness probes. This ADR fixes the `input`
document those Rego rules evaluate.

## `input` shape

```json
{
  "engagement_id": "…",
  "environment": "staging" | "production",
  "run_id": "…",
  "request": { "scheme": "https", "method": "GET", "host": "…", "path": "/orders/123",
               "path_template": "/orders/{order_id}" },
  "test_class": "idor",
  "payload_class": "auth-token-swap",
  "request_role": "primary" | "baseline_victim" | … | "hazard_warmup" | "liveness",
  "auth_context_id": "…",
  "principal_tier": "declared" | "discovered",
  "target_confidence": 0.87,
  "now": "<RFC3339>"
}
```

Everything is snapshot from the constructed request + `TestCase` + run — no graph
read inside policy (ADR-0003's rule). **Both** `path` (concrete) and
`path_template` (the Endpoint's current inference) are present: the canonical
Scope-glob rules match `path` — same semantics as the Python `is_in_scope` helper
(ADR-0020/0035), so planner-side and dispatcher-side scope checks agree by
construction — while `path_template` is available for tester-authored deny rules
that want to name an Endpoint without enumerating ids. `request_role` lets policy
treat controls differently (e.g. always allow `liveness` to a declared
self-endpoint; never allow `baseline_negative` with a destructive `payload_class`).

## `data` bundle is generated from the `Scope` node (ADR-0003 reaffirmed)

The OPA bundle is **generated**, not hand-written: a build step reads the
engagement's `Scope` node + `Engagement.environment` and emits
`data.scope = { allowed_hosts, method_allowlist, path_globs,
payload_class_denylist, time_windows, environment }`. The Rego *rules* are a
small fixed set checked into the repo (host-glob match, path-glob match,
payload-class deny, time-window, environment×payload-class matrix); the
per-engagement *facts* are the generated `data`. Tester-authored extra rules
(per-engagement `.rego` overlay) are supported but optional.

## Considered Options

- **Concrete `path` only** (rejected): cannot express "deny anything targeting
  `/users/{id}/delete`" without enumerating ids; `path_template` is one extra
  string and reuses an inference the graph already maintains.
- **Template only** (rejected): the template is a *revisable inference* (ADR-0004);
  denying on it alone means a re-templating could silently un-deny a request. The
  concrete path is what actually leaves the process.
- **Hand-written Rego per engagement** (rejected): drifts from the `Scope` node
  that `is_in_scope` reads, breaking the planner/dispatcher agreement ADR-0038
  relies on. Generation keeps one source of truth.

## Consequences

- The slice-1 deny-all Rego skeleton is replaced; the planner→OPA wire (ADR-0038
  noted it unexercised) MAY now be connected, but the planner continues to use
  `is_in_scope` — the dispatcher's OPA call is the authoritative one.
- `request_role ∈ {hazard_warmup, liveness}` are Executor-internal sends
  (ADR-0043/0044), not Interpreter roles, but they pass the same gate — so a
  Scope that denies `GET /login` will also block a `csrf_token` resolver that
  needs it, surfacing as `hazard_unresolved` (correct: policy wins).
- Rego unit tests (per CLAUDE.md convention) get a fixture `input` per role.
