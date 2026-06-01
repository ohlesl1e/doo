# Auth helper is a sibling process; the agent never mints credentials

When a declared `AuthContext`'s token expires or is revoked mid-engagement, refresh is performed by a separate **auth helper process** that holds the refresh credential. The agent process (planner / dispatcher / executor / interpreter) never holds refresh tokens, OAuth client secrets, or any credential-mint capability. The helper writes a new `AuthContext` node on each rotation, sets the old one to `status = "expired"`, and keeps the `OF_PRINCIPAL` edge pointing at the same `Principal` — matching ADR-0010's "token rotation = new AuthContext, same Principal" rule.

The trust split mirrors the kill-switch lease: a sibling process holds powers the agent must not. The agent's executor reads current AuthContext material from a secret-store path; it has no write or refresh capability against that path.

YAML declares an optional per-AuthContext `refresh:` block with one of three mechanisms: `command` (shells out to a tester-provided script — most flexible, covers any auth scheme), `oauth_refresh` (built-in refresh-grant), `http` (tester-templated request). Whichever mechanism, the credential to perform the refresh lives in the helper's env, not the dispatcher's.

Triggers are **proactive** (helper polls `AuthContext.validity_window`, refreshes ahead of `exp - margin`) and **reactive** (dispatcher emits `auth_invalid` events per ADR-0013; helper consumes them, rate-limited to e.g. 3 refreshes per AuthContext per hour to prevent re-auth storms from a buggy interpreter). Rate-limiting the reactive trigger is itself a stateful dispatcher guard (per ADR-0003).

**MVP timing.** The helper itself is deferred until slice 3 (when agent-sent requests begin). The data-model pieces it depends on — AuthContext rotation, `status = "expired"`, `dispatch_status = "auth_invalid"` — land in slice 1 because coverage queries need them. The YAML `refresh:` field is *not* in the slice-1 `EngagementConfig` schema (per ADR-0012); it ships when the helper does.

## Considered Options

- **Agent process performs token refresh itself** (rejected): gives the agent credential-mint capability. A buggy or compromised agent could rotate arbitrarily, exhaust refresh quotas, or exfiltrate refresh tokens. Same principle that keeps the kill switch out of the agent.
- **Tester rotates env vars manually with no helper** (rejected for long engagements): works for slow-rotation auth; fails for tokens that expire in minutes. Operational footgun once dispatch is real.
- **Reactive-only helper (no proactive polling)** (rejected): predictable expiry windows become unnecessary `auth_invalid` runs that pollute the audit log and add round-trips to dispatch.
- **Reserve the YAML `refresh:` field in slice 1 as a hint the loader validates but doesn't act on** (rejected): adds surface area before behaviour exists; testers cannot meaningfully fill it in. Adding the field with the helper is a one-line schema bump.

## Consequences

- Every long-lived declared `Principal` accumulates an audit trail of `expired` `AuthContext`s as the engagement runs. Queries asking for "the current AuthContext for Principal X" filter to `status = "active"` (the default per ADR-0001).
- The refresh credential is the most sensitive material in the engagement. Out-of-band storage (env, secrets manager) is mandatory; it is never in the YAML.
- The `command` refresh mechanism is intentionally broad — it shells out to tester code. Acceptable because the helper runs under the tester's authority, not the agent's; the agent never invokes it directly.
- Slice-1 reviewers should expect to revisit setup-format ergonomics once the `refresh:` field lands (ADR-0012 anticipates schema bumps of this kind).
