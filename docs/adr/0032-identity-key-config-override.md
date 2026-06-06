# The tester can pin the identity key per engagement (`auth.identity_key`)

An engagement-global `auth.identity_key` lets the tester **authoritatively declare which claim identifies the user**, overriding the heuristic claim-priority (ADR-0030). Mirrors `auth.session_cookie_names` (ADR-0026/#28): one engagement-level knob that pins what the heuristic would otherwise guess.

## Why

ADR-0030's claim-priority is a good default, but a tester who knows the target can do better — e.g. the app's real account key is a non-standard field the priority wouldn't rank, or the priority would pick a shared/tenant id. This is legitimate tester configuration (like declared Principals, ADR-0012), not black-box seeding.

## Decision

- **Engagement-global** `auth.identity_key` — a claim/field name, optionally **source-qualified**: `claim:_id` (any decoded token/credential claim), `header:x-user-id`, `body:accountRef` (self-endpoint body field). A small vocabulary over the same identity sources ADR-0030 already understands.
- **Authoritative-when-present.** When an actor exposes the declared claim, it is *the* key (overriding the priority). When an actor never exposes it, fall back to the heuristic priority — absence isn't punished into a fragmented synthetic, so collapse isn't lost.
- **Per-host is deferred.** ADR-0030's unified, host-agnostic key already converges an actor across hosts that present the same claim+value. Per-host *key selection* only helps when different hosts use **different** identity claims for one actor — which re-fragments (different claim → different key) and needs the cross-claim unification ADR-0030 leaves out of scope. So per-host is a later, deliberate step, not this one.

## Considered Options

- **Per-host map (`auth.identity_keys`)** now — rejected for now: partial benefit (cross-host convergence is already automatic), real complexity, and the divergent-claim case it targets needs cross-claim unification anyway.
- **Hint (reorder priority) rather than authoritative** — rejected: a tester pinning the key is asserting it; authoritative-when-present is the predictable, useful semantic (matching #28).

## Consequences

- A tester can resolve identity precisely for an awkward target in one line, without us guessing.
- Threads the engagement config to the identity-keying point (resolve + flush), the way `session_cookie_names` already threads to the cue (config → Engagement node → envelope → parse).
- Defaults (ADR-0030 priority + ADR-0029/0031 signals) handle the standard cases with no config; this is the override.
