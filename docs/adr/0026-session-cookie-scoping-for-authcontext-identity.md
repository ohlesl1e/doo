# Only session-credential cookies feed the AuthContext identity; app/UI-state cookies are excluded

The `AuthContext` identity (`auth_hash`) for a cookie-authenticated request is computed over **only the session-credential cookies**, not every cookie on the request. A cookie is classified at L2 (`extract_auth_context_cue`) by value shape — **include-biased**: every cookie feeds identity *except* those that are confidently app/UI state — with an authoritative per-engagement `session_cookie_names` allowlist as an override. A JWT-shaped cookie value is unconditionally a session credential.

## Why

Re-ingesting a real 74 MB cookie-auth Burp export produced **46 fragmented discovered Principals**. The capture has **zero `Authorization` headers**; of 134 cookie names, only `token` is the credential (13 distinct values — rotation, ~1–2 real users), and the rest are UI state (`ap_offset`, `ap_page`, `ap_filterData`, `sidenavExpanded`, …). `extract_auth_context_cue` folded **all** cookie value-hashes into `cookie_session_hashes`, so every pagination/filter change minted a new AuthContext, and thus a new discovered Principal. Measured: **47 distinct AuthContexts hashing all cookies vs 14 hashing only `token`** — roughly two-thirds of the fragmentation was pure UI-state pollution of the credential identity.

The cookie *names* are discarded after L2 (`cookie_session_hashes` is a flat hash tuple), so any classification must happen **inside `extract_auth_context_cue`**, at single-request granularity — it can see each cookie's name and value shape, but not cross-request behavior.

## Decision

- **Shape-first, include-biased classification.** A cookie contributes to the AuthContext identity unless its value is *confidently app-state*: empty, length < 8, a pure integer (`^-?\d+$`), or a boolean/sentinel (`true|false|yes|no|on|off|null`). This biases toward **inclusion** because the two error modes are asymmetric: wrongly *excluding* the real session cookie collapses a request to a different identity or to anonymous — a security-relevant **identity/merge error** — whereas wrongly *including* an app cookie merely re-introduces fragmentation for that one cookie (no correctness loss).
- **A new, looser opacity predicate — not `_high_entropy` from `artifacts.py`.** That predicate requires mixed upper+lower+digit and would reject `JSESSIONID` (hex) and `PHPSESSID` (lowercase-hex) — real session cookies. Cookie-opacity must accept hex and base64 alike.
- **Authoritative allowlist, engagement-global.** An optional engagement-config `session_cookie_names` (a single flat list, not per-host) pins the exact session cookie name(s); when set, identity is computed over **only** those listed cookies present on the request and the heuristic is bypassed. A *global* list is safe because cookies are host-scoped at request time — a request carries only its own host's cookies — so a union list naturally partitions across a multi-host engagement; the only failure is a same-name-different-role collision across hosts (rare), at which point the field can grow an optional per-host form without invalidating the flat default. This is legitimate tester configuration (like declared Principals, ADR-0012), not black-box seeding. Under-specifying (omitting a second auth cookie) is the tester's to fix, and it is visible as residual fragmentation.
- **JWT-shaped cookie ⇒ always a credential**, bypassing the heuristic (and decoded per ADR-0027).

## Considered Options

- **Hash all cookies (status quo)** — rejected: UI-state cookies fragment the credential identity (the 46-Principal bug).
- **Exclude-biased positive credential test** — rejected: maximal dedup, but a session cookie that fails the test is dropped → identity/merge error. The asymmetry of harms favors include-bias.
- **Name heuristic only** (`token|sess|sid|…`) — rejected as the primary mechanism: brittle to unconventional names; usable as a tiebreaker but not load-bearing.
- **`Set-Cookie` / `HttpOnly` observation** — deferred: the strongest signal, but the flag lives on a *response* header while the cue is built from the *request*, so it needs cross-request response-side correlation and new plumbing. A worthwhile future enhancement, layered on, not blocking.
- **Cross-request aggregation** (classify by stable-per-actor-vs-varies-per-request) — rejected for now: most accurate but a large architectural change; the single-request shape heuristic plus config override captures the bulk of the value.

## Consequences

- The 46 discovered Principals collapse toward ~14 from cookie-scoping alone (the rest are genuine `token` rotations, addressed by ADR-0027 / a later observed-response-identity tracer).
- **The cookie `auth_hash` changes** for cookie-auth requests, so existing graphs get new AuthContext/Principal nodes on re-ingest — consistent with the prior "re-ingest replaces, no migration" stance.
- `extract_auth_context_cue` gains a dependency on the engagement's `session_cookie_names` config — the classifier + config must be threaded into a function that today takes only the request.
- App-state cookies excluded from *identity* are no longer carried at all; whether any of them (e.g. `nw_creatorIdValue`) should surface as request-input *values* (leak-to-input) is a separate value-extraction concern, out of scope here.
- A request bearing only app-state cookies (and no other credential) now resolves to **anonymous** — correct, since UI state does not identify an actor.
