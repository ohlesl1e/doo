# Discovered-Principal identity is a unified claim-keyed model across all sources

A discovered `Principal` is keyed on **`discovered:{claim}:{value}`** — source-agnostic — used by *both* the resolve-time credential cue and the flush-time observed-response path. Every identity an observation surfaces (from a bearer/cookie JWT, a response header, a self-endpoint body, or an SSO login exchange) is a **claim-tagged** `(claim_type, value)` pair; the *source* is provenance/confidence only. This supersedes the split `discovered:jwt:{claim}:{value}` (ADR-0027) and `discovered:observed:{signal}:{value}` (ADR-0029) namespaces and completes the cross-signal unification ADR-0029 deferred.

## Why

Identity arrives from several places — a JWT in a header or cookie (ADR-0027), an `X-User-*` header or `/me` body (ADR-0029), and (ADR-0031) an OIDC id_token or SAML assertion. The old model carried **one** `ObservedIdentity` per observation and used that single value for *both* re-keying synthetic Principals *and* aliasing — conflating two needs that pull opposite ways: **keying** must prefer an **account-unique** id (`sub`/`_id`/…), while **aliasing** wants *all* identities including the human-readable but person-level `email`. And the two key namespaces meant one actor presenting an access-token JWT `sub` *and* an id_token / `/me` `sub` fragmented into two Principals.

## Decision

- **Claim-tagged identity set.** An observation surfaces a *set* of `(claim_type, value)` identities. `claim_type` is the semantic id kind — `sub`, `uid`, `user_id`, `uuid`, `_id`, `username`, `uname`, `preferred_username`, `email`, `nameid` (with SAML Format). Source (cue / header / body / id_token / SAML) is kept for provenance + confidence, not for identity.
- **One claim-type priority**, spanning all sources: **account-unique first** — `sub` (issuer-scoped), `_id`, `uid`, `user_id`, `uuid`, `username`, `uname`, `preferred_username`, and a `persistent`/`emailAddress` SAML `NameID`; then **`email` last** (person-level); a **`transient` NameID is never** a key (per-session, like a per-request id).
- **Unified key** `discovered:{claim}:{value}`, with `sub` issuer-scoped (`discovered:sub:{iss}:{value}`, ADR-0028/PR#38). The **same** scheme is produced at resolve-time (credential cue) and flush-time (observed), so they **converge via the identity-key MERGE** — no explicit cross-path merge.
- **Keying** a discovered Principal: the single highest-priority *account-unique* claim present. Conflicting values for the top claim on one AuthContext → **abstain** (stay synthetic; never merge on ambiguity).
- **Aliasing** (ADR-0029, retained): record **all** of an AuthContext's claim values as `observed_aliases` on the resolved Principal — enrichment that never re-keys or merges, so `email` is always surfaced as a label even when an account-unique claim is the key.
- **Merge-safety invariant** (unchanged in spirit): key values are account-unique (issuer-scoped for `sub`); `email` and `transient NameID` never key; declared and already-keyed Principals are never re-keyed by a weaker signal.

## Considered Options

- **Keep split namespaces (`discovered:jwt:*` + `discovered:observed:*`)** — rejected: one actor with an access-token JWT *and* an id_token/`/me` `sub` stays two Principals; the model can't express several simultaneous identities.
- **Single value + separate alias list** — rejected: bifurcates the model and still can't hold several account-unique claims at once (needed for SSO).
- **Unified claim-keyed set (chosen)** — one priority, one key scheme, source as provenance; keying and aliasing cleanly separated.

## Consequences

- One Principal per real actor across bearer/cookie JWT, id_token, `/userinfo`, and `/me` — the cross-signal unification deferred in ADR-0029.
- `email` is now strictly a **last-resort key and always an alias** (person-level; one email can own multiple accounts), resolving the deferred email-last fix.
- **Amends ADR-0027 and ADR-0029**: their `discovered:jwt:*` / `discovered:observed:*` keys become `discovered:{claim}:{value}`. Existing graphs are replaced by re-ingest; no automated migration.
- The residual: one actor presenting *different claim types* across credentials with no shared value (e.g. `sub:A` on one host, `_id:B` on another) stays honestly fragmented — unavoidable black-box; aliasing surfaces what evidence exists.
