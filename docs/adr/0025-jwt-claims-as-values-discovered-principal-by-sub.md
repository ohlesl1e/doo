# JWT claims are extracted as values; discovered Principals are keyed on the JWT `sub`, not the token hash

When the JWT detector fires, the token is decoded (unverified) and its **identity claims are emitted as value candidates** (`sub` → `identifier`, `email` → `email`) alongside the hash-only `secret` candidate for the whole token. And a **discovered `Principal`'s identity is keyed on its stable signal** — the JWT `sub` when present — rather than the per-token credential hash, so a user's reissued tokens collapse to one Principal.

## Why

Re-ingesting a real 72 MB HAR produced **48 `Principal`s, 46 of them `discovered, unmerged=true`** — for what is realistically one or two undeclared users. The cause: `discovered_principal_identity_key()` is `f"discovered:{auth_hash}"`, keyed on `sha256("bearer:" || full_token)`. A JWT reissued each request (new `iat`/`exp`/signature → new token → new `auth_hash`) mints a brand-new discovered Principal every time. Meanwhile the AuthContext already carries `bearer_claims` (the decoded `sub`) — the stable per-user identity is decoded and sitting right there, simply unused for the Principal's identity.

Two distinct gaps, both centred on the JWT `sub`:

1. The token's **claims are valuable values** — a `sub` (a user id) that leaks in a response token and is later sent as a request input is a textbook leak-to-input pivot — but they were hashed away with the token, never extracted.
2. The **discovered Principal identity is volatile** — keyed on the per-request token rather than the stable user the token represents.

## Decision

- **(A) Extract JWT claims as values.** On JWT detection, decode unverified (reuse the path that T4 / ADR-0010 already uses for reconciliation) and emit its identity claims as value candidates — `sub` → `identifier`, `email` → `email`, and other known identity claims. The token itself remains a hash-only `secret` candidate (the signature is the secret; the claims are not).
- **(B) Key the discovered Principal on its stable signal.** `discovered_principal_identity_key` becomes `discovered:jwt_sub:{sub}` when a `sub` is present, falling back to `discovered:{auth_hash}` only when there is no extractable stable signal. This amends ADR-0010's synthetic-fallback (step 5) to prefer the same `sub` the reconciliation priority list already uses for *declared* matching.
- **AuthContexts stay per-token.** Their `auth_hash` remains over the full token, so each reissued credential is its own faithful observation. The differing validity windows (`iat`/`exp`) are *signal* — a gap or shift in token timestamps can reveal session boundaries or testing windows — and collapsing them would destroy that information.

## Considered Options

- **Keep the per-token discovered Principal** (rejected): 46 Principals for one user makes per-user coverage ("which endpoints did this actor reach?") unanswerable.
- **Dedup AuthContexts too** (rejected): a reissued JWT *is* a distinct credential snapshot; the validity-window differences are testing-relevant signal, so the AuthContext multiplicity is faithful, not noise.
- **Discard the JWT claims as part of the secret** (rejected): the claims are the highest-signal identifiers in an authenticated capture; hashing them away forfeits the leak-to-input pivots they enable.

## Consequences

- The 46 discovered Principals collapse to ~1–2 per real user; per-user coverage and authz-boundary reasoning become tractable.
- A user's `sub` becomes a first-class `ObservedValue` — the `sub`-leaks-into-input pivot (ADR-0009's "what to test next") is captured for authenticated traffic.
- **AuthContexts remain per-token**, each with its validity window, evidencing its one Principal; a Principal has many AuthContexts (consistent with ADR-0010 / CONTEXT.md).
- A credential with **no extractable stable signal** (opaque/non-JWT bearer) still falls back to a per-credential discovered Principal (`auth_hash`) — unchanged behaviour for that case.
- Amends ADR-0010's reconciliation: the synthetic fallback now reconciles undeclared users by `sub`, mirroring the declared path.
- Existing graphs (discovered Principals keyed on `auth_hash`) are replaced by re-ingest; no automated migration.
