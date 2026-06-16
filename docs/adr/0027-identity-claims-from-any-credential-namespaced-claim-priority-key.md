# Decode identity claims from any session credential; key the discovered Principal on a namespaced claim-priority list

JWT claims are decoded from **whatever carries the session credential** — the bearer `Authorization` header *or* a session cookie — into a single source-agnostic `identity_claims` dict on the cue. A discovered `Principal` is keyed on a **namespaced claim-priority list**: `discovered:jwt:{claim}:{value}` over the first present of `sub → uid → user_id → uuid → _id → username → uname → preferred_username → email`. This amends ADR-0025 (which keyed on `sub` only, from the bearer header only) and refines ADR-0010's level-1 reconciliation signal.

## Why

ADR-0025 keyed discovered Principals on the JWT `sub` to collapse reissued tokens — but only for **bearer** tokens, and only when `sub` is present. The 74 MB cookie-auth capture (ADR-0026) exposed both limits: the credential was a **cookie**, never decoded (only the bearer header fed `_decode_jwt_claims`); and real apps key users on claims other than `sub` (`uid`, `_id`, `username`, …). `bearer_claims` is also a misnomer the moment a cookie JWT exists.

## Decision

- **Generalize `bearer_claims` → `identity_claims`.** Populated from the primary decodable credential, precedence **bearer `Authorization` JWT first, else the session-cookie JWT** (the session cookie identified per ADR-0026). One source-agnostic dict, because the *use* — Principal identity + reconciliation — does not depend on where the JWT rode. `resolve.py` keys on `identity_claims`.
- **Namespaced claim-priority Principal key.** `discovered:jwt:{claim}:{value}` over the first present of `sub → uid → user_id → uuid → _id → username → uname → preferred_username → email`. `email` is lowercased (case-insensitive in practice) to avoid case fragmentation; the others are kept raw. Falls back to `discovered:{auth_hash}` (synthetic, per ADR-0010 step 5) only when **no** listed claim is present.
- **Same set broadens the value-extraction claim map (#22 / ADR-0025(A)).** Response-body JWT claims in this set emit `ObservedValue` candidates — all → `identifier` except `email` → `email`.
- **AuthContexts stay per-token** (unchanged from ADR-0025): a reissued credential is its own faithful snapshot; only the Principal collapses.

### Why namespacing the key by claim is safe (and a priority list is too)

Namespacing (`{claim}:{value}`, not a bare `{value}`) means a user whose tokens expose *different* claims will fragment — but that is **honest**: without a shared claim we cannot prove two credentials are the same actor. The deeper safety property:

> **Any claim in the list is ≥ the synthetic fallback.** The synthetic fallback already fragments per-token, so keying on *any* claim is never *worse* for fragmentation (worst case is per-token, i.e. synthetic-equivalent), and it *collapses* whenever the claim is stable per user. The only residual hazard is a **wrong merge**, which requires two distinct users to share a claim *value* — and every claim in the list is globally unique per user.

This is why the list can be generous (`uuid`, `uname`, …) without risk: each added level is monotonically non-harmful for fragmentation and merge-safe on unique values.

## Considered Options

- **Keep `sub`-only (ADR-0025)** — rejected: no collapse at all for the (common) apps that key users on `uid`/`_id`/`username`/`email` instead of `sub`, or that carry the JWT in a cookie.
- **Unnamespaced priority key** (`discovered:jwt_id:{value}`) — rejected: risks merging two users whose different claim spaces collide on a value; namespacing costs nothing and removes the hazard.
- **Parallel `cookie_claims` field** — rejected: two fields plus a merge rule wherever claims are read; the consumer only ever wants "the identity claims for this credential," so one generalized field is cleaner.

## Consequences

- A user authenticated by a JWT cookie now collapses to one discovered Principal (the gap ADR-0025 left for cookie auth).
- `identity_claims` replaces `bearer_claims` across the cue, `resolve.py`, and tests (a rename, internal type).
- A claim-priority key collapses cleanly when a user's tokens consistently expose the same highest-priority claim, and fragments (honestly) when claim presence varies across their tokens — never wrongly merging.
- **Out of scope (separate tracer):** observed-response identity reconciliation — a user-id seen in a `/me`/`/whoami` response body or a stable `X-User-*` header, correlated back to the AuthContext (ADR-0010 levels 2–3). This is what would collapse an **opaque, non-JWT** rotating credential (the ~13-Principal residual in the capture), and it is a different mechanism (response-side correlation, value-extraction plumbing).
- Existing graphs are replaced by re-ingest; no automated migration.

## Amendment (#103) — declared-side cookie-JWT decode

The loader's JWT decode extends to `kind == "cookie"` (previously bearer-only) and runs over the **canonical credential value** (percent-decoded + DQUOTE-stripped, ADR-0026 amendment), so a declared cookie-JWT contributes its `identity_claims` to the priority-0 reconciliation walk (ADR-0048) the same way a bearer token does. The wire-form raw stays un-normalised in the secret store / rotation file.
