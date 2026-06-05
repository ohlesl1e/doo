# Discovered Principals are upgraded from observed-response identity at flush (headers, self-endpoint bodies)

When a credential carries no decodable identity claim (an opaque, non-JWT token), a discovered `Principal` still keys on the per-token `auth_hash` synthetic fallback (ADR-0027), so one user's reissued opaque tokens fragment into a Principal per token. This ADR adds the **observed-response** identity signals ADR-0010 anticipated — an identity **response header**, or a **self-endpoint** response body — correlated back to the request's `AuthContext` at **flush time**, to collapse those fragments onto the real actor. This is a **revisable-identity upgrade** of low-confidence synthetic Principals, never a merge of already-distinct ones.

## Why

ADR-0027 collapses a user's reissued credentials when a stable claim is decodable (JWT `sub`/`uid`/`_id`/email). For a genuinely **opaque** rotating credential there is nothing to key on, so the residual is one discovered Principal per token (e.g. the real capture's opaque case before its tokens turned out to be JWTs). ADR-0010's identity priority list already names the fallbacks — "observed user-id from `/me`/`whoami` responses, stable `X-User-*` header, email tied to the AuthContext" — but only the credential-side (JWT) level was built; `resolve.py` explicitly stubs the observed-response step.

## Decision

- **Flush-time, cross-observation inference.** The identifying response often arrives *after* other requests by the same credential, so this runs at **flush** (like deferred re-templating, ADR-0022, and promotion, ADR-0023), not at per-request `resolve_auth_context`.
- **Merge-safe signals only, precision-ordered.** The observed value must be **globally unique per user** (same safety property as ADR-0027):
  1. **Identity response headers** — a small set of conventional names (`X-User-Id`, `X-User`, `X-Username`, `X-Authenticated-User`, `X-Account-Id`). Server-asserted, unambiguous.
  2. **Self-endpoint response body** — a request whose path matches a generic self pattern (`/me`, `/whoami`, `/profile`, `/account`, `/session`, `/user/current`) yielding an identity claim (`email`, then `sub`/`_id`/`uid`/`user_id`), reusing ADR-0027's claim-priority set.
- **Bind observed identity ↔ the eliciting request's `AuthContext`** (its `auth_hash`). At flush, a discovered Principal that is **synthetic (opaque, `unmerged=true`)** and whose AuthContext(s) carry an observed identity is **re-pointed** onto a Principal keyed `discovered:observed:{signal}:{value}`. All AuthContexts sharing one observed identity collapse onto one Principal — implementing ADR-0010's "merge synthetics = `OF_PRINCIPAL` edge re-pointing; the orphan is marked retracted, not deleted."
- **Merge safety is the invariant.** Only **upgrade** low-confidence synthetic (`unmerged`) Principals; never merge two already-declared/confident Principals; require a globally-unique-per-user value. Confidence ordering: response-header > self-endpoint-body > synthetic, with provenance (which signal, which observation) recorded.
- **Observed identities are also attached as aliases** (amendment). Beyond *re-keying* synthetic Principals, every (non-anonymous) Principal an observed identity resolves to records it as a known **alias** — an `observed_aliases` set on the node (`{signal}={value}`) — regardless of the Principal's primary-key tier. This is **enrichment, not re-keying**: it never changes the `identity_key` and never merges two Principals, so it carries far less risk than re-keying and applies to JWT-keyed and declared Principals too. A JWT-`_id` Principal thus gains its `/me` **email** alias (so the actor reads as `admin@gmail.com`, not just an ObjectId). Aliasing uses the same per-AuthContext chooser (conflict → abstain) and is idempotent (set semantics).
- **Black-box-legal.** The header names and self-endpoint path patterns are **generic conventions**, not target-specific seeding — the same standing we give to recognising JWT structure. A tester MAY additionally declare `known_signals.me_user_id` / `headers` / `email` (already in the config) for the declared-reconciliation path.

## Considered Options

- **Per-request resolution** — rejected: the identifying response can post-date earlier requests by the same credential; only a flush-time pass sees the whole picture.
- **Self-endpoint body heuristics for *any* id field** — rejected as too eager: picking an arbitrary body field (e.g. a shared tenant id) risks the cardinal **false merge** of two users. Restricted to globally-unique-per-user claims under a self-endpoint path.
- **Unify by re-keying with ADR-0027's `discovered:jwt:*` namespace** (key purely on `(type, value)` regardless of where the identity was seen) — still deferred: it would re-key existing JWT identities and widen the merge surface. The lighter **aliasing** above gives the cross-signal *visibility* (a Principal shows all its observed identifiers) without the riskier identity-merge; full re-key unification remains a later, deliberate step.

## Consequences

- Opaque, non-JWT rotating credentials collapse to the real actor count, making per-user coverage and authorization-boundary reasoning tractable for cookie/opaque-token targets — not just JWT ones.
- A discovered Principal's identity becomes genuinely **revisable**: a synthetic node is upgraded (and its siblings merged) when a stronger observed signal appears, with confidence and provenance reflecting the source.
- A JWT-keyed (or declared) Principal now **surfaces its observed identifiers** (e.g. the `/me` email) as `observed_aliases`, so an actor known only by an opaque ObjectId becomes human-readable, and the cross-signal evidence is visible on one node.
- **Gap (accepted):** full *re-key* unification — collapsing a JWT-keyed Principal and a same-value observed Principal into a single node — is still deferred; aliasing gives the visibility without the merge.
- Requires response-side capture the graph already records (headers, bodies via `BlobRef`); the flush pass reads observations + their AuthContexts. Larger than a single tracer — to be sliced via the normal PRD → issues flow.
- Existing graphs are replaced by re-ingest; no automated migration.
