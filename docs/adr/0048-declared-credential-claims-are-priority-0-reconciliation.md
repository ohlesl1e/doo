# Declared-credential identity claims are the priority-0 reconciliation signal; the sweep is retroactive

Declared↔discovered Principal reconciliation (ADR-0010) gains a **priority-0** step: the
discovered credential's `identity_claims` are matched against each declared
`AuthContext`'s own decoded `identity_claims` (persisted by the loader, and by the
auth-helper on rotation), walking the ADR-0030 claim-priority list with
`auth.identity_key` (ADR-0032) at the front — *walk-and-intersect, stop on the first
both-present disagreement*. `known_signals` drops to the opaque-token fallback role it
was designed for. The same match runs **retroactively** — at `engagement start` after
declared writes, and at flush after `reconcile_observed_identities` — sweeping existing
claim-keyed `discovered:{claim}:{value}` Principals and re-pointing `OF_PRINCIPAL` per
ADR-0010, so declare-after-ingest converges without manual Cypher.

## Why

`_match_declared_principal` only walked `sub` / identifying-header / `email` against
`known_signals`, while the discovered fallback walks the full ADR-0030 list — so a JWT
exposing only `_id` (or `uid`, `username`, …) could never reconcile onto a declared
Principal even when the declared token decoded the same value, and no path applied the
match retroactively. The declared credential *is* the ground truth the tester already
hands the loader; deriving the signal from it removes a hand-maintained config field
that drifts on rotation, and reusing the ADR-0030 walk makes "declared and discovered
reconcile via the same priority" (CONTEXT.md) literally true.

## Considered Options

- **Overload `known_signals.me_user_id`** — rejected: that field is ADR-0010's
  *response-body* `/me` signal, semantically distinct from a credential claim; conflating
  signal sources muddles the priority list, and the field is currently inert anyway.
- **New `known_signals.identity_claims: {claim: value}`** — rejected: makes the tester
  hand-copy a value out of a JWT they already supply via env-var; drifts on rotation
  unless the auth-helper rewrites config. Kept as a *deferred* escape hatch for opaque
  declared tokens where the tester knows the claim value out-of-band.
- **`auth.identity_key`-only match** — rejected: leaves the bug open for engagements that
  don't set the override; ADR-0032 frames `identity_key` as an override, not a
  prerequisite. The full-list walk fixes the whole class.
- **Retroactive sweep at flush only** — rejected: declare-after-ingest with no further
  ingestion would never reconcile. `engagement start` is the trigger; flush is
  belt-and-braces so a flush-upgraded synthetic is swept in the same pass.

## Consequences

- Declared `AuthContext` nodes carry `identity_claims` (renamed from `bearer_claims`,
  completing ADR-0027's rename on the declared side). The auth-helper decodes and writes
  them on rotation, plus `validity_window` from `exp`.
- The matcher's declared-AC query includes `status ∈ {active, expired}` — an expired AC's
  claims remain valid identity evidence for its Principal.
- `known_signals.jwt_sub` becomes redundant for JWT-bearing declared tokens (subsumed by
  priority-0 on `sub`); it stays for opaque-token + known-`sub` cases. No removal.
- Synthetic `discovered:{auth_hash}` Principals are out of the retroactive sweep's scope
  (no claim to compare); flush's existing synthetic→claim upgrade feeds them in.
- Depends on #103 for the `kind: cookie` case (loader cookie-JWT decode +
  `canonical_credential_value`); the `kind: bearer` case works standalone.
