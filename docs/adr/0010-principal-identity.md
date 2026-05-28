# Principal identity: declared by label, discovered by signal, reconciled by match

`Principal` is an inference-layer node with **revisable** identity (same pattern as `Endpoint` / ADR-0004), but in **two tiers** because two populations of Principals coexist in any engagement. **Declared Principals** (the ones we control) carry a manual label set at engagement config with `source = "manual"` and `confidence = 1.0`. **Discovered Principals** (actors observed in passive traffic) are identified by the strongest stable signal available, in priority order: (1) JWT `sub` claim, (2) observed user-id from `/me` / `/whoami` introspection responses, (3) stable identifying header (`X-User-Id`, etc.), (4) email tied to the AuthContext, (5) a deterministic synthetic fallback seeded from the first observed AuthContext's hash, low confidence, flagged `unmerged`.

Declared and discovered **reconcile via the same priority list** — when a discovered signal matches a declared Principal's known one, the discovered `AuthContext` attaches to the declared Principal rather than creating a phantom twin. Merging two synthetics later proven the same is **`OF_PRINCIPAL` edge re-pointing**, not node deletion: edges move to the surviving Principal, the orphan is marked `retracted` with its `DERIVED_FROM` lineage preserved (per ADR-0001).

**Anonymous is a singleton per Engagement.** All unauthenticated requests `USED_AUTH` → one anonymous `AuthContext` → one anonymous `Principal`. Anonymity by definition lacks identity; synthesizing differentiated anonymous Principals (e.g., one per IP) would invent identity we don't actually have.

## Considered Options

- **Always-distinct synthetic Principals per AuthContext** (rejected): two AuthContexts of the same actor (token rotation, multi-device session) would land as two Principals, and cross-Principal coverage queries like C2 ("hit as A but not as B") would treat the same actor as two identities, producing false coverage gaps.
- **Single-tier identity — treat declared and discovered the same** (rejected): no way to mark the ground-truth identity we have for Principals we set up; reconciliation between observed signals and known setup becomes ad hoc.
- **Differentiated anonymous Principals (per-IP or per-session)** (rejected): a fabrication. Anonymity is one actor by definition; differentiation along an IP axis belongs in a separate dimension, not Principal.

## Consequences

- The merge operation is a graph mutation the application must support: move `OF_PRINCIPAL` edges from orphan to survivor, set the orphan's `status = "retracted"`, append a provenance event. Step 5 invariants enforce that every `AuthContext` has exactly one `OF_PRINCIPAL` edge, including across merges.
- A Principal's `first_seen` / `last_seen` are the `min`/`max` over its AuthContexts' evidence (per Step 4); merging two Principals updates these naturally.
- The synthetic-fallback id is deterministic over the first AuthContext's `auth_hash`, so re-ingesting the same traffic produces the same synthetic Principal — needed for replay and audit reproducibility.
- Coverage queries that group by Principal benefit directly: token rotation no longer splits one actor into many, so "endpoints hit as A but not as B" answers what the user actually asked.
