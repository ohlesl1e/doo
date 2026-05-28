# Tenant is a first-class inference node; tenant-kind TrustBoundaries draw between Tenants

In black-box mode we **infer** tenants from observations — values appearing in `/orgs/{org_id}` URL positions, `X-Org-Id` headers, JWT `org` claims surfaced as `AuthContext` properties, response-body fields. `Tenant` is therefore an inference-layer node (like `Asset`, `ParameterSemantic`, `TrustBoundary`), with `DERIVED_FROM` edges to its evidence and the standard cross-cutting fields. A `Principal` belongs to zero or more `Tenant`s via `(Principal)-[:OF_TENANT]->(Tenant)`; cardinality is **many-to-many** (multi-org membership is common). Findings about tenant-pair leakage ("tenant 42's data was readable from tenant 43") attach naturally to the Tenant nodes; the C7 cross-tenant coverage query is a single `collect(DISTINCT t)` traversal.

This **refines ADR-0002.** That ADR established `TrustBoundary` as a node and answered Q2 with "drawn between Principals (identity tier) or AuthContexts (capability tier)." Now that `Tenant` exists, the cleaner model is: `TrustBoundary BETWEEN` is **polymorphic by `kind`** —

- `kind = tenant` → between `Tenant`s
- `kind = role` / `ownership` → between `Principal`s
- capability tier (`scope`, `mfa`, `freshness`) → between `AuthContext`s of one Principal

The original Q2 answer pre-dated `Tenant`'s existence; this is the answer it should have given once Tenant was modeled.

## Considered Options

- **`Principal.tenant_id` as a flat property** (rejected): no place for provenance, confidence, or revisable inference on the "Principal is in this tenant" claim; findings about tenants have nowhere to attach; multi-tenant membership is awkward to express as a scalar property.
- **Tenant only implicit, via `TrustBoundary {kind:"tenant"}` between `Principal`s** (rejected): sneaks tenants into the model without giving them an identity to be wrong about, retract, or attach evidence to. A tenant inferred from one URL position and a JWT claim is a real entity, not just a boundary's anonymous side.

## Consequences

- `Tenant` is revisable. A wrong inference ("we thought these two Principals were in different Tenants but the JWT claim shows they share one") is corrected by re-grouping `OF_TENANT` edges, with the underlying `ResponseArtifact` / `Parameter` / `AuthContext` observations untouched — the same pattern ADR-0001 set up.
- `TrustBoundary BETWEEN` is polymorphic by `kind`. Query patterns and the eventual invariants (Step 5) will need per-`kind` expectations about what type sits on each end.
- Scope-tenant intersection ("test only within tenant 42") is a property on the `Scope` node (extending gap #1) referencing the Tenant by id — *not* a new `Scope -> Tenant` edge.
