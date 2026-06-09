# Slice-3 TrustBoundary inference: capability + tenant only; boundary tests are authz replays of evidence

`TrustBoundary` is the ontology piece slice 3 pulls in (ADR-0002 made it a node;
this ADR decides what gets *inferred*, at what granularity, and how a
boundary-targeting `TestCase` finds a concrete endpoint). Governed by the
grill-queue rule: build it with the planner so granularity matches a real
consumer — do not mint boundary nodes nothing tests.

## A boundary test gets its endpoint from the boundary's evidence

A `TestCase` that `TARGETS_BOUNDARY` cannot also target an `Endpoint` (the
three-way XOR, ADR-0007). The concrete endpoint a boundary test sends to is **read
from the boundary's `DERIVED_FROM` evidencing observation at propose time**, not
from a target edge. A boundary test *is an authz replay* (consistent with the
ADR-0037 payload model): take an observation on one side of the boundary and
replay it under the other side (`auth_context_ref` = the attacker side); the
payload is empty (sentinel) or an observed value. The boundary node stays an
abstract pair; no new edge type, XOR preserved.

## Inferred kinds: capability + tenant; role/ownership deferred

- **capability (`scope` / `mfa` / `freshness`)** — **required**: C4 is defined on
  it. Drawn between two `AuthContext`s *of the same Principal* that show a **claim
  delta** in the already-decoded `bearer_claims` (JWT `scope` / `acr` / `amr` /
  `auth_time`, ADR-0025). Structured, fairly high confidence.
- **`tenant`** — **included**: cross-tenant IDOR/BOLA is the planner's
  highest-value lead, `Tenant` nodes already exist (ADR-0008), and Findings attach
  to the tenant boundary. Drawn between `Tenant`s.
- **`role` / `ownership` (between `Principal`s)** — **deferred.** C2/C2b already
  surface principal-differential access at the endpoint/parameter level, and a
  C2/C2b proposal can `TARGETS_ENDPOINT` / `TARGETS_PARAMETER` directly. Minting
  `Principal`-pair boundary nodes would duplicate the C2 signal with no slice-3
  consumer that needs the *node* (Findings and C5 are slice 4). The boundary node
  earns its place only where the testable thing is genuinely boundary-shaped and
  spans endpoints — capability (C4) and tenant (Findings) clear that bar; role /
  ownership does not, in slice 3.

The ontology already supports all kinds; this defers *inferring* role/ownership,
not modelling them. Add them when a node-level consumer (Findings, C5) needs them.

## Granularity controls (avoid an N^2 explosion)

- **capability**: only between same-`Principal` `AuthContext`s with a claim delta
  — naturally tiny.
- **tenant**: only between tenant-pairs that **share ≥1 `Endpoint`** (both have
  observations on the same template) — exactly where cross-tenant tests apply;
  bounds pair count to the real surface. One undirected node per unordered pair;
  test direction lives in the proposal.

## Write-path, at flush

Materialised on the L3 write-path at the per-drain flush settle point (ADR-0022),
like `Endpoint` / `Tenant` inference — *not* a query-time derivation. It must be a
node so `TestCase`s / `Finding`s can attach (ADR-0002). Carries the standard
provenance / confidence / `DERIVED_FROM` fields.

## Considered Options

- **Infer all kinds now (incl. role/ownership)** (rejected): duplicates the C2/C2b
  signal as `Principal`-pair nodes with no slice-3 node-level consumer.
- **Boundary node carries / is drawn per endpoint** (rejected): explodes node
  count (pair × endpoint) and is unnecessary once the endpoint is read from
  evidence at propose time.
- **Add an endpoint edge to boundary `TestCase`s** (rejected): breaks the
  ADR-0007 target XOR; the evidence-endpoint replay model needs no new edge.
