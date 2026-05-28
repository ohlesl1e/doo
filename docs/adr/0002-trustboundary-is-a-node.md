# TrustBoundary is a node, not an edge

A `TrustBoundary` (a line across which authorization is expected to change) is modelled as a node, even though a boundary-between-two-things reads naturally as an edge. The decisive reason is a Neo4j constraint: a relationship cannot be an endpoint of another relationship, so if `TrustBoundary` were an edge we could not attach a `Finding` to a violated boundary, point a `TestCase` at one as its target, or run "boundaries with no boundary-violation test" coverage queries. A boundary is also a *dimension* (one "tenant" boundary spans many Principal-pairs), so a node avoids the O(n²) duplicate-edge explosion.

## Considered Options

- **Labeled edge between Principals/AuthContexts** (rejected): more natural for traversal, but cannot have other nodes attached to it and would force reification anyway. If you are reading this because an edge seems cleaner — it isn't; this was deliberate.
