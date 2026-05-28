# Asset and ObservedValue coexist as distinct nodes, linked by SAME_VALUE_AS

Both `Asset` and `ObservedValue` are inference-layer nodes that can refer to the same underlying string — a leaked internal hostname is naturally both an `ObservedValue` of kind `hostname` *and* an `Asset` of kind `internal_hostname`. We keep them as **two distinct node types**, with an optional `(Asset)-[:SAME_VALUE_AS]->(ObservedValue)` edge between them when the value matches. They are *not* unified into one node type, and *not* modelled as a strict promotion chain.

The semantic split is real and the queries differ:

- `ObservedValue` answers "this value appeared across contexts" — used by the C3 leak-to-input pivot (`ResponseArtifact → CONTAINS_VALUE → ObservedValue ← SENT_VALUE ← RequestObservation`).
- `Asset` answers "we believe this represents a backend resource worth testing" — used by C6 lead surfacing ("assets with strong evidence not yet reached as `Host`/`Endpoint`").

Each query stays one node-type cleaner; the optional `SAME_VALUE_AS` edge lets queries pivot when useful (e.g. "is this Asset's value ever sent as a request parameter elsewhere?" walks `Asset → SAME_VALUE_AS → ObservedValue → SENT_VALUE`).

## Considered Options

- **Unify — fold `Asset` into `ObservedValue` with an `is_lead: bool` flag** (rejected): drops one node type, but trades a node-type filter for a property filter without simplifying queries. Would also partially undo ADR-0001's named example pair (`ResponseArtifact → Asset`).
- **Two-step inference — `Asset PROMOTED_FROM ObservedValue`** (rejected): the more principled hierarchy, but adds a node hop on every asset query with no current payoff. Reconsider if a future query genuinely needs to traverse the chain.

## Consequences

- `Asset` and `ObservedValue` share evidence: both have `DERIVED_FROM` edges to the same `ResponseArtifact`s when they refer to the same string. The overlap is bounded — only kinds like `hostname` / `url` are genuine candidates for both, and within those `Asset` is specifically the *internal / unreached* subset.
- The merge-via-re-pointing mechanic from ADR-0010 (Principal) applies to both `Asset` and `Tenant`: when alternate identifiers reveal sameness, edges move to the surviving node and the orphan is marked `retracted`.
- ADR-0001 still names `ResponseArtifact → Asset` as an example observation/inference pair; that example remains correct. ADR-0009 separately introduces `ObservedValue` for the cross-context-value concern. The two inferences coexist with overlapping but non-identical scope.
