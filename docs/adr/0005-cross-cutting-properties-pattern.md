# Cross-cutting properties: seven fields on every fact, derivation edges, decay at query time

Every node and every edge in the graph carries the same seven fields — `source`, `source_id`, `confidence`, `confidence_method`, `first_seen`, `last_seen`, `ingested_at` — and inferences carry two more (`inferred_at`, `code_version`) plus explicit `DERIVED_FROM` edges to the observations that fed them. Provenance is properties, not a separate node; time is bitemporal-lite (event time + transaction time); confidence is set once and decayed by *consumers at query time*, never re-written in storage. Enforced by a `Provenanced` Pydantic mixin and matching Cypher property-existence constraints. See `ONTOLOGY.md` Step 4 for the full schema.

## Considered Options

- **Decay confidence in storage on a schedule** (rejected): would re-write potentially every node on every tick (write amplification, lost audit immutability) for the same query behavior consumers can compute on the fly from `confidence` and `last_seen`.
- **Provenance as a dedicated linked node** (rejected): doubles node count and adds a `HAS_PROVENANCE` clause to every query for an aesthetic gain. The *structured* part of provenance — lineage — is already carried by `DERIVED_FROM` edges where it actually pays off.
- **One combined `confidence` field, infer calibration from `source` strings** (rejected): forces every query that aggregates or filters on confidence to know the source-naming convention, and silently mixes calibrated and uncalibrated numbers under any `AVG`/`SUM`. An explicit `confidence_method` enum avoids both traps for the cost of one short string per node.
- **Full bitemporal (four clocks: valid-time start/end + transaction-time start/end)** (deferred): correct for systems with retroactive corrections, but black-box testing handles "we were wrong" through inference retraction, not temporal versioning. Bitemporal-lite (`first_seen`/`last_seen` + `ingested_at`) is enough until a query demands otherwise.

## Consequences

- Observations carry `confidence = 1.0` *only when parser validation was clean* — a parse that flagged ambiguity carries less. This is more truthful than a blanket "observations are facts" and lets the planner avoid building on a shaky foundation.
- Inference timestamps reflect the *evidence's* event time (min/max over contributing observations); the computation time lives in `inferred_at`. This makes "when was this Endpoint last hit?" answerable directly from `last_seen`.
- The Pydantic mixin guards the application boundary; the Cypher constraint guards the graph boundary. Between them, CLAUDE.md's "no exceptions" rule becomes actually true rather than aspirational.
- When templating heuristics, prompts, or inference algorithms change, `code_version` identifies which inferences are stale and re-derivable without forcing a full rebuild.
