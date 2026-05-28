# ObservedValue is a promoted inference node for cross-context value matching

When a value appears in a `ResponseArtifact` and later as an input `Parameter` on a different `Endpoint`, that is the leak-to-input pivot — the canonical black-box "what to test next" signal. To answer C3 (`ONTOLOGY.md` Step 6) as a single graph traversal rather than a property scan, *interesting* values are promoted to a first-class `ObservedValue` inference node. Junk strings — HTML fragments, timestamps, common words, "0" — stay inline on the originating observation. Only values that match a known shape (UUID, URL, email, hostname, JWT, etc.) or appear at multiplicity ≥2 across observations are promoted.

The node carries `value_hash` (SHA-256 over the normalized form, the dedup key), `value_preview` (first 32 chars), `normalized_value`, `kind ∈ {identifier, url, email, hostname, token, secret, other}`, plus the cross-cutting fields. New edges: `(RequestObservation) -[:YIELDED]-> (ResponseArtifact)`, `(ResponseArtifact) -[:CONTAINS_VALUE]-> (ObservedValue)`, `(RequestObservation) -[:SENT_VALUE { parameter_name }]-> (ObservedValue)`, and the usual `(ObservedValue) -[:DERIVED_FROM]-> <observation>`. Promotion is deterministic-first L2 enrichment; the LLM may propose ambiguous cases at lower starting confidence (the same entity-resolution role already sanctioned in L3).

**Secrets** (`kind ∈ {token, secret}` — JWTs, API keys, high-entropy credentials) are stored as `value_hash` + length + first-N-chars only. The full value lives only in the originating observation in object storage, accessed explicitly. The graph is not a credential store.

## Considered Options

- **Inline value matching only — no node** (rejected): every cross-context query becomes a property-equality scan, and there is no place to attach provenance, confidence, retraction, or `Finding`s to a value.
- **Promote every observed string** (rejected): the graph would drown in HTML fragments, timestamps, "0", common dictionary words. Promotion is the filter that keeps the model tractable.

## Consequences

- A value seen for the first time (single observation) is promoted at low confidence on shape signal alone; later observations raise confidence via multiplicity — the same trick path templating uses (ADR-0004).
- `value_hash` is computed after `normalized_value` (lowercased host, decoded percent-encoding, etc.), so unicode-equivalent or case-equivalent values dedupe; visually-distinct values do not.
- `kind` is a controlled enum, letting queries scope to a class of pivot ("show every `url` that appeared in a response and got sent to another endpoint").
- C3 reduces to a single bi-directional traversal through `ObservedValue` with `WHERE req_from <> req_to` as the only domain filter.
- The `RequestObservation -[:YIELDED]-> ResponseArtifact` edge — needed anyway, but only formalised by this gap — gives every ResponseArtifact an explicit producing observation, enabling lineage queries from any leaked value back to the exact request that surfaced it.
