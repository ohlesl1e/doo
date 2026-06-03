# Retire `ResponseArtifact`; promote values to `ObservedValue` on cross-context signal

Response extraction does not mint a node per extracted value. The raw `ResponseArtifact` node — one per identifier / URL / email / hostname / secret found in a response — is retired. Instead, each `RequestObservation` records its extracted **value occurrences inline**, and a deferred **promotion pass** mints an `ObservedValue` node only for values that show **cross-context signal**. Diagnostic extractions (technology fingerprint, error-message excerpt) become inline properties of the observation.

## Why

T6 created a `ResponseArtifact` node for every extractor hit. A real 72 MB / 3,961-request Burp HAR produced **277,041 `ResponseArtifact` nodes** — ~70 per request, 98.5% of the graph — and they dominated a ~32-minute drain (each artifact is its own L3 commit: semantic-key `SETNX` + `MERGE` + `YIELDED` edge + `l3-event`).

Almost all of that volume is low-signal: every `id`/`*_id` field and every UUID in a paginated response becomes a node, whether or not it is ever interesting. The values that matter for black-box testing are the ones with **cross-context signal** — above all the **leak-to-input pivot** (a value that appears in a response *and* is accepted as a request input elsewhere; ADR-0009's "what to test next" signal), and secondarily values seen at multiplicity ≥2. Eagerly node-ifying every shape-match is the wrong grain: the pivot is defined *across* observations, so it cannot be known at the moment of a single extraction.

ADR-0009 already names `ObservedValue` as the *promoted, deduplicated* value node and says junk "stays inline." This ADR finishes that model and draws the consequence T6 didn't: if values live on `ObservedValue`, the per-extraction `ResponseArtifact` node has no remaining job.

## Decision

**Retire the `ResponseArtifact` node.** Its responsibilities split:

1. **Diagnostics → inline observation properties.** `Server`/`X-Powered-By` fingerprints and 5xx error-body excerpts are one-per-response and never cross-context (CONTEXT.md: "a technology fingerprint stays a ResponseArtifact forever — never promoted"). They become properties on the `RequestObservation` (`server_fingerprint`, `error_excerpt`), not nodes.

2. **Values → `ObservedValue`, promoted on signal.** Each `RequestObservation` records its extracted **candidate occurrences inline**, each tagged with a **role**:
   - `output` — values extracted from the response body/headers
   - `input` — values *sent* as request parameters (path/query/body), hashed the same way

   A candidate is `(value_hash, kind, location, role)` plus the value for non-secret kinds; secret kinds carry `value_hash` + length + preview only (ADR-0015). These are arrays on one node, not N nodes.

3. **Promotion pass at flush (ADR-0022 seam).** Graph-wide, the pass aggregates candidate occurrences by `value_hash` and mints an `ObservedValue` (identity `(engagement_id, value_hash)`) for any value where **any** signal fires:
   - **leak-to-input** — occurs as both `output` and `input` → `(:RequestObservation)-[:YIELDED_VALUE {location, extractor}]->(:ObservedValue)` and `(:RequestObservation)-[:SENT_VALUE {parameter_name}]->(:ObservedValue)`
   - **multiplicity ≥2** — occurs in ≥2 observations
   - **shape-allowlist** — `kind ∈ {secret, token, internal_hostname, email}` promote on shape alone, even at a single occurrence (rare and inherently interesting)

   High-cardinality identifiers (list-item UUIDs/ints) promote *only* on signal; a single-occurrence list id stays an inline candidate.

**Retention is lossless and promotion is retroactive + re-runnable.** Nothing is discarded at extraction time: the full response body is in object storage, and every extracted value is retained as an inline candidate. Promotion is a *view* recomputed at flush — when a value later crosses a threshold (a second occurrence, or a matching request input), it is promoted then, wiring edges to all observations that contained it, including past ones. Thresholds and the extractor set are therefore tunable after the fact: lower a threshold or add a `_v2` extractor and re-run the pass (or re-extract from blobs) to promote retroactively, no re-ingest.

## Considered Options

- **Keep `ResponseArtifact` per extraction; add `ObservedValue` dedup on top** (rejected): dedup collapses repeated values *across* responses, but a paginated list is 100 genuinely-distinct UUIDs — the per-extraction node count (the actual problem) is unchanged. Still ~277k nodes.
- **Keep `ResponseArtifact` but only materialise it for promoted extractions** (rejected): makes it rare, but then `ResponseArtifact` and `ObservedValue` are both "a promoted value node" — two names for one concept. Muddier than retiring it.
- **Promote on multiplicity only; defer leak-to-input to slice 2** (rejected): leak-to-input is the core security signal and the reason `ObservedValue` exists. Indexing request inputs now is cheap (the params are already parsed), and it makes leak-to-input fall out of the same aggregation as multiplicity. Deferring would ship a half-built index and force a later migration. Only the *coverage query* that surfaces pivots (C3) is genuinely slice-2; the underlying graph is built now.
- **Side-index candidates in Redis instead of inline on the observation** (deferred): faster to aggregate and keeps observation nodes small, but adds a store and detaches provenance. Start in-graph (candidates inline, aggregated at flush); move to a side index only if the flush aggregation becomes a bottleneck.

## Consequences

- **Volume collapses.** The 72 MB HAR's 277k `ResponseArtifact`s become: one `server_fingerprint`/`error_excerpt` property per relevant response, plus a small set of promoted `ObservedValue`s. The graph stops being 98.5% artifacts, and the drain stops being dominated by per-artifact commits.
- **`ResponseArtifact` leaves the node catalog.** `CONTEXT.md` is revised: the `RequestObservation -[:YIELDED]-> ResponseArtifact -[:CONTAINS_VALUE]-> ObservedValue` chain becomes `RequestObservation -[:YIELDED_VALUE]-> ObservedValue` (and `-[:SENT_VALUE]->` for inputs); `ResponseArtifact evidences Asset` becomes `ObservedValue`/observation evidence; the fingerprint/error sentences move to inline observation properties. This **amends ADR-0009** (which routed values through `ResponseArtifact`) — `ObservedValue` is now reached directly from the observation.
- **The `L2Event` union drops the `ResponseArtifact` variant.** L2 emits `RequestObservation` (now carrying inline candidates + diagnostics) and `ParseFailure`. `ParseFailure` is unaffected and remains an observation node.
- **Promotion is eventual (ADR-0022).** `ObservedValue`s appear at flush, alongside endpoints — consistent with the deferred-inference model; slice 1 has no mid-drain reader.
- **Provenance preserved.** Every promoted value still traces to the exact observations that yielded/sent it, via `YIELDED_VALUE`/`SENT_VALUE` edges carrying `location`/`extractor`/`parameter_name` (the metadata the `ResponseArtifact` node used to hold).
- **Secrets unchanged in spirit (ADR-0015).** Secret candidates and secret `ObservedValue`s carry hash + length + preview only; the raw value lives only in the object-storage blob.
- **Cost: candidate arrays inline on observations.** A 100-item list response stores ~100 candidate occurrences as arrays on its `RequestObservation` node — far cheaper than 100 nodes, but not zero. If that grows uncomfortable, the side-index option above is the escape hatch.
- **C3 unblocked.** The leak-to-input coverage query becomes a single traversal through `ObservedValue` (`output` observation ↔ `input` observation), with the data already in place; only the query/surfacing is slice-2 work.
- **Migration.** Existing graphs with `ResponseArtifact` nodes (e.g. the current `acme-test`) are from the retired model; a fresh ingest under the new pipeline replaces them. No automated migration — re-ingest from the retained HAR/blobs.
