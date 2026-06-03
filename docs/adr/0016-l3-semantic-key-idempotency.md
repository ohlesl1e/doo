# L3 commit idempotency is keyed on `(event_kind, source, source_id, engagement_id)`

L3 maintains a per-engagement idempotency index keyed on the tuple `(event_kind, source, source_id, engagement_id)`. Re-deliveries of the same logical L2 event — whether from Redis Stream redelivery, L2 retries after a crash, or replays of L2 against historic blobs — produce no graph mutation; the `CommitResult` flags `accepted = false` and carries the prior `commit_id`. This is distinct from L1's `idempotency_key` (which collapses re-uploads of the same source blob) and from L2's `event_id` (which is unique per emission attempt).

Why semantic. Graph correctness depends on each logical observation being committed exactly once. Event-id idempotency lets duplicates through when L2 re-emits the same logical observation under a fresh `event_id` (which crash-and-retry pipelines do routinely). Blob-hash idempotency catches re-uploads but misses partial-stream redeliveries — Logger++ shim retrying one record after a network blip, for instance. The semantic key captures the actual invariant: *this entry from this source for this engagement has been recorded.*

`source_id` therefore becomes load-bearing across the system. Every L2 event must carry a stable per-source identifier, and parsers must produce identifiers stable across re-extractions:

- HAR: `f"{entry_index}|{startedDateTime}"` (entry index alone is not stable across parser changes; pair with timestamp).
- Burp / Logger++: the item id assigned by Burp.
- nuclei: the finding hash from nuclei's output.
- agent (RequestObservation with `source = "agent"`, per ADR-0006): the TestCase content-address hash + execution sequence number.
- `ParseFailure`: the failing-entry's identifier from the source so the failure de-dups on replay (and doesn't fill the graph on every retry).

## Considered Options

- **Event-id keyed** (rejected): L2 retries after crashes generate fresh event_ids for the same logical observation, producing duplicate graph nodes. Replays of L2 against historic blobs would also duplicate. This option fails the central use case (parser bug-fix replays) outright.
- **Blob-hash keyed (carry L1's `idempotency_key` through to L3)** (rejected): a single HAR file produces many L2 events from one L1 envelope. Idempotency at L3 must be per-event, not per-blob.
- **Content-hash of the L2 event payload** (rejected): canonicalisation is fiddly (header ordering, timestamp precision, Pydantic-default rounding), and the resulting key is opaque in audit logs. The semantic key is short, diagnosable, and surfaces meaningful identity.

## Consequences

- L3 idempotency requires a fast lookup store that survives restart — Redis with persistence, or a Neo4j unique-index on the key tuple. Either way, the index is per-engagement so engagement teardown can drop it cleanly.
- Replay is safe and useful. After a parser bug-fix in L2, re-running L2 against the historic L1 envelope queue commits only events that legitimately produce new observations; everything previously committed is a no-op.
- Adding a new event kind requires deciding on its `source_id` derivation up front. The decision lives next to the parser; `source_id` stability is a property of the parser, not L3.
- Audit traces are diagnosable: a duplicate-commit attempt in the audit log shows the tuple, not an opaque hash, so a human can see "this is the Burp item id we already have."
- The idempotency tuple is part of the L3 commit contract; consumers that subscribe to `l3-events` can rely on each `node_id` corresponding to a unique semantic identity.
