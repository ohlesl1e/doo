# L2 is the boundary at which auth-bearing material is hashed; raw tokens never enter L3

L2 extracts auth-bearing material from observed requests and responses, hashes it at its layer boundary, and emits L3 events carrying only hashes and derived metadata (parsed JWT claims without verification, validity windows, observed capabilities). Raw bearer tokens, cookie values, API keys, basic-auth credentials, and any high-entropy substring matching a secret-shape pattern do not persist beyond L2. The raw bytes live only in the object-storage blob the originating `RequestObservation` references; the graph and every downstream stream are secret-free.

This generalises and centralises three previously-scattered disciplines into one boundary rule:
- AuthContext identity hashes the token at construction (CONTEXT.md identity rule, ADR-0010).
- `ObservedValue` for `kind ∈ {token, secret}` stores `value_hash` + length + preview only (ADR-0009).
- `ResponseArtifact` for secret-shape kinds carries `value_hash` + `value_length` + `value_preview`; for non-secret kinds carries the raw matched substring.

All three are special cases of: **L2 hashes; L3+ never sees raw secret bytes.**

Mechanism. L2 emits `RequestObservation`s carrying an `AuthContextCue` that holds `bearer_token_hash`, `cookie_session_hashes`, `api_key_headers`, `basic_auth_user_hash`, `bearer_claims` (decoded without verification), and `is_anonymous`. The dispatcher (L5 executor) reads raw bearer tokens from a separate secret store handle keyed by AuthContext id — populated from env-var references at setup per ADR-0012. The graph never holds the raw material.

## Considered Options

- **Hash later, at L3** (rejected): leaves raw tokens in transit on the L2→L3 Redis Stream, where retention, replication, and crash-dump behaviour aren't designed for secret material. Hashing at L2 makes the wire format past L2 secret-clean by construction; operational logging and replay of the L3 stream become safer.
- **Hash earlier, at L1 (before object storage)** (rejected): object storage already holds the raw blob — it is the replay source of truth. Hashing at L1 would either rewrite blobs (breaking re-extraction) or maintain a parallel hashed copy (adding complexity without benefit). The raw blob is acceptable in object storage because access is bounded by the engagement's ACL; the graph is not.
- **No hashing at all; rely on Neo4j ACLs to bound exposure** (rejected): violates the existing AuthContext / ObservedValue / ResponseArtifact discipline and expands the secret surface to anywhere the graph is exposed (Browser UI, Cypher exports, planner contexts sent to LLMs, debug dumps).

## Consequences

- L2 is the only routine code path that handles raw secret bytes. Security review concentrates there.
- The L2→L3 Redis Stream is treated as a non-secret transport. Operational logging, debug dumps, and crash reports of this stream are safer than they would be otherwise.
- Adding a new auth scheme (e.g., HMAC signatures, mTLS) is an L2 task: extend `AuthContextCue` with the new hash + scheme-specific metadata, update the dispatcher's secret-store read path to recognise the new scheme.
- The dispatcher's secret-store read path is the second sensitive code path. The dispatcher reads from a handle scoped to one AuthContext at a time; the graph never sees the raw.
- LLM-bound planner contexts cannot leak raw secrets via accidental graph dumps — the graph doesn't have them. This matters disproportionately when planner context is sent to a third-party API.
- Re-extraction (re-running L2 against historic blobs after a parser fix) re-hashes from the raw source. Hashes are stable across re-extractions because hashing is deterministic.
