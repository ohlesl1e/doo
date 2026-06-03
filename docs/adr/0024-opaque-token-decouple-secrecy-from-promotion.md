# High-entropy values are `opaque_token`, not `secret`: secrecy-for-storage is decoupled from promotion-worthiness

A generic high-entropy string (a long base64url/hex run with no recognised structure) is classified `opaque_token`, not `secret`. `opaque_token` is stored hash-only — like a secret — but is **not** on the always-promote allowlist: it becomes an `ObservedValue` node only on a second signal (multiplicity ≥2 or leak-to-input). `secret` is reserved for the high-precision structured detectors (JWT, AWS, Stripe), which stay always-promoted.

## Why

Re-ingesting a real 72 MB / 3,961-request HAR under the ObservedValue pipeline (ADR-0023) produced **14,498 `secret` `ObservedValue`s** out of 15,222 — a capture does not contain 14k credentials. The cause: the `high_entropy_token_v1` extractor matches any base64url/hex string ≥32 chars (sweeping up ETags, content hashes, signed-URL tokens, base64 data blobs), and `is_secret_kind` made one flag govern **two unrelated decisions**:

1. **Secrecy-for-storage** (ADR-0015): never store the raw value; hash + length + preview only.
2. **Promotion-worthiness** (ADR-0023 shape-allowlist): always becomes a node, even at a single occurrence.

For a JWT/AWS/Stripe key, both are correct. For a generic high-entropy blob the decisions diverge: storage *should* be cautious (an unrecognised high-entropy string might be a real credential we failed to recognise), but promotion should *not* be eager (it is almost certainly noise). Conflating them turns "high entropy ⇒ secret ⇒ always-promote" into the 14,498-node prolixity — the same eager-node-ification problem ADR-0023 solved for identifiers, reappearing under `secret`.

## Decision

Split the two properties into independent sets:

- **secret-for-storage** = `{secret, token, opaque_token}` — hash-only (ADR-0015). An `opaque_token` is treated as potentially-credential for storage, so a real unrecognised secret never leaks its raw bytes.
- **always-promote allowlist** = `{secret, internal_hostname, email}` — promotes on shape alone. **`opaque_token` is deliberately absent**: it promotes only on multiplicity ≥2 or leak-to-input.

`secret` is narrowed to the **structured, high-precision** detectors (JWT three-segment, AWS `AKIA…`, Stripe `sk_/pk_`). The generic `high_entropy_token` detector emits **`opaque_token`**.

## Considered Options

- **Keep one `is_secret_kind` flag; just tighten/retire the high-entropy detector** (rejected): lossy either way — keep classifying borderline strings as `secret` and they still over-promote, or drop them to a non-secret kind and risk storing a real opaque secret's raw value (ADR-0015 violation).
- **Classify generic high-entropy as `identifier`** (rejected): same raw-storage risk for an unrecognised secret.
- **Decouple via `opaque_token`** (chosen): safe storage *and* precise promotion, no false dichotomy.

## Consequences

- The 14,498 collapses to the handful of structured secrets plus the opaque tokens that actually recur or pivot. The graph stops being a credential-noise dump.
- **ADR-0015 holds**: `opaque_token` is hash-only, so an unrecognised real secret still never lands raw.
- `opaque_token` candidates are still *extracted and retained inline* (hash-only) on the observation, so they remain available for multiplicity / leak-to-input promotion and for retroactive re-promotion (ADR-0023's lossless-retention property) — only node-creation is gated.
- Over-detection by the high-entropy regex now costs only inline-candidate volume + flush aggregation, **not nodes**. Tightening the detector (e.g. excluding obvious md5/sha hex) is a deferrable precision/perf follow-up, no longer load-bearing.
- Amends ADR-0023: the shape-allowlist is now `{secret, internal_hostname, email}`, and `CandidateKind` gains `opaque_token`.
- Existing graphs (built with high-entropy → `secret` → promoted) are replaced by re-ingest; no automated migration.
