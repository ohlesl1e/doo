# `opaque_token` is a whole-value classification of structured leaf values, not a body-text sweep

Generic high-entropy (`opaque_token`) candidates are extracted **only from structured leaf values** (JSON leaf strings) by **full-value** match of a bounded opacity predicate — never by sweeping substrings over the raw response body. The `_HIGH_ENTROPY_RE.finditer(text)` body sweep is removed. The high-precision **structured** secret detectors (JWT, AWS, Stripe) continue to run over the whole body.

## Why

Re-ingesting the real 74 MB capture under ADR-0024 produced **14,483 promoted `opaque_token` `ObservedValue`s** (and ~260,735 inline candidates). Characterising them: **100% were JSON leaf values**, dominated by **inline base64 binary** — e.g. `iVBORw0KGgoAAAANSUhEUgAA…` is the base64 magic for a PNG — plus **fragments** of those blobs (a long base64 run chopped at `+`/`/` boundaries into many 32+ char matches). None were credentials or identifiers.

The root cause is an asymmetry between the two extraction sides:

- **Output side** (`_extract_secrets_from_body`): `finditer` — matches any 32+ char **substring** of the body, so a 50 KB base64 image becomes dozens of "tokens."
- **Input side** (`classify_input_kind`): `fullmatch` — classifies the **whole** parameter value, bounded.

The input side already had the right idea; the output side's blind substring sweep is the bug. ADR-0024's multiplicity≥2 gate could never filter this, because embedded blobs recur across responses by construction.

## Decision

- **Whole-value, structured-leaf extraction.** `opaque_token` (output role) is emitted from **JSON leaf string values** (walking the parsed JSON, alongside the existing `*_id` identifier walk) when the **entire leaf** matches the opacity predicate. The `_HIGH_ENTROPY_RE.finditer` body-text sweep is deleted.
- **One bounded opacity predicate, shared by input and output.** A value is `opaque_token`-shaped iff: base64url/hex charset, **length ∈ [32, 512]**, mixes upper+lower+digit (so all-hex checksums and lowercase slugs do not trip), and is not a `data:` URI. The upper bound is the new lever: whole-leaf matching means an inline image is a single oversized leaf (rejected), and fragments cannot arise because substrings are no longer considered. 512 is generous for real signed/session tokens while binary blobs are KB–MB.
- **Structured detectors unchanged.** JWT (three-segment), AWS (`AKIA…`), Stripe (`sk_/pk_`) still run over the whole body — they are high-precision and catch real structured secrets anywhere, including non-JSON bodies.
- **Promotion gate unchanged** (ADR-0023/0024): with precise extraction, `multiplicity ≥2 ∨ leak-to-input` is correct again — a genuinely recurring or leaked opaque token still promotes.

## Considered Options

- **Keep the sweep, add exclusions** (data-URI guard, length cap, drop hex-only) — rejected: patches symptoms, still extracts ~260k inline candidates, and fragments persist.
- **Gate promotion only** (`opaque_token` promotes solely on leak-to-input) — rejected: stops the *node* flood but keeps the ~260k inline-candidate extraction cost and can never promote a legitimate recurring server-emitted token.
- **Whole-value on structured leaves** (chosen): fixes the root cause, restores input/output symmetry, and removes the extraction cost, not just the nodes.

## Consequences

- The ~14.5k noise nodes and ~260k inline candidates collapse to the handful of JSON-leaf values that are genuinely bounded opaque tokens.
- **Lost recall**: an opaque token embedded in a **non-JSON body** (HTML/JS) or as a **substring** of a larger field is no longer extracted. Judged acceptable — those were unusable noise anyway; structured (JWT/AWS/Stripe) detectors still fire everywhere; and HTML `<meta>`/hidden-input/`<script>`-config token extraction is better added later as its own *structured* extractor than via a blind sweep.
- Input and output now share one canonical `opaque_token` shape (bounded), removing a latent divergence.
- Existing graphs are replaced by re-ingest; no automated migration (consistent with ADR-0023/0024).
