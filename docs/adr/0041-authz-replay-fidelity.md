# Authz-replay fidelity: structured hold/hazards, and unresolved hazards mean "untested"

Slice-3 authz tests (C2 / C2b / C4 / tenant + capability boundaries) are **replays
of an evidencing observation under a swapped identity** (ADR-0037, ADR-0039). A
verbatim replay has two failure modes the original "send under auth B" framing
hid:

- **Replay-breakers** — CSRF tokens, nonces, signatures, timestamps bound to the
  original session. A replay that trips one fails for a *non-authz* reason, but
  returns a 403/401 that *looks* like "boundary enforced." That is a **false
  negative**: the tool reports a boundary safe when it was never actually tested —
  the worst outcome for a security tool.
- **Hold-vs-swap differs per boundary kind** — IDOR holds A's object-id and swaps
  B's auth; capability holds everything and swaps to the weaker token; tenant holds
  tenant-42's resource ref and swaps tenant-43's auth. "Send under auth B" captures
  none of this.

The LLM must not construct requests (hard rule), so the LLM proposes a *structured*
transformation and deterministic code applies it.

## Slice 3 — make the proposal expressive and honest

`PlannerProposal` / `TestCase` gain two structured fields (never raw bytes):

- **`hold`** — the security intent: which references define the cross-boundary
  access attempt (object-id / ownership ref / tenant ref kept verbatim from the
  evidence observation), named by `Parameter` / role. LLM-proposed; this is the
  meaningful choice a human reviews ("read A's `order_id` as B").
- **`replay_hazards`** — a **deterministically-detected** annotation: fields in the
  evidencing observation that would break a naive replay (CSRF-token-shaped params,
  nonce / signature headers, timestamps). Detection is shape/name/entropy
  heuristics via `ParameterSemantic`, **not** the LLM. Slice 3 does not pretend to
  *solve* refresh — it *flags* that naive replay would false-negative.

This adds one slice-3 enrichment deliverable: **`ParameterSemantic` / detector
kinds for replay-hostile roles** (`csrf_token`, `nonce`, `signature`,
`timestamp`) — deterministic, name + entropy + short-lived heuristics.

## Slice 4 — the mechanics

Actual field refresh/rewrite (fetch a fresh CSRF token from the attacker's
warm-up, strip stale nonces) is dispatch work. Plus a new `dispatch_status` value
**`replay_invalid`** (sibling of `auth_invalid`, ADR-0013): a replay that fails on
an *unresolved hazard* maps to it and is therefore **treated as untested — never
reported as "boundary enforced."** This is what closes the false negative.

## Identity: the transformation is NOT in `key_hash`

The hold/refresh strategy is a derivable function of (boundary + evidence + auth),
so adding it to the `TestCase` identity (ADR-0007) would needlessly fracture
identity. One `TestCase` per logical `(boundary/target, auth, class, payload)`;
*which* evidence observation is replayed is a dispatch detail — multiple replays
become multiple `EXECUTED_AS` edges (the ADR-0007 retry model).

## Considered Options

- **Treat replay as a bare auth swap** (rejected): the status quo this ADR fixes —
  silent false negatives on any endpoint with CSRF/nonce/signature protection.
- **Let the LLM emit the rewritten request** (rejected): violates the
  no-LLM-request-construction hard rule.
- **Put the transformation in `key_hash`** (rejected): fractures content-addressed
  identity for an execution detail; the strategy is derivable, not an identity
  component.
