# baseline_victim's send credential is resolved via a Principal-sibling walk at evidence-load

An `auth-bypass` confirm loop sends `baseline_victim` under the victim's live
material to establish the differential baseline (ADR-0043, #124). The victim
AuthContext comes from the evidencing observation — often a discovered-tier HAR
session whose token has since expired and which has no slot, so
`SecretStore.material_for()` (keyed on the ADR-0049 declared `(principal_label,
slot)` map) returns `None` and the baseline can't arm. #160 stopped that from
dead-ending the verdict at `inconclusive`; this recovers the *actual* send.

Because a discovered session whose `identity_claims` match a declared credential
is already attached to the **declared Principal** at resolve time (ADR-0048
priority-0 + retroactive sweep; `resolve.py`), the live credential is reachable
by following the `OF_PRINCIPAL` edge L3 already created — not by re-matching
identity. `load_evidence` therefore resolves `baseline_victim_auth_context_id`
to the declared sibling on the shared Principal whose `slot` matches the observed
session's carrier (`token_kind`); generation is left to `SlotResolvingSecretStore`'s
rotation overlay. Ambiguous (≥2 distinct slots match the carrier) or no-carrier-match
declines to the existing un-armable path — the change is strictly additive.

## Considered Options
- **Dispatch-time identity re-matching** (walk `observed_aliases`/`known_signals`
  in the send tool) — rejected: duplicates the ADR-0030/0048 walk in a second
  place where it can drift; the match already happened at L3.
- **Resolve in the SecretStore** — rejected: `EnvSecretStore` /
  `SlotResolvingSecretStore` are deliberately graph-light (a slot map precomputed
  once at arm time); a per-lookup live Principal walk breaks that.
- **Resolve in the send tool** — rejected: keeps the tool from staying narrow
  (ADR-0043); evidence-load already chooses the victim AC, so the choice belongs there.

## Consequences
- `EvidenceObservation.baseline_victim_auth_context_id` now means "the live AC to
  send baseline_victim under," which may differ from the AC the evidence was
  observed under. Observed provenance remains recoverable via
  `observation_id → OBSERVED_UNDER`.
- Security-sensitive: we replay as a declared principal on the strength of an L3
  identity link, so the substitution is logged
  (`dispatch.evidence.baseline_victim_resolved_via_sibling`).
- Carrier-match-or-defer avoids false negatives from replaying over the wrong carrier.
- Assumes convergence; genuine discovered/declared Principal split is a separate
  L3 reconciliation bug, not patched here.
