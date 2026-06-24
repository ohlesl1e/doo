# Auth-helper rotations are verified on first use; re-dispatch is watermark-gated

The auth-helper (ADR-0014/0049) mints new credential material on rotation but
never proves it works, and `SlotResolvingSecretStore` (ADR-0049) uses the
rotation-file entry **unconditionally** over the seed token — resolution is
positional, with no notion of "the current token is still valid". So a single
dead mint (short TTL, expired-before-use, or a misconfigured refresh mechanism)
poisons the slot, every authz `primary` under it returns `auth_invalid` (ADR-0044),
each emits a reactive refresh event, and the helper mints again — a self-amplifying
dead-token storm. Worse, blind manual re-dispatch of those `auth_invalid` TestCases
re-sends them against the still-dead slot, burning request budget (ADR-0042) for
zero information. Observed in practice: dozens of `idor`/`bola`/`auth-bypass`
primaries with 2–5 `auth_invalid` attempts each and **0 C5 gaps** — because C5 is
boundary-level and a clean sibling TestCase masks a never-clean one (see #166).

## Decision: verify the mint at the Dispatcher on first use; gate re-dispatch on a rotation watermark

**The helper stays target-blind.** It continues to call only the IdP (refresh
credentials, out-of-band) and writes the rotation-file entry tagged
**`unverified`** — never sending to the target. Giving the sibling target-send
capability would put in-scope traffic *outside* the Dispatcher gate, where the
kill-switch lease, OPA, and budget cannot see it (CLAUDE.md hard rule, ADR-0042).

**The Dispatcher verifies on first use.** When the Executor resolves a slot whose
rotation entry is `unverified`, the Dispatcher runs the existing ADR-0044 liveness
probe *before* the `primary`:

- probe **live** → promote the entry to `verified`, proceed with the `primary`.
- probe **dead** → **refuse the `primary` (do not burn it)**, emit the ADR-0014
  reactive event, and record the mint as **failed**. The verdict feeds back to the
  helper, which **backs off**: after K consecutive dead mints on a slot it stops
  rotating and surfaces `slot unrecoverable — check refresh config` rather than
  storming. This replaces the silent `poll_reactive` ack-loss — a failed mint is a
  *named* outcome, and `rotate()` returns a typed result (rotated / rate-limited /
  failed), not a bare bool.

**Re-dispatch is watermark-gated.** An `auth_invalid` `primary` edge is
re-dispatch-eligible only once its slot has a confirmed-newer `active` AuthContext
generation whose `first_seen` is later than the failed edge's `at` (the **rotation
watermark**). Below the watermark, the candidate is "waiting on rotation" — never
auto-sent, and refused even on manual rerun. This makes `auth_invalid`
**transient-but-gated**: re-dispatchable only when its precondition has
demonstrably cleared, not merely because the status is "transient".

**The re-dispatch set is derived, not stored.** "Re-dispatch candidates" are
computed at query time over existing axes (`dispatch_status`, edge `at`, AuthContext
`first_seen`/`status`) — no `parked`/`needs_redispatch` flag on the TestCase,
consistent with coverage's pull/ephemeral, no-`CoverageGap`-node rule. Manual rerun
(by `key_hash`) selects exactly that set; **auto re-dispatch is a later,
staging-only layer** — production requires a fresh mode-gated gate at dispatch time
and approval is "consideration, not authorization" (ADR-0042/0040).

## Considered Options

- **Verify at mint (helper probes the new token before publishing)** — rejected:
  gives the sibling target-send capability outside the gate, and is a TOCTOU
  (mint-live-then-expire-before-use). Verify-on-first-use checks liveness at the
  moment it matters and never wastes a `primary` on an unproven token.
- **Keep the helper "dumb mint", solve entirely on the dispatch side with no
  feedback** — rejected: without the verification verdict flowing back, the helper
  cannot distinguish a transient dead window from a broken refresh config, so it
  keeps storming. The feedback path is what enables back-off.
- **Store a `parked` lifecycle flag on the TestCase** — rejected: a fifth mutable
  axis duplicating facts already derivable from the edges, against the no-stored-
  coverage-state philosophy.
- **Auto re-dispatch on any target, including production** — rejected: bypasses the
  ADR-0042 fresh-gate-at-dispatch and treats approval as authorization.

## Consequences

- The rotation-file entry gains an `unverified`/`verified` field;
  `SlotResolvingSecretStore` reads it; the ADR-0044 probe moves *ahead* of the
  `primary` for an unverified slot. `rotate()` returns a typed outcome and a
  verdict feedback path replaces `poll_reactive`'s unconditional ack.
- One extra liveness probe per slot per rotation generation (cached per
  `(AuthContext, window)` like the existing ADR-0044 probe), counted against the
  run's request budget — paid once, not per test.
- A genuinely broken refresh mechanism now fails **loud and bounded** (`slot
  unrecoverable`) instead of storming until the budget is exhausted.
- Amends ADR-0014 (rotation publishes `unverified`, backs off on failed mints),
  ADR-0044 (the probe also gates an unverified slot pre-`primary`), and ADR-0049
  (resolution is no longer purely positional — an unverified entry is provisional
  until the Dispatcher promotes it).
