# The keepalive may co-launch the auth-helper as an isolated child process

Running a dispatch today needs **three** terminals: `doo engagement keepalive`
(holds the kill-switch lease), `doo auth-helper run` (rotates declared
AuthContexts — only when the engagement has `refresh:` blocks), and `doo dispatch
run` (the agent). The keepalive and the auth-helper are both tester-started
**sibling processes** (ADR-0014): each holds an authority the agent must never
have — the kill-switch lease, and credential-mint capability. ADR-0014 framed the
helper as "a separate process the tester starts, never the agent," which a reader
can mistake for "every sibling must be its own process." It is not: the trust
boundary that matters is **the agent vs. everything else**, not sibling vs.
sibling. Two siblings sharing a launcher keeps both powers out of the agent just
as well as two launchers do — and removes a terminal.

## Decision: a `--with-auth-helper` flag co-launches the helper as a child subprocess

`doo engagement keepalive <id> --with-auth-helper --config <yaml>` runs the lease
heartbeat in the **parent** and spawns the auth-helper as a **child subprocess**.
This collapses the workflow to two terminals (keepalive+helper, and dispatch). It
cannot collapse to one: `dispatch` *is* the agent, and the kill-switch must live
outside the agent (CLAUDE.md hard rule), so dispatch always keeps its own
terminal.

Four properties make the co-launch safe rather than a trust-model violation:

- **Child subprocess, not a shared thread.** The lease heartbeat is the system's
  load-bearing safety mechanism; it must keep refreshing or the lease expires and
  the agent halts (fail-safe). The helper shells out to tester refresh scripts
  (60s timeout) and makes network calls — a hung refresh must never stall the
  heartbeat. A separate OS process makes the heartbeat physically immune to
  anything the helper does, and keeps the refresh credentials loaded only into the
  child's env (preserving ADR-0014's "refresh creds in the helper's env, not the
  dispatcher's" even within one launcher).
- **Conditional launch.** The child is spawned only when the engagement has
  managed (`refresh:`) slots (`AuthHelper.from_config(...).managed` non-empty);
  otherwise the keepalive runs lease-only and says so. `--config` is required only
  when the flag is set, and its `engagement.id` is validated against the positional
  id (the same guard the standalone command enforces).
- **Helper death never touches the lease.** On unexpected child death the parent
  attempts a **bounded restart** (≤3 within a 10-minute window, with backoff);
  past the cap it stops respawning, emits a loud `stderr` + structured warning, and
  **keeps holding the lease**. A clean `exit 0` is not restarted, and a child exit
  during the parent's own SIGTERM shutdown is not counted as a crash. The
  safety-critical parent stays simple.
- **Only the kill-switch halts dispatch.** The helper is a refresh/availability
  aid, not a correctness or safety mechanism: `SlotResolvingSecretStore` resolves
  slot material whether or not the helper is up (ADR-0049), and a dead helper only
  matters when a credential expires mid-engagement, which surfaces as bounded
  `auth_invalid`/`auth_unverified` + re-dispatch candidates (ADR-0053), never as a
  silent "boundary held." So helper failure is **advisory** — surfaced loudly,
  never halting. (The dispatch-side early warning for "auth failures climbing, no
  rotation happening" is tracked separately, #183.)

The flag is **opt-in, default off**: a tester may deliberately run the helper on a
different, more-locked-down host since it holds the engagement's most sensitive
material. When managed slots exist and the flag was not passed, the keepalive
prints a hint pointing at `--with-auth-helper` or the standalone command.

## Considered Options

- **Supervised thread instead of a subprocess** (rejected): simpler (no IPC,
  shared infra clients) but the helper's refresh work then shares an address space
  and runtime with the lease-write capability — fuzzing ADR-0014's credential
  separation — and a misbehaving refresh can contend with the heartbeat. The whole
  point of allowing co-launch is ergonomics; it must not buy a path where a tester
  refresh script can stall the safety primitive.
- **A dedicated `doo engagement supervise` command** (rejected for now): cleaner
  naming (the parent genuinely supervises) but forks the answer to "how do I keep
  the lease alive?" into two commands — bad for a primitive testers should reach
  for reflexively. The lease semantics are unchanged by the optional child, so the
  flag stays on the one lease command. Promote to `supervise` only if we ever
  supervise *many* siblings.
- **Tear down the lease when the helper dies** (rejected): inverts the safety
  model — it puts a non-safety condition (refresh stopped) in charge of the safety
  primitive (the kill-switch). Helper death must leave the lease untouched.

## Consequences

- `keepalive` gains a conditional `--config` dependency and child-process
  lifecycle/signal-forwarding logic; its single-purpose "hold the lease" core is
  unchanged and still runs even if the child never starts or later dies.
- "Supervisor" is an implementation/CLI-mode word, **not** a domain term — the
  canonical concept is the **sibling process (the trust split)** in `CONTEXT.md`.
- ADR-0014's sibling-process model is unchanged in substance; this only clarifies
  that the boundary is agent-vs-rest and that siblings may share a launcher.
