# Interpreter sends by request-role; hazard resolution is the Executor's

The slice-4 confirm loop (ADR-0042) has the Interpreter (LLM) calling a narrow
`send_http_request_within_scope` tool ≤N times per `TestCase`. The hard rule
says the LLM never constructs HTTP requests. This ADR fixes the tool's signature
and where ADR-0041's replay-hazard mechanics live.

## The send tool takes `(testcase_id, role)`; roles are a per-`test_class` enum

The Interpreter's only authority over what goes on the wire is **which request
role to send next**. A role is a closed enum keyed by `test_class` — e.g. for
`idor` / `bola`: `primary` (the test), `baseline_victim` (same held object under
the owner's auth, to diff bodies against a generic-200), `baseline_negative`
(held identifier swapped to a known-nonexistent value, to rule out "any id
200s"); for `auth-bypass` / `privilege-escalation` / `boundary-violation`:
`primary`, `baseline_victim`; for sink classes (`ssrf` / `open-redirect` /
`path-traversal` / `leak_replay`): `primary` only (their confirmation is
out-of-band — `check_callback` — or in the response itself).

The Executor owns one **deterministic request constructor** per
`(test_class, role)`, each a pure function of `(TestCase, evidence
RequestObservation, AuthContext material)` → concrete HTTP request. Constructors
are unit-testable in isolation; adding a confirmation strategy is "new enum value
+ new constructor," not a prompt change. The role enum is also the
**`confirm`-mode boundary** (ADR-0042): any request not expressible as a role for
*this* TestCase is by definition a different test and goes back to `proposed`.

Roles whose answer is always useful (`baseline_victim` on every authz test) MAY
be pre-sent by the Executor in the same dispatch and handed to the Interpreter on
turn 1 alongside `primary` — fewer LLM round-trips, same enum, same constructors.

## Hazard resolution runs inside the `primary` constructor, not as a role

ADR-0041 deferred replay-hazard *mechanics* (fetch a fresh CSRF token, strip a
nonce, refresh a timestamp) to slice 4. They live in the **Executor**, not the
Interpreter: the `primary` constructor reads the TestCase's
deterministically-detected `replay_hazards` and runs a per-`kind` **resolver**
(mirroring the slice-3 per-`kind` *detector* registry) before the send —
`csrf_token` → fetch the `source_hint` page under the TestCase's `auth_context`,
extract the token, splice it; `nonce` → strip; `timestamp` → set to now;
`signature` → no resolver (refuse). The Interpreter never sees warmup as a step;
"got `replay_invalid`? warm up then retry" is a mechanical decision the LLM would
add only latency and error to.

Warmup HTTP sends still pass the Dispatcher gate (kill-switch → OPA → guards),
still become `source = "agent"` `RequestObservation`s, and count against the
**run's request budget** — but not the Interpreter's per-TestCase **tool-call**
budget (one `send(role=primary)` call may cost >1 wire send).

## Unresolvable hazard ⇒ refuse to send, surface to a dispatch-side review queue

If any resolver fails (no `source_hint`, extraction missed, no resolver for the
`kind`), the Executor **refuses the `primary` send** for that TestCase and records
a per-TestCase run outcome `hazard_unresolved` with the reason. The TestCase
surfaces in a dispatch-side review queue (`doo dispatch review`, sibling to
`doo planner review`) where the human can: supply the missing `source_hint`,
mark the hazard ignorable ("send anyway — accept the `replay_invalid` risk"), or
reject the test. It does **not** silently become "untested" in coverage with no
signal — an authz test the tool *knows* it cannot run honestly is a question for
the human, not a quiet gap.

`dispatch_status = replay_invalid` (ADR-0041) is therefore reserved for the
**post-send** case: a send *did* happen (resolver believed it succeeded, or the
slice-3 detector missed a hazard) and the response indicates a non-authz replay
failure. How the deterministic classifier distinguishes that 403 from
`auth_invalid` and from a genuine "boundary held" `ok` is settled separately.

## Considered Options

- **Transform-DSL signature** — `send(testcase_id, {swap_auth, hold,
  override_param, …})` (rejected): a structured DSL expressive enough to cover
  the confirm cases is request construction by another name. Give it enough verbs
  and the LLM is building requests in JSON; the hard rule is read strictly.
- **`send(testcase_id)` only; baselines pre-computed** (rejected as the *only*
  mode): cannot do reactive hazard refresh and cannot let the Interpreter skip a
  baseline it doesn't need. Kept as an *optimization* (pre-send always-useful
  roles), not the contract.
- **`hazard_warmup` as an Interpreter-driven role** (rejected): puts a mechanical
  retry decision in the LLM loop, costing ≥2 extra tool-calls per hazarded test
  for zero added judgement, and risks the LLM *not* warming up when it should —
  reintroducing the ADR-0041 false negative.
- **Best-effort resolve, else `replay_invalid`, no surfacing** (rejected): a test
  the Executor *knows upfront* it cannot run honestly should not quietly join the
  "untested" pile; the human can often supply the one missing fact (where the
  CSRF token comes from) in seconds.

## Consequences

- The slice-3 `replay_hazards` detector must be extended to emit a **`source_hint`**
  per `csrf_token` hazard (the referer / form page the token was observed on) —
  otherwise the resolver has nothing to fetch. Detectors without a hint produce a
  `hazard_unresolved` on the first dispatch, which is the surfacing path.
- The Executor's tool surface for MVP is small: `send_http_request_within_scope
  (testcase_id, role)`, `read_response_body(blob_ref)`. `freelance` (post-MVP,
  ADR-0042) adds `propose_testcase(PlannerProposal)` reusing the slice-3 Validator
  + commit path; sink-class execution (post-MVP) adds `check_callback(probe_id)`.
- **Transport: native tool-use loop, not an MCP server, for MVP.** The
  Interpreter is a deterministic Python loop driving multi-turn
  `litellm.completion(tools=[…])`; on each `tool_use` block, *our* code dispatches
  on `tool_name` to plain Executor functions and feeds `tool_result` back — the
  same seam as `planner/llm.py`, just multi-turn. The LLM emits JSON; it never
  executes anything, so narrowness is enforced identically. Executor tool
  functions are written with **MCP-ready signatures** (pure `(args) → result`, no
  globals) so wrapping them in an MCP server later — for process isolation, an
  egress-isolated Executor host, or `freelance` long-lived sessions — is a
  transport swap, not a refactor. **Third-party** MCP servers (Burp's,
  hexstrike-ai) are consumable *behind* the Executor (as the wire-send transport
  inside `send_http_request_within_scope`), never exposed directly to the
  Interpreter — a third-party `send_request` tool would bypass the Dispatcher
  gate.
- A dispatch run's per-TestCase outcome is one of `executed` (≥1 `EXECUTED_AS`
  created; Interpreter ran), `hazard_unresolved`, `dispatcher_blocked` (OPA / lease
  / budget refused before any send), recorded in the dispatch ledger (ADR-0042) and
  rendered by `doo dispatch review`.
- `baseline_victim` sends under a **different** `auth_context_id` than the
  TestCase's. That request is *not* a new TestCase (it is a control, not a
  hypothesis) but it *is* a real send through the Dispatcher under the victim's
  auth — so `AuthContext` rotation (ADR-0014) and rate limits apply to it too.
