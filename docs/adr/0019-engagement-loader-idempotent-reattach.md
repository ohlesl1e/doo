# Engagement loader is idempotent on re-run; `engagement.id` is immutable

`doo engagement start --config X.yaml` is the same command for Day 1 and Day N. When the YAML's `engagement.id` does not yet exist in the graph, the loader creates the `Engagement` node and its dependencies (Scope reference, declared Principals + AuthContexts, kill-switch lease config). When the id already exists, the loader re-attaches: it computes the diff between the YAML and the current graph state and applies it, never recreating.

Two invariants protect against the failure modes of an idempotent loader:

1. **`engagement.id` is immutable.** The loader refuses to apply a YAML whose id differs from any prior version of the file in the project's git history (best-effort heuristic) or from any prior `EngagementConfig` it has previously loaded. Changing the id means starting a new campaign, which is a new YAML file. This is the "you meant a new engagement" footgun guard.
2. **Material diffs require confirmation.** When the diff would change a declared Principal (add, remove, or modify token reference / `known_signals`), change the referenced `Scope` rules (different `content_hash` than what the existing Engagement is `UNDER_SCOPE` of), or alter the kill-switch configuration, the loader prints the diff and requires explicit confirmation. Cosmetic changes (description text, comments) apply silently.

Re-attach is the same command intentionally. A workflow that makes Day 1 different from Day N invites tester error ("did I run `start` or `reattach`?") and breaks scripting; one command with internal branching is friendlier and equally safe given the two invariants above.

## Considered Options

- **Create-only; require an explicit `doo engagement reattach` for Day N** (rejected): forces the tester to remember which command applies to today's state. Morning-friction every day. The two-command split adds no safety beyond what the invariants already provide.
- **Silent re-attach; never diff, never apply changes** (rejected): loses the ability to evolve an engagement (add a Principal mid-campaign, narrow the Scope after a finding). Tester edits would silently fail to take effect, which is worse than the diff-with-confirmation cost.
- **Apply diffs silently without confirmation** (rejected): a typo in a Scope rule that widens the allowlist could be applied without the tester noticing — a finding could be sent against a target that wasn't actually authorised. Confirmation on material diffs is cheap and catches this class.
- **Loader-driven Scope migration when content_hash changes** (rejected for now): when a YAML edit changes Scope rules, the loader could rebind the Engagement to the new Scope and retract the old one. Tempting but raises audit questions ("which Scope was in effect when this finding was discovered?") that need pinning. Defer until needed.

## Consequences

- The loader is the only code that writes Engagement-root state. Code review centralises around the diff-and-apply logic.
- The diff-vs-current-graph computation requires the loader to read the Engagement subgraph at startup. Cheap (Engagement + declared Principals + AuthContexts is a small subgraph), one-time cost per `start` invocation.
- The confirmation prompt is interactive by default; CI / scripted use cases can pass `--apply` to skip the prompt, with the diff still printed to logs for audit.
- The git-history heuristic for `engagement.id` immutability requires the YAML to live in a git-tracked location. Operationally fine for the bug-bounty workflow (engagements are checked in) but worth flagging.
- ADR-0012's "setup is YAML loaded by a Pydantic-typed `EngagementConfig`" stays intact; this ADR refines the loader's behaviour around the second-and-subsequent loads.
- Engagement teardown (`doo engagement archive <id>`) and engagement re-creation under a new id remain explicit, distinct commands. The idempotency described here applies only to repeated `start` against the same id.
