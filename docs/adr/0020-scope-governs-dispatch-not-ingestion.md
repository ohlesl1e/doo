# `Scope` governs dispatch and query-time filtering, not ingestion

`Scope` rules are evaluated at exactly two points in the pipeline:

1. **At dispatch** (per ADR-0003): OPA reads the proposed request as `input` and the Scope rules as `data`, returning a pure allow/deny decision. This is the correctness gate that prevents the agent from acting outside scope.
2. **At query time**: coverage queries, the planner's gap-surfacing logic, and any consumer that needs "in-scope only" Endpoints/Hosts/Parameters derives the in-scope filter from the Scope rules of the current Engagement. The filter is computed at consumer time, not stored on nodes — same pattern as confidence decay (ADR-0005).

`Scope` is **not** evaluated at L1 intake. Passive observations of any host the tester captured land in the graph with full provenance, regardless of whether the host is in the program's published allowlist. Out-of-scope hosts become `Host` nodes; cross-host references in responses become `ResponseArtifact`s and `Asset`s. The dispatcher refuses to actively probe them; the graph faithfully records that they exist.

## Why ingestion is scope-blind

Two workflows depend on this:

- **SSO and federated auth flows.** The IdP's host (`auth.example.com`, `login.acme-sso.com`) is rarely in the target's bug-bounty Scope but is essential context for reasoning about the auth-bearing material the tester sees. Filtering it at intake would discard the redirect chain and break inference about `AuthContext`s, claims, and token-issuance behaviour.
- **SSRF, callback-based, and cross-origin testing.** The callback target of an SSRF probe is by construction out of scope (it's the tester's own callback server, or it's an internal host the tester is probing through the in-scope frontend). The relationship between the in-scope `Endpoint` and the out-of-scope callback target is the *whole point* of the test. Suppressing the callback `Host` at intake makes the finding invisible to the graph.

More generally: **the graph is a world model.** Its purpose is to faithfully record what was observed and what we infer. Scope is policy about agent action, not policy about reality.

## Mechanism

`Scope` rules live on the `Scope` node as structured properties (allowed host patterns, methods, path patterns, payload classes, rate limits, time windows). The OPA `data` bundle is generated from these properties at engagement start (per ADR-0012) and re-generated when the Scope changes.

For query-time filtering, a small `is_in_scope(node, scope)` helper evaluates a `Host` / `Endpoint` / `Parameter` against the Scope rules. Coverage and planner queries call this in their filter predicates. The helper is deterministic and side-effect-free; if it ever needs to be hot enough to matter, its result can be memoised at query-batch boundaries — but it is **never stored on the node itself**, because doing so would couple the node to a Scope version and require cascading writes when Scope changes.

The dispatcher's OPA call already evaluates the Scope rules per ADR-0003; this ADR does not change the dispatcher path.

## Considered Options

- **Reject out-of-scope observations at L1 intake** (rejected): breaks SSO and SSRF testing outright. The L1 rule is "raw bytes + provenance, no interpretation" (per the L1 contract); applying Scope at L1 violates that and forces a policy layer into the wrong place.
- **Ingest everything; tag each observation with `scope_status ∈ {in_scope, out_of_scope, boundary}` as a stored property** (rejected): cheap to query, but couples the node to a Scope snapshot at commit time. A Scope edit (Acme widens their allowlist) would either leave historical `scope_status` stale or require cascading writes over the engagement's whole subgraph. Computing at query time avoids both.
- **Ingest everything; promote in-scope and out-of-scope to distinct node labels** (rejected): same coupling problem as the property, plus label-thrash on Scope edits.

## Consequences

- The Scope helper (`is_in_scope`) becomes a load-bearing piece of library code: planner queries, coverage gap queries, and audit tooling all call it. Its semantics must match the OPA Rego evaluation exactly — same canonicalisation, same host-pattern matching, same path-template handling. Inconsistencies between Python helper and Rego rule produce silent bugs ("the planner thinks this is in scope, the dispatcher disagrees, the test gets proposed and rejected").
- A small test suite that runs the same set of `(request, scope)` inputs through both the Python helper and the Rego policy, and asserts identical answers, is mandatory. This is the unit test bar from CLAUDE.md ("tests for policy decisions are unit tests on Rego") restated for the dual-path case.
- `ResponseArtifact`s, `Asset`s, and `ObservedValue`s referencing out-of-scope hosts are first-class graph citizens. SSRF findings, IdP token analysis, and cross-origin-leak detection rely on this.
- A Scope edit mid-engagement (Acme adds a host to the allowlist) takes effect immediately for new dispatches and for new query-time filters; existing observations are unchanged. The provenance trail (which Scope was in force at the time of a given dispatch) is recoverable from the OPA decision log, which references the Scope content_hash that was active at decision time. This is one of the audit reasons `Scope` identity is its content hash (ADR-0017): a Scope edit produces a new `Scope` node with a new content_hash; the old node survives for historical reference.
- "Out of scope but observed" must not become a backdoor for active testing. The dispatcher's OPA check is the only authorisation — no consumer code can dispatch directly against a graph node it queried. This was already an ADR-0003 invariant; this ADR reinforces it by making out-of-scope nodes queryable but unactionable.
