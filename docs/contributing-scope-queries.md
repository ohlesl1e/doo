# Contributing: engagement-scoped queries and scope filtering

This note documents three conventions that every consumer query in `doo` must
follow, plus the dual-path test pattern that keeps the scope helper honest. They
implement ADR-0017 (Engagement is the graph root) and ADR-0020 (Scope governs
dispatch and query-time filtering, not ingestion).

## 1. `for_engagement(engagement_id)` — required for every scoped read

Per ADR-0017 the graph is rooted at `Engagement`, and **all consumer-facing
Cypher must start from the `Engagement` root or filter explicitly on
`engagement_id`.** A query that forgets the filter risks pulling another
engagement's observations into the current engagement's coverage view (a
cross-engagement data leak — see ADR-0017 "Why `Host` is scoped").

Use the helper in `doo.ontology.queries`:

```python
from doo.ontology.queries import for_engagement

frag = for_engagement(engagement_id)               # var defaults to "n"
cypher = f"MATCH (n:Endpoint) {frag.where_clause} RETURN n"
rows = session.run(cypher, **frag.parameters)      # value is parameterised
```

- The `engagement_id` value is **bound as a parameter** (`$engagement_id`),
  never interpolated into the query string — this preserves Neo4j plan-cache
  hits and prevents injection.
- Match under a different alias with `for_engagement(eng_id, var="e")`.
- Append further predicates with `frag.and_("n.status = 'active'")`.

Code review rejects scoped reads that hand-roll the `WHERE engagement_id` clause
instead of using `for_engagement`. Legitimate cross-engagement queries (audit,
prior-art) are **explicit traversals across `Engagement` roots**, never
accidental joins through shared subgraphs — call those out in review.

## 2. `is_in_scope(node, scope)` — query-time scope filtering

Per ADR-0020, `Scope` is evaluated at exactly two points: at dispatch (the
dispatcher's OPA call) and at **query time**. Ingestion is scope-blind:
out-of-scope hosts (SSO IdPs, SSRF callback targets) are first-class graph
citizens with full provenance. Consumers that want "in-scope only"
Endpoints/Hosts compute the filter at query time with the pure helper in
`doo.policy.scope`:

```python
from doo.policy.scope import is_in_scope

in_scope = [ep for ep in endpoints if is_in_scope(ep, scope_rules)]
```

- `is_in_scope` is **pure** — no graph, no Redis, no I/O. It accepts a
  `Host`-shaped, `Endpoint`-shaped, or (forward-compatible) `ProposedRequest`-
  shaped value (structural Protocols; any object with the right attributes
  works).
- The scope-status is **never stored on the node** (ADR-0020): storing it would
  couple the node to a Scope version and force cascading writes on every Scope
  edit. Compute it at query time instead — same pattern as confidence decay.
- Matching semantics (host glob/explicit/IP, scheme/port, method `*`,
  path-template `/users/*` ↔ `/users/{user_id}`, payload-class denylist) are
  documented in `src/doo/policy/scope.py`. They **must** match the Rego policy
  exactly.

The canonical "in-scope Endpoints for engagement X" query composes both helpers:
`for_engagement` scopes the `MATCH`; `is_in_scope` filters the rows. See
`tests/test_for_engagement.py::test_example_in_scope_query_over_mixed_endpoints`.

## 3. Dual-path test pattern (mandatory per ADR-0020)

The Python `is_in_scope` helper and the Rego policy
(`src/doo/policy/scope.rego`) must return **identical** answers for the same
`(node, scope)` inputs. A drift produces silent bugs ("the planner thinks this
is in scope, the dispatcher disagrees"). ADR-0020 therefore makes a dual-path
test mandatory.

`tests/test_scope_dual_path.py` feeds one fixture set through both paths and
asserts agreement:

- **OPA runner:** the `opa eval` CLI (a single static binary), not
  `opa-python-client`. This runs the *actual* Rego the dispatcher loads, with no
  Python shim that could diverge. Install OPA with `brew install opa` or grab the
  static binary from <https://www.openpolicyagent.org/docs/latest/#running-opa>.
  When `opa` is not on `PATH` the dual-path test **skips with a clear reason**
  (it does not silently pass); the Python-side assertions still run.
- **Slice-1 invariant:** the Rego is deny-all (`default allow := false`, no
  granting rule). So every slice-1 fixture is constructed to be out-of-scope for
  the Python helper too (host not in the allowlist), making the expected answer
  `False` on both paths. When the real Rego matching rules land in slice 4, add
  `True`-expecting fixtures alongside the new rules — and keep this test green.

When you add or change scope-matching semantics, change **both** `scope.py` and
`scope.rego` in the same commit and extend the dual-path fixtures to cover the
new behaviour.
