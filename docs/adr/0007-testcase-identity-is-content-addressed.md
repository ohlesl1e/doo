# TestCase identity is content-addressed and Engagement-scoped

A `TestCase` is identified by a deterministic hash over its content — `key_hash = sha256(canonicalized(engagement_id, test_class, target_endpoint_id?, target_parameter_id?, target_trust_boundary_id?, payload_class, payload_hash, auth_context_id))` — stored as a unique-indexed property. Same content → same node. The planner emits proposals without an explicit dedup pass; the commit is a hit or a no-op. The dispatcher's dedup guard (C8 in `ONTOLOGY.md` Step 6) reduces to one indexed key lookup. Retries and parameter sweeps add `EXECUTED_AS` edges to the same node; payload sweeps (50 SQLi variants) create 50 distinct nodes — each is its own auditable test.

The target half is a **three-way XOR**: exactly one of `target_endpoint_id` (route-level test), `target_parameter_id` (parameter-level test against a `Parameter` node, whose Endpoint is reachable via `HAS_PARAMETER`), or `target_trust_boundary_id` (boundary test). The other two normalize to null and fall out of canonicalization. The matching graph edge is one of `TARGETS_ENDPOINT` / `TARGETS_PARAMETER` / `TARGETS_BOUNDARY`.

`Engagement` is part of the key: a TestCase `IN_ENGAGEMENT` exactly one Engagement (its own kill-switch, budget, audit boundary). Re-running the same logical test in a different Engagement creates a new node. The "test we know how to run, regardless of engagement" abstraction (a `TestTemplate`) is a deferred concept and is *not* the same thing as a TestCase.

## Considered Options

- **Synthetic id per proposal, dedup as a separate query** (rejected): two code paths to keep in sync (planner-side filter and dispatcher-side guard), graph fills with near-duplicate proposal nodes, and "have we run this before?" becomes a join on many fields instead of a key lookup.
- **Cross-Engagement TestCase identity (the catalog view)** (rejected for TestCase, deferred as `TestTemplate`): mixing TestCases across Engagements collapses audit boundaries and complicates finding attribution. The reusable-test-across-engagements concept is a different object.

## Consequences

- `payload_hash` covers the concrete bytes after any payload-template substitution; tests that carry no payload use sentinel `sha256("")` to avoid Cypher null-handling pain.
- The unused half of the target tuple (`target_parameter_id` for boundary-targeted tests, `target_trust_boundary_id` for endpoint-targeted tests) stays null and is normalized out before hashing.
- `AuthContext` is part of the key: the same test under a different auth state is a distinct TestCase — which is the whole point of auth-coverage analysis.
- The LLM proposing the "same" test slightly rephrased self-dedupes at commit. No application-level dedup loop is required.
