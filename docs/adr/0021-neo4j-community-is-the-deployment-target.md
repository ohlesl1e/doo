# Neo4j Community Edition is the deployment target; no Enterprise-only features

doo runs on **Neo4j Community Edition**, full stop. The project is open-source and must run on local hardware a single researcher owns, with no licence to buy. No part of the design may depend on a Neo4j Enterprise feature. Where Enterprise offers a database-level guarantee we want, we reproduce that guarantee in application code instead.

This makes explicit a constraint that was implicit in the stack table (`neo4j:5-community`) and already shaped one decision (ADR-0017 rejected per-engagement databases because Community supports only one user database). It surfaced concretely in slice 1: `apply_schema` emitted property-existence constraints (`REQUIRE n.<field> IS NOT NULL`), which are Enterprise-only and fail at bootstrap on Community.

## What Community gives us, and where it's enough

Everything doo's architecture relies on is in Community:

- **Uniqueness constraints** (single and composite, `IS UNIQUE`) — these back L3 commit idempotency (ADR-0016) and engagement-scoped identity (ADR-0017). Community-supported.
- **Indexes** — btree/range on `engagement_id` and identity fields, plus fulltext and vector indexes (the latter for future LLM-similarity work) are all Community since 5.13.
- **APOC core**, deterministic Cypher for coverage analysis, single-database property-scoped multi-tenancy.

The one Enterprise feature we were using — **property-existence constraints** — is redundant: non-null / provenance presence is already guaranteed upstream by the Pydantic layer-boundary models and the L3 commit-time scoping gate (ADR-0017), which is the single code path that mutates the graph. The database refusing a null is a belt-and-suspenders check we don't need when the only writer already validates.

## Mechanism

`apply_schema` is **edition-aware**: it detects the server edition and applies the existence constraints only on Enterprise, skipping them with a logged warning on Community while still applying all uniqueness constraints and indexes. The schema therefore self-adapts and stays portable — a researcher on Community gets a working graph; if someone ever runs Enterprise they get the extra DB-level net for free. Non-null remains enforced in code regardless of edition.

## Other Enterprise features, and why we don't need them

- **Multiple named databases** (per-engagement isolation at the DB level) — Enterprise. Rejected already in ADR-0017; doo isolates engagements by an `engagement_id` property + the commit-time gate within a single database. If hard isolation is ever required, the open-source answer is **separate Community instances/containers per engagement**, not Enterprise multi-database.
- **RBAC / fine-grained sub-graph security** — Enterprise. Not needed: doo is a single-tester tool, and the one trust split that matters (the kill-switch) lives in Redis, not Neo4j (ADR-0014).
- **Causal clustering / HA, online (hot) backup, LDAP/Kerberos** — Enterprise. Irrelevant for a local single-operator research tool; offline `neo4j-admin dump` covers backup.

## Considered Options

- **Switch graph databases** (rejected): the only Enterprise dependency was a feature we can enforce in code; a DB switch would discard ONTOLOGY.md, the Cypher coverage queries, and the ADR corpus to solve a problem that doesn't require solving. If Community is ever genuinely outgrown, Cypher-compatible open-source engines exist (Memgraph, KùzuDB) — but that is not a decision for now and nothing in the current roadmap forces it.
- **Run Neo4j Enterprise under its dev/eval terms** (rejected): contradicts the open-source, runs-on-owned-hardware goal and reintroduces a licence boundary the project exists to avoid.
- **Keep DB existence constraints, require Enterprise** (rejected): same licence problem; and it duplicates a guarantee the commit gate already provides.

## Consequences

- DB-level non-null enforcement is a **code invariant, not a schema invariant**. The L3 commit gate and the Pydantic models are now the *sole* guarantee that provenance/confidence/`engagement_id` are present on every node (the "provenance on every node, no exceptions" hard rule). Their unit tests carry that weight; losing them would silently weaken the rule.
- Any future feature proposal that reaches for an Enterprise-only Neo4j capability is out of bounds by default and must either find a Community-native mechanism or trigger an explicit revisit of this ADR.
- The grill-queue "pick a default and move" entry for Neo4j local dev (`neo4j:5-community`) is now a hard architectural constraint, not just a dev-environment convenience.
- This ADR amends the enforcement discussion in ADR-0017: of its "three layers" (uniqueness constraints, commit-time gate, query convention), the uniqueness constraints stay DB-enforced on Community; the existence dimension moves entirely to the commit-time gate.
