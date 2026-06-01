# Engagement setup may declare tester-side facts only

Setup declares only facts a real bug-bounty hunter would have at engagement start without privileged access: `Engagement` metadata, `Scope` rules (the program's public ROE), declared `Principal`s (test accounts the tester controls, their `AuthContext` token material, and any identifying signals the tester observed from warm-up traffic against their own accounts). Setup may **not** declare target-side facts — endpoint inventories, parameter lists, response schemas, tenant identifiers belonging to other actors. Those enter through L1 ingestion as observations with provenance.

The litmus test: *would a real hunter have this on day zero without insider access?* Yes → allowed at setup. No → banned; must surface through ingestion.

Format is **YAML loaded by a Pydantic-typed `EngagementConfig`**. Tokens are env-var references (`token: ${VAR}`), never inline. The loader is the only code; YAML is the only declarative surface. The loader produces two outputs from one config: graph mutations creating `Engagement` / `Scope` / declared `Principal` / `AuthContext` nodes with `source = "manual"`, `confidence = 1.0`, `confidence_method = "manual"`; and an OPA `data` bundle generated from the `Scope` section (per ADR-0003).

The Q1-compliance discipline is on the tester: the YAML format doesn't mechanically enforce that `known_signals` came from warm-up traffic against the tester's own accounts. Mechanical enforcement (e.g., requiring a HAR fixture in the engagement that contains every declared signal) is overhead we punt on.

## Considered Options

- **Python setup module instead of YAML** (rejected): full power, but invites `for endpoint in known_endpoints: seed(...)` — the banned path. Declarative-only YAML enforces the discipline by being lower-power.
- **Graph-seed script (direct Cypher)** (rejected): skips the Pydantic validation layer, couples setup to the Neo4j schema, can't drive OPA-bundle generation without duplicating data, hides intent behind imperative writes.
- **Allow swagger / OpenAPI as a setup input** (rejected): the line we are drawing exists exactly to keep this out. If a hunter has a swagger spec the program publishes publicly, it can be ingested via L1 with `source = "swagger"`, marked observed-not-declared.

## Consequences

- The `EngagementConfig` Pydantic model is the schema-of-record for setup; schema migrations are versioned with the loader.
- Tokens never appear in `git diff` of a config file — only env-var references do. Operational secret discipline (env, secrets manager) lives outside the repo.
- Adding a new setup-time fact (e.g., the engagement's allowed time window) requires a schema bump and a fresh question against the Q1 line: is this a tester-side fact?
- The honour-system discipline on bootstrap signals means a sloppy tester could pre-seed unfair knowledge. The audit log captures `source = "manual"` so reviewers can flag it; correctness depends on review, not the format.
