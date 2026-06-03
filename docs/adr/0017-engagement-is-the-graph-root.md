# `Engagement` is the graph root; observation and inference nodes are engagement-scoped

Every node in the doo graph belongs to exactly one of two categories. **Shared structural nodes** (`Engagement`, `Scope`) have engagement-independent identity. **Engagement-scoped nodes** — every other node type — carry `engagement_id` in their identity tuple and are isolated by it. The graph is rooted at `Engagement`; cross-engagement traversal is explicit, never accidental.

Scoped node types: `RequestObservation`, `ResponseArtifact`, `ParseFailure`, `Endpoint`, `Parameter`, `ParameterSemantic`, `Host`, `AuthContext`, `Principal`, `Tenant`, `TrustBoundary`, `Asset`, `ObservedValue`, `TestCase`, `Finding`. (TestCase was already engagement-scoped per ADR-0007; this generalises the same discipline to the rest.)

`Scope` is the *only* node besides `Engagement` itself that is sharable. Its identity is `content_hash = sha256(canonicalized(rule_document))`, so two engagements declaring identical rules collapse to one `Scope` node naturally. This is the de-facto "Project" abstraction: Acme's published program rules are one `Scope`; multiple campaigns (`Engagement`s) over years reference it.

## Why `Host` is scoped, not shared

Tempting to share `Host` on the argument that `api.example.com:443` is a global network identity. Rejected: if Engagement A discovers `internal-billing.corp` as an `Asset` and promotes it to a `Host` (per CONTEXT.md), sharing means Engagement B sees that discovery without ever having observed it — a Q1-of-G1 (ADR-0012) violation. The hostname's canonicalisation function is global; the `Host` *node* is per-engagement. Two engagements observing the same hostname produce two `Host` nodes.

## Enforcement, three layers

**Neo4j uniqueness constraints.** Every scoped node type has a constraint whose key tuple includes `engagement_id`. The database refuses cross-engagement collisions. Plus indexes on `engagement_id` for query performance.

**L3 commit-time gate.** The L3 commit function is the single code path that mutates the graph. It reads `engagement_id` from the inbound `L2Event` and refuses to create nodes whose `engagement_id` doesn't match, or edges whose endpoints disagree on `engagement_id`. Edges from a scoped node to a shared node are allowed only when the shared target is `Engagement` or `Scope`. Single enforcement point; covered by unit tests.

**Query convention.** All consumer-facing Cypher starts from the `Engagement` root or filters explicitly on `engagement_id`. A `for_engagement(eng_id)` helper makes this idiomatic; code review catches deviations. Cross-engagement queries (audit, prior-art lookup) are legitimate but **explicit traversals across `Engagement` root nodes**, never accidental joins through shared subgraphs.

## Engagement lifecycle

- **Create**: loader (per ADR-0012) writes the `Engagement` node with `status = "active"`, references its `Scope`, declares Principals.
- **Run**: every commit stamps `engagement_id`; constraints enforce; queries filter.
- **Pause**: `Engagement.status = "paused"`; observations may continue to ingest but the planner/dispatcher refuse to act. (Detail TBD when the dispatcher exists.)
- **Archive**: `Engagement.status = "archived"`; the scoped subgraph is cascaded to `status = "archived"`; queries default to filter archived out; audit traversal can opt in.
- **Drop**: real deletion via `MATCH (e:Engagement {id: $eng})-[*]->(n) DETACH DELETE`; destructive; leaves only the `Engagement` audit stub and the (potentially shared) `Scope`.

## Considered Options

- **Share inference-layer nodes, scope observation-layer nodes** (rejected): the boundary is queryable but easy to leak across — a query that traverses `Endpoint -[HIT]- RequestObservation` crosses from shared to scoped and risks pulling observations from other engagements into the current engagement's coverage view. Requires every cross-layer query to remember the engagement filter; discipline-dependent.
- **Separate Neo4j databases per Engagement** (rejected for MVP): strongest isolation, but Neo4j Community Edition supports only one database; Enterprise/Aura adds operational and licensing cost without enough payoff at MVP scale. Cross-engagement queries (audit, prior-art) become impossible without federation.
- **Engagement as a Neo4j label only, no identity participation** (rejected): labels alone don't enter uniqueness constraints. Two engagements observing the same endpoint identity would attempt to write the same node and collide on the existing identity hash, then either merge (data leak) or reject (commit failure on legitimate work). Property-in-identity is the strict mechanism.

## Consequences

- The identity rules in CONTEXT.md must be amended for every scoped node type to include `engagement_id` in the tuple. ADR-0007 (TestCase) already follows this pattern; the rest catch up.
- Cross-engagement reuse against the same target produces duplicate inference graphs (one `Endpoint`/`Host`/`Tenant`/... per engagement per concept). Acceptable cost for isolation; explicit cross-engagement queries are still possible by traversing `Engagement` roots.
- Engagement teardown is a graph cascade, not a database operation. Audit data survives by status flag, per ADR-0001's retraction discipline.
- The Q1-of-G1 setup boundary (ADR-0012) is mechanically protected at the graph layer: knowledge from one engagement cannot accidentally flow into another, because it isn't reachable through normal queries.
- The kill-switch lease (ARCHITECTURE.md L5) is engagement-scoped, matching the engagement's safety boundary. There is no sub-engagement safety unit; if finer-grained kill controls are ever needed, they go on `Engagement` properties, not on a new sub-node.
