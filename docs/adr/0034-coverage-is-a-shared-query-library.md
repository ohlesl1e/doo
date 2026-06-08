# The coverage analyzer is a shared query library, not a CLI-only tool

The slice-2 coverage analyzer is a **pull / ephemeral library** of deterministic query functions (`run_c1`, `run_c2`, `run_c2b`, `run_c3`) returning per-query Pydantic result models. It reads the graph at a settle point and writes nothing back — there is no `CoverageGap` node (gaps are derived at query time, the same discipline as `is_in_scope` (ADR-0020) and confidence decay (ADR-0005)). Both the human **CLI** (`doo coverage …`) and the slice-3 **planner** are thin consumers that import the *same* library; neither re-implements the C-queries.

## Why a library, not a CLI

The planner (slice 3) needs the same coverage signal a human does. If the CLI owned the queries and the planner re-ran its own Cypher, the two definitions of "gap" would silently drift — the planner would propose tests against a coverage view the human never sees. One library, one definition. This mirrors `is_in_scope`, which is a single helper shared by planner, coverage, and audit (ADR-0020), rather than re-expressed per consumer.

## Relation to "consumers query Neo4j directly"

ARCHITECTURE.md says consumers query Neo4j directly. That is about **not** building a read-proxy in front of the write API — it is not a mandate that every consumer rewrite the coverage queries. Coverage queries *are* the shared read code; the CLI and planner call into them and still talk to Neo4j directly through that shared layer. No contradiction.

## Per-query typed models, not a generic envelope

Results are per-query Pydantic models over a small `CoverageResult` base (`engagement_id`, `query_id`, `generated_at`), not a single generic `CoverageGap` bag. The queries return genuinely different shapes — C1 yields Endpoints; C2 yields `(A, B, endpoint, evidence)`; C2b yields `(endpoint, [per-principal evidence])`; C3 yields pivots — and the ADR-0033 soft-200 evidence tuples `(status, size, body_sha256)` only make sense per-query. A generic envelope would be lossy. The CLI renders these as human tables by default and as `--json` (the planner / regression-fixture form) from one serialization.

## Considered Options

- **CLI owns the queries; planner re-implements** (rejected): guarantees drift between the human's coverage view and the planner's, defeating the point of a shared signal.
- **Materialize `CoverageGap` nodes a consumer reads** (rejected, see slice-2 scope in `grill-queue.md` and ADR-0022): recreates the staleness/cascade problem that query-time derivation (ADR-0020/0005) exists to avoid.
- **One generic result envelope** (rejected): lossy across four structurally different query shapes.
