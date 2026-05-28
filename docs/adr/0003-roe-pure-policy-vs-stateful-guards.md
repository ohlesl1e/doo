# ROE is split into pure OPA policy decisions and stateful dispatcher guards

OPA/Rego evaluates a proposed request as a **pure function** of `input` (the proposed test — target, method, `PayloadClass`, target confidence, current time) and `data` (static scope/program policy). It does **not** read the graph. Constraints that depend on live aggregate state — rate limits, per-engagement test budgets, duplicate-test dedup, the kill-switch lease — are **not** expressed in Rego; they are deterministic guards in the dispatcher over the graph/counter store. Rule of thumb: anything the planner can snapshot into the proposal goes in OPA `input`; anything that's a live aggregate is a dispatcher guard.

This is why the payload **class** travels on the request document (`PayloadClass` as a tag) rather than payload strings living as graph nodes — OPA reads the class from `input`, not from Neo4j.

## Considered Options

- **Graph-aware Rego (`http.send` to Neo4j from policy)** (rejected): it would let policies reason over live state directly, but it breaks the "policy decisions are unit-testable in isolation" rule (CLAUDE.md), makes the same request return different answers as the graph changes (non-reproducible), and adds a network round-trip on the dispatch hot path. If you are reading this because querying the graph from Rego seems convenient — it was rejected on purpose.
