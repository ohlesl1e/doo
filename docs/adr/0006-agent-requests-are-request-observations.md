# Agent-sent requests are RequestObservations, unified with passive traffic

Our dispatcher's outbound HTTP requests are stored as `RequestObservation` nodes — the same node type used for passive traffic from Burp/HAR/nuclei — with `source = "agent"` distinguishing them. The `TestCase` that authored a request points at the resulting observation via an `EXECUTED_AS` edge (cardinality 0..N — retries and parameter sweeps add edges, not new TestCases). Coverage, rate-limit, and budget queries then run over one unified observation set, with `source` as a filter when origin matters.

## Considered Options

- **A separate `Execution` entity attached to TestCase** (rejected): forces a `UNION` over `RequestObservation` and `Execution` in every coverage query that asks "what endpoints have we hit?" — for no benefit, since the existing `source` field already separates active from passive when a query needs to.

## Consequences

- The response to an agent request feeds the same observation→inference plumbing as a Burp capture — new `Parameter` observations, new `ResponseArtifact`s, potential `Asset` promotions — for free.
- The deterministic-construction rule is unchanged: the Executor builds the bytes; the LLM does not. Unification is about the shape of the stored record, not who authored the request.
- `TestCase.status` becomes largely derivable from `EXECUTED_AS` edges + attached `Finding`s, rather than a free-floating field that can drift from reality.
