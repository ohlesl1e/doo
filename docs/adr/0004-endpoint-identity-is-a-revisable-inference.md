# Endpoint identity is a revisable inference, not frozen at ingest

In black-box mode there is no route table, so whether a path segment (`/orgs/42`) is a parameter must be guessed before enough requests are seen to be sure. We therefore do not compute an Endpoint's path-template once at ingest and freeze it into the node's identity. Instead the **concrete path** is stored on the `RequestObservation`, the inferred **template** on the `Endpoint`, and the `HIT` membership edge is a revisable inference carrying confidence. Re-templating — merging `/orgs/42` and `/orgs/43` into `/orgs/{org_id}`, or splitting a position that turns out to be two real routes — is an edge re-grouping, not destructive node surgery.

## Considered Options

- **Commit the template at ingest and bake it into Endpoint identity** (rejected): every time a guess is revised it forces merging/splitting Endpoint nodes and re-pointing every attached `RequestObservation`, `TestCase`, and `Finding` — on the hot path, with provenance-loss risk.

## Consequences

The templating heuristics (trie + multiplicity, value-shape cold-start prior, `v\d+` version guard, literal-sibling precedence, self-reference value flagging) are *allowed to be wrong early* and improve as evidence arrives, because correction is cheap. See `ONTOLOGY.md` Step 3 for the mechanism.
