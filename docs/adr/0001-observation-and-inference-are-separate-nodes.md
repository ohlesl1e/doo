# Observation and inference are separate node types

Every fact in the black-box graph is either observed or inferred, and the two are always modelled as distinct node types — `RequestObservation`→`Endpoint`, `Parameter`→`ParameterSemantic`, `ResponseArtifact`→`Asset` — rather than one node carrying a `source`/`status` flag. We chose separation so an inference can be retracted (it can be wrong) without destroying the underlying observation, which we must never lose. This pattern governs every future node type: when adding one, decide which layer it belongs to.

## Considered Options

- **One node with a `source` field** (rejected): retracting an inference would mean mutating or deleting a node that also holds observed facts, risking loss of provenance and making "show me only what we actually saw" queries awkward.
