"""Ontology layer (L3) — Neo4j schema bootstrap and graph plumbing.

Slice 1 ships only the schema bootstrap: idempotent constraints and indexes
that every L3 process startup must run. The commit interface and entity
resolvers land in slice 2 (T2).
"""

from doo.ontology.schema import (
    ENGAGEMENT_SCOPED_NODE_LABELS,
    SHARED_NODE_LABELS,
    SchemaStatement,
    apply_schema,
    schema_statements,
)

__all__ = [
    "ENGAGEMENT_SCOPED_NODE_LABELS",
    "SHARED_NODE_LABELS",
    "SchemaStatement",
    "apply_schema",
    "schema_statements",
]
