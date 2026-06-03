"""Ontology layer (L3) — Neo4j schema bootstrap and graph plumbing.

Slice 1 ships the schema bootstrap (idempotent constraints/indexes every L3
process startup runs) and the engagement-scoped query helpers (`for_engagement`,
per ADR-0017). The commit interface and entity resolvers land in slice 2 (T2).
"""

from doo.ontology.commit import (
    CommitOrchestrator,
    CommitResult,
    EngagementScopeViolation,
    RedisSetNX,
    semantic_key,
)
from doo.ontology.graph_state import Neo4jGraphState
from doo.ontology.l3_worker import L3WorkerDeps, process_l2_event, run_l3_worker
from doo.ontology.queries import CypherFragment, for_engagement
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
    "CypherFragment",
    "SchemaStatement",
    "apply_schema",
    "for_engagement",
    "schema_statements",
    "CommitOrchestrator",
    "CommitResult",
    "EngagementScopeViolation",
    "RedisSetNX",
    "semantic_key",
    "Neo4jGraphState",
    "L3WorkerDeps",
    "process_l2_event",
    "run_l3_worker",
]
