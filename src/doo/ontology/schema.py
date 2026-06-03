"""Neo4j schema bootstrap.

Idempotent `CREATE CONSTRAINT ... IF NOT EXISTS` for every scoped node type
per ADR-0017, plus indexes on `engagement_id` for every scoped label, plus the
shared structural nodes (`Engagement`, `Scope`) per their identity rules.

Includes slice-4 hedge constraints (`TestCase`, `Finding`) — the hedge applies
to schema too, so that when slice 4 lands we are not migrating constraints
under live data.

Runs on every L3 process startup. The statements are deterministic and ordered
so two parallel bootstraps converge to the same state; Neo4j's `IF NOT EXISTS`
handles the race.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from doo.observability.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class SchemaStatement:
    """One Cypher schema statement plus a human label for logging.

    `enterprise_only` flags property-existence constraints, which require Neo4j
    Enterprise. On Community the bootstrap skips these (see `apply_schema`); the
    non-null guarantee is still enforced by the Pydantic models + the commit-time
    scoping/validation gate.
    """

    name: str
    cypher: str
    enterprise_only: bool = False


class _CypherRunner(Protocol):
    """Minimal duck-type for the neo4j driver session / transaction.

    We accept anything with `.run(cypher)` so the schema can be applied against
    a real Neo4j driver, a testcontainer session, or a fake in unit tests.
    """

    def run(self, cypher: str, /) -> object: ...  # pragma: no cover - protocol


# Shared structural nodes: identity is engagement-independent (ADR-0017).
SHARED_NODE_LABELS: tuple[str, ...] = ("Engagement", "Scope")

# Engagement-scoped node labels per ADR-0017. Every one must have
# `engagement_id` in its identity tuple.
ENGAGEMENT_SCOPED_NODE_LABELS: tuple[str, ...] = (
    "RequestObservation",
    "ParseFailure",
    "Endpoint",
    "Parameter",
    "ParameterSemantic",
    "Host",
    "AuthContext",
    "Principal",
    "Tenant",
    "TrustBoundary",
    "Asset",
    "ObservedValue",
    "TestCase",
    "Finding",
)


def schema_statements() -> tuple[SchemaStatement, ...]:
    """Return the full ordered schema bootstrap.

    Order: shared-node constraints first (they are roots), then engagement-
    scoped constraints (which depend conceptually on Engagement), then indexes.
    Each statement is idempotent via `IF NOT EXISTS`.
    """

    out: list[SchemaStatement] = []

    # --- Shared structural nodes ---
    # Engagement.id is unique (the root, ADR-0017).
    out.append(
        SchemaStatement(
            name="engagement_id_unique",
            cypher=(
                "CREATE CONSTRAINT engagement_id_unique IF NOT EXISTS "
                "FOR (n:Engagement) REQUIRE n.id IS UNIQUE"
            ),
        )
    )
    # Scope.content_hash is unique (ADR-0017 — Scope is the shared
    # program-level abstraction).
    out.append(
        SchemaStatement(
            name="scope_content_hash_unique",
            cypher=(
                "CREATE CONSTRAINT scope_content_hash_unique IF NOT EXISTS "
                "FOR (n:Scope) REQUIRE n.content_hash IS UNIQUE"
            ),
        )
    )

    # --- Engagement-scoped uniqueness constraints ---
    # Each scoped node's identity tuple starts with `engagement_id`. The
    # additional fields come from the per-node identity rules in CONTEXT.md.
    scoped_identity: dict[str, tuple[str, ...]] = {
        # Observation layer.
        "RequestObservation": ("engagement_id", "observation_id"),
        "ParseFailure": ("engagement_id", "observation_id"),
        # Inference layer.
        "Endpoint": ("engagement_id", "method", "host_id", "path_template"),
        "Parameter": ("engagement_id", "endpoint_id", "location", "name"),
        "ParameterSemantic": ("engagement_id", "parameter_id", "semantic_kind"),
        "Host": ("engagement_id", "scheme", "canonical_hostname", "port"),
        "AuthContext": ("engagement_id", "auth_hash"),
        # Principal identity is two-tier per ADR-0010; `identity_key` covers
        # declared (manual label) and discovered (priority-list hash) tiers.
        "Principal": ("engagement_id", "identity_key"),
        "Tenant": ("engagement_id", "kind", "normalized_value"),
        "TrustBoundary": ("engagement_id", "kind", "between_a_id", "between_b_id"),
        "Asset": ("engagement_id", "kind", "normalized_value"),
        "ObservedValue": ("engagement_id", "value_hash"),
        # Slice-4 hedge: TestCase and Finding.
        "TestCase": ("engagement_id", "key_hash"),
        "Finding": ("engagement_id", "id"),
    }

    for label, props in scoped_identity.items():
        prop_list = ", ".join(f"n.{p}" for p in props)
        constraint_name = f"{label.lower()}_identity_unique"
        if len(props) == 1:
            require = f"{prop_list} IS UNIQUE"
        else:
            require = f"({prop_list}) IS UNIQUE"
        out.append(
            SchemaStatement(
                name=constraint_name,
                cypher=(
                    f"CREATE CONSTRAINT {constraint_name} IF NOT EXISTS "
                    f"FOR (n:{label}) REQUIRE {require}"
                ),
            )
        )

    # --- Indexes on engagement_id for every scoped label ---
    for label in ENGAGEMENT_SCOPED_NODE_LABELS:
        idx_name = f"{label.lower()}_engagement_id_idx"
        out.append(
            SchemaStatement(
                name=idx_name,
                cypher=(
                    f"CREATE INDEX {idx_name} IF NOT EXISTS "
                    f"FOR (n:{label}) ON (n.engagement_id)"
                ),
            )
        )

    # --- Property-existence constraints for the cross-cutting fields ---
    # ADR-0005: every entity carries the seven fields + status. Enforce at the
    # graph boundary as defense-in-depth alongside the Pydantic mixin.
    cross_cutting_fields = (
        "source",
        "confidence",
        "confidence_method",
        "first_seen",
        "last_seen",
        "ingested_at",
        "status",
    )
    # TODO(slice-1 decision): DB-level existence constraints need Neo4j Enterprise
    # — see ARCHITECTURE.md edition decision. The project standard is
    # `neo4j:5-community`, where `REQUIRE ... IS NOT NULL` fails. These are flagged
    # `enterprise_only=True` and skipped on Community by `apply_schema`; the
    # non-null guarantee is upheld in code by the Pydantic models + the commit-time
    # scoping/validation gate.
    for label in ENGAGEMENT_SCOPED_NODE_LABELS:
        for field in cross_cutting_fields:
            cname = f"{label.lower()}_{field}_exists"
            out.append(
                SchemaStatement(
                    name=cname,
                    cypher=(
                        f"CREATE CONSTRAINT {cname} IF NOT EXISTS "
                        f"FOR (n:{label}) REQUIRE n.{field} IS NOT NULL"
                    ),
                    enterprise_only=True,
                )
            )

    return tuple(out)


# Marker substring Neo4j Community emits when an Enterprise-only constraint is
# attempted, used as a belt-and-braces guard alongside the edition probe.
_ENTERPRISE_REQUIRED_MARKER = "requires Neo4j Enterprise Edition"


def apply_schema(
    session: _CypherRunner, *, edition: str = "community"
) -> tuple[SchemaStatement, ...]:
    """Apply the schema bootstrap against an open Neo4j session/transaction.

    Returns the statements that were *issued* (in order) so callers can log.
    `IF NOT EXISTS` makes each statement idempotent.

    Edition-aware (slice-1 decision): property-existence constraints
    (`enterprise_only=True`) require Neo4j Enterprise. On `edition != "enterprise"`
    they are skipped with a logged warning; uniqueness constraints + indexes
    (which back idempotency and work on Community) always apply. If an
    enterprise-only statement somehow slips through and the server rejects it with
    the Enterprise-required error, that single statement is swallowed so the
    bootstrap stays green on Community.
    """

    is_enterprise = edition.lower() == "enterprise"
    issued: list[SchemaStatement] = []
    skipped = 0
    for stmt in schema_statements():
        if stmt.enterprise_only and not is_enterprise:
            skipped += 1
            continue
        try:
            session.run(stmt.cypher)
        except Exception as exc:  # noqa: BLE001
            if stmt.enterprise_only and _ENTERPRISE_REQUIRED_MARKER in str(exc):
                skipped += 1
                continue
            raise
        issued.append(stmt)
    if skipped:
        log.warning(
            "schema.existence_constraints_skipped",
            count=skipped,
            edition=edition,
            reason="property-existence constraints require Neo4j Enterprise; "
            "non-null enforced in code (Pydantic + commit gate)",
        )
    return tuple(issued)
