"""Unit tests for the edition-aware schema bootstrap (T2 Neo4j blocker fix)."""

from __future__ import annotations

from doo.ontology.schema import apply_schema, schema_statements


class _RecordingSession:
    def __init__(self, *, fail_on: str | None = None) -> None:
        self.calls: list[str] = []
        self._fail_on = fail_on

    def run(self, cypher: str) -> object:
        if self._fail_on is not None and self._fail_on in cypher:
            raise RuntimeError(
                "Failed to create constraint: ... requires Neo4j Enterprise Edition."
            )
        self.calls.append(cypher)
        return None


def test_existence_constraints_are_flagged_enterprise_only() -> None:
    existence = [s for s in schema_statements() if s.name.endswith("_exists")]
    assert existence  # they still exist in the list
    assert all(s.enterprise_only for s in existence)
    # Uniqueness + indexes are NOT enterprise-only (work on Community).
    non_existence = [s for s in schema_statements() if not s.name.endswith("_exists")]
    assert all(not s.enterprise_only for s in non_existence)


def test_community_skips_existence_constraints() -> None:
    session = _RecordingSession()
    issued = apply_schema(session, edition="community")
    # No existence-constraint Cypher was issued on Community.
    assert all(not s.name.endswith("_exists") for s in issued)
    assert all("IS NOT NULL" not in c for c in session.calls)
    # Uniqueness constraints (idempotency backbone) WERE issued.
    assert any("IS UNIQUE" in c for c in session.calls)


def test_enterprise_applies_existence_constraints() -> None:
    session = _RecordingSession()
    issued = apply_schema(session, edition="enterprise")
    assert any(s.name.endswith("_exists") for s in issued)
    assert any("IS NOT NULL" in c for c in session.calls)


def test_enterprise_required_error_is_swallowed_as_belt_and_braces() -> None:
    # Even if an existence statement slips through with edition=enterprise but the
    # server rejects it, the bootstrap stays green.
    session = _RecordingSession(fail_on="IS NOT NULL")
    issued = apply_schema(session, edition="enterprise")
    # The failing existence statements were swallowed; uniqueness still applied.
    assert any("IS UNIQUE" in c for c in session.calls)
    assert all(not s.name.endswith("_exists") for s in issued)
