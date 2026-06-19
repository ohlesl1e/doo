"""Interpreter follow-ups + InterpreterMode strategy (S8/#93, ADR-0042/0045).

Pure: `select_interpreter_mode` picks the strategy; `FreelanceMode` raises (the
unimplemented seam). Container: `ConfirmMode.handle_follow_ups` runs each follow-up
through the slice-3 Validator + commit — one in-scope follow-up lands at
`review_status=proposed` / `source=llm-interpreter`, one out-of-scope is discarded.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from doo.dispatch.interpreter.loop import INTERPRETER_PROMPT_VERSION
from doo.dispatch.interpreter.mode import (
    ConfirmMode,
    FreelanceMode,
    select_interpreter_mode,
)
from doo.dispatch.interpreter.models import FollowUpProposal
from doo.ids import AuthContextId, EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.graph_state import Neo4jGraphState
from doo.ontology.schema import apply_schema
from doo.setup.loader import PlannedMutation

ENG = "eng-followups"
HOSTNAME = "api.example.com"


# --- pure: strategy selection + the freelance seam ------------------------


def test_select_interpreter_mode() -> None:
    assert isinstance(select_interpreter_mode("confirm"), ConfirmMode)
    assert isinstance(select_interpreter_mode("freelance"), FreelanceMode)


def test_freelance_mode_raises() -> None:
    fu = FollowUpProposal(
        test_class="idor", payload_class="no-payload", target_handle="TARGET",
        justification="x", expected_outcome="y",
    )
    with pytest.raises(NotImplementedError, match="freelance"):
        FreelanceMode().handle_follow_ups(
            (fu,), neo4j=None, engagement_id=EngagementId(ENG),  # type: ignore[arg-type]
            auth_context_id=AuthContextId("ac-x"),
            default_target_endpoint_id="ep-in", now=datetime.now(UTC),
        )


# --- container: confirm-mode commit + discard -----------------------------


@pytest.fixture
def neo4j_client(neo4j_container) -> Iterator[Neo4jClient]:
    client = Neo4jClient.connect(
        neo4j_container.get_connection_url(),
        neo4j_container.username,
        neo4j_container.password,
    )
    with client.driver.session() as session:
        apply_schema(session, edition=client.server_edition())
    try:
        yield client
    finally:
        client.close()


def _seed(neo4j: Neo4jClient) -> None:
    now = datetime.now(UTC)
    cross = {
        "source": "manual", "source_id": None, "confidence": 1.0,
        "confidence_method": "manual", "first_seen": now, "last_seen": now,
        "ingested_at": now, "status": "active",
    }
    Neo4jGraphState(neo4j).apply_mutations((
        PlannedMutation(kind="scope_create", properties={
            "content_hash": f"scope-{ENG}",
            "rules": {
                "host_patterns": [HOSTNAME], "allowed_methods": ["*"],
                "allowed_path_patterns": ["/api/**"], "payload_class_denylist": [],
                "rate_limit": None, "time_window": None, "required_headers": [],
            }, **cross,
        }),
        PlannedMutation(kind="engagement_create", properties={
            "id": ENG, "name": ENG, "description": None, "time_window": None,
            "kill_switch": {"backend": "redis"}, "session_cookie_names": [],
            "identity_key": None, "environment": "staging", **cross,
        }),
        PlannedMutation(kind="engagement_under_scope", properties={
            "engagement_id": ENG, "scope_content_hash": f"scope-{ENG}",
        }),
    ))
    # ep-in (in scope: /api/**) and ep-out (out of scope: /admin/**), plus an AC.
    neo4j.execute_write(
        """
        MERGE (h:Host {engagement_id:$eid, id:'h-1'})
        ON CREATE SET h.scheme='https', h.canonical_hostname=$host, h.port=null,
                      h.is_ip_literal=false, h += $cross
        MERGE (ein:Endpoint {engagement_id:$eid, id:'ep-in'})
        ON CREATE SET ein.method='GET', ein.path_template='/api/orders', ein += $cross
        MERGE (ein)-[:ON_HOST]->(h)
        MERGE (eout:Endpoint {engagement_id:$eid, id:'ep-out'})
        ON CREATE SET eout.method='GET', eout.path_template='/admin/secrets', eout += $cross
        MERGE (eout)-[:ON_HOST]->(h)
        MERGE (ac:AuthContext {engagement_id:$eid, id:'ac-x'})
        ON CREATE SET ac.is_anonymous=false, ac.tier='declared', ac += $cross
        """,
        eid=ENG, host=HOSTNAME, cross=cross,
    )


def test_confirm_mode_commits_valid_discards_out_of_scope(neo4j_client: Neo4jClient) -> None:
    _seed(neo4j_client)
    valid = FollowUpProposal(
        test_class="idor", payload_class="no-payload", target_handle="TARGET",
        justification="same endpoint exposes a sibling object id",
        expected_outcome="attacker reads another user's order",
    )
    out_of_scope = FollowUpProposal(
        test_class="idor", payload_class="no-payload", target_handle="ep-out",
        justification="admin endpoint looked interesting",
        expected_outcome="should be denied",
    )

    outcome = ConfirmMode().handle_follow_ups(
        (valid, out_of_scope),
        neo4j=neo4j_client,
        engagement_id=EngagementId(ENG),
        auth_context_id=AuthContextId("ac-x"),
        default_target_endpoint_id="ep-in",  # TARGET resolves here (in scope)
        now=datetime.now(UTC),
    )
    assert outcome.committed == 1
    assert outcome.discarded == 1  # ep-out is out of scope (/api/** only)

    # The committed follow-up is a proposed TestCase with the interpreter source.
    rows = neo4j_client.execute_read(
        """
        MATCH (t:TestCase {engagement_id:$eid})-[:TARGETS_ENDPOINT]->(e:Endpoint {id:'ep-in'})
        RETURN t.review_status AS rs, t.source AS src, t.code_version AS cv,
               t.generator AS gen
        """,
        eid=ENG,
    )
    assert len(rows) == 1
    assert rows[0]["rs"] == "proposed"
    assert rows[0]["src"] == "llm-interpreter"
    assert rows[0]["gen"] == "interpreter"
    assert rows[0]["cv"] == INTERPRETER_PROMPT_VERSION
    # Nothing committed against the out-of-scope endpoint.
    oos = neo4j_client.execute_read(
        "MATCH (t:TestCase {engagement_id:$eid})-[:TARGETS_ENDPOINT]->(:Endpoint {id:'ep-out'}) "
        "RETURN count(t) AS n",
        eid=ENG,
    )
    assert oos[0]["n"] == 0
