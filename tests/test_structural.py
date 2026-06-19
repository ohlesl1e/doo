"""L3Event tagged-union tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import TypeAdapter, ValidationError

from doo.events.structural import (
    EdgeCreated,
    EdgeRemoved,
    L3Event,
    NodeCreated,
    NodeUpdated,
    Reconciliation,
)


def _common() -> dict:
    return dict(
        commit_id="commit-1",
        trace_id="0" * 32,
        span_id="0" * 16,
        engagement_id="acme-2026",
        emitted_at=datetime.now(UTC),
    )


def test_node_created_constructs() -> None:
    ev = NodeCreated(
        **_common(),
        node_type="Endpoint",
        node_id="ep-1",
        properties={"method": "GET", "path_template": "/orgs/{org_id}/projects"},
    )
    assert ev.kind == "node_created"


def test_node_updated_changed_properties_shape() -> None:
    ev = NodeUpdated(
        **_common(),
        node_type="Endpoint",
        node_id="ep-1",
        changed_properties={"confidence": {"old": 0.6, "new": 0.9}},
    )
    assert ev.changed_properties["confidence"].old == 0.6
    assert ev.changed_properties["confidence"].new == 0.9


def test_edge_created_default_empty_properties() -> None:
    ev = EdgeCreated(
        **_common(),
        edge_type="HIT",
        from_node="ro-1",
        to_node="ep-1",
    )
    assert ev.properties == {}


def test_edge_removed_requires_known_reason() -> None:
    with pytest.raises(ValidationError):
        EdgeRemoved(
            **_common(),
            edge_type="HIT",
            from_node="ro-1",
            to_node="ep-1",
            reason="oops",  # not in the enum
        )


def test_reconciliation_construct() -> None:
    ev = Reconciliation(
        **_common(),
        node_type="Principal",
        survivor_id="p-1",
        retracted_id="p-2",
        reason="JWT sub matched declared",
    )
    assert ev.kind == "reconciliation"


def test_l3_event_extra_forbid() -> None:
    with pytest.raises(ValidationError):
        NodeCreated(
            **_common(),
            node_type="X",
            node_id="x",
            properties={},
            bogus=1,
        )


def test_l3_event_discriminator() -> None:
    adapter = TypeAdapter(L3Event)
    payload = {
        **_common(),
        "kind": "edge_created",
        "edge_type": "HIT",
        "from_node": "ro-1",
        "to_node": "ep-1",
    }
    parsed = adapter.validate_python(payload)
    assert isinstance(parsed, EdgeCreated)


def test_l3_event_rejects_bad_trace_id() -> None:
    with pytest.raises(ValidationError):
        NodeCreated(
            commit_id="c",
            trace_id="not-hex",
            span_id="0" * 16,
            engagement_id="e",
            emitted_at=datetime.now(UTC),
            node_type="X",
            node_id="x",
            properties={},
        )
