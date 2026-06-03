"""L4 ROE / policy.

Slice 1 ships the pure `is_in_scope` Scope evaluator (the query-time / planner
mirror of the dispatcher's OPA decision, per ADR-0020) and the deny-all Rego
skeleton (`scope.rego`). The OPA `data`-bundle generator and the real Rego
matching rules land in slice 4.
"""

from doo.policy.scope import (
    EndpointLike,
    HostLike,
    ProposedRequestLike,
    is_in_scope,
)

__all__ = [
    "EndpointLike",
    "HostLike",
    "ProposedRequestLike",
    "is_in_scope",
]
