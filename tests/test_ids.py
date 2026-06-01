"""Sanity check: typed-id aliases construct cleanly and stay assignable to str.

`NewType` is a runtime-noop, but the test reminds future readers that these
are not Pydantic models — they're a mypy aid.
"""

from doo.ids import (
    AuthContextId,
    EngagementId,
    ObservationId,
    PrincipalId,
    ScopeContentHash,
    Sha256Hex,
    SpanId,
    TraceId,
)


def test_newtypes_construct_and_compare_as_strings() -> None:
    eid = EngagementId("acme-2026")
    pid = PrincipalId("test_user_a")
    assert eid == "acme-2026"
    assert pid == "test_user_a"
    assert eid != pid


def test_newtypes_can_be_passed_where_strings_expected() -> None:
    aid = AuthContextId("acme-2026:" + "0" * 64)
    sid = SpanId("0" * 16)
    tid = TraceId("0" * 32)
    obs = ObservationId("obs-1")
    sch = ScopeContentHash("0" * 64)
    sha = Sha256Hex("0" * 64)
    for v in (aid, sid, tid, obs, sch, sha):
        assert isinstance(v, str)
