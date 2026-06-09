"""Unit tests for the pure path-templating algorithm (T3 deep module C).

No docker / no graph — these pin the deterministic templating heuristics from
ONTOLOGY.md Step 3 / ADR-0004: multiplicity, cold-start shape priors, version
guard, literal-sibling router precedence, parameter naming, self-reference.
"""

from __future__ import annotations

from doo.canonical.templating import (
    SELF_REFERENCE_VALUES,
    shape_of,
    template_paths,
)


def _templates(paths: list[str]) -> dict[str, str]:
    return {p: tp.path_template for p, tp in template_paths(paths).items()}


def test_multiplicity_collapses_integer_ids() -> None:
    out = template_paths(["/users/42", "/users/87", "/users/123"])
    assert {tp.path_template for tp in out.values()} == {"/users/{user_id}"}
    tp = out["/users/42"]
    assert tp.confidence == 1.0  # multiplicity -> full confidence
    assert [p.name for p in tp.parameters] == ["user_id"]
    assert tp.parameters[0].index == 1  # 0-based segment position


def test_parameter_name_from_preceding_segment() -> None:
    t = _templates(["/orgs/abc-123/projects", "/orgs/def-456/projects"])
    assert set(t.values()) == {"/orgs/{org_id}/projects"}


def test_version_segment_stays_literal_under_multiplicity() -> None:
    t = _templates(
        [
            "/v1/orgs/abc-123/projects",
            "/v2/orgs/def-456/projects",
        ]
    )
    assert t["/v1/orgs/abc-123/projects"] == "/v1/orgs/{org_id}/projects"
    assert t["/v2/orgs/def-456/projects"] == "/v2/orgs/{org_id}/projects"


def test_literal_sibling_wins_over_parameter() -> None:
    t = _templates(["/users/42", "/users/87", "/users/settings"])
    assert t["/users/42"] == "/users/{user_id}"
    assert t["/users/87"] == "/users/{user_id}"
    assert t["/users/settings"] == "/users/settings"  # router precedence


def test_cold_start_single_uuid_is_low_confidence_param() -> None:
    out = template_paths(["/files/550e8400-e29b-41d4-a716-446655440000"])
    tp = next(iter(out.values()))
    assert tp.path_template == "/files/{file_id}"
    assert tp.confidence < 1.0
    assert tp.parameters[0].shape == "uuid"


def test_cold_start_ordinary_word_stays_literal() -> None:
    out = template_paths(["/about"])
    tp = out["/about"]
    assert tp.path_template == "/about"
    assert tp.parameters == ()
    assert tp.confidence == 1.0


def test_self_reference_value_does_not_block_collapse() -> None:
    t = _templates(["/users/42", "/users/87", "/users/me"])
    assert t["/users/42"] == "/users/{user_id}"
    assert t["/users/me"] == "/users/{user_id}"  # me is a value of the param


def test_self_reference_alone_stays_literal() -> None:
    # `me` with no id-shaped sibling is just a word.
    t = _templates(["/users/me"])
    assert t["/users/me"] == "/users/me"


def test_different_lengths_never_share_template() -> None:
    t = _templates(["/products", "/products/42"])
    assert t["/products"] == "/products"
    # /products/42 cold-starts to a param at low confidence (integer shape).
    assert t["/products/42"] == "/products/{product_id}"


def test_deterministic_regardless_of_order() -> None:
    a = _templates(["/users/1", "/users/2", "/users/settings"])
    b = _templates(["/users/settings", "/users/2", "/users/1"])
    assert a == b


def test_interior_word_multiplicity_collapses() -> None:
    # Two ordinary words at an *interior* slot that reconverges to /projects
    # collapse on pure multiplicity (the re-templating revision case).
    t = _templates(["/orgs/acme/projects", "/orgs/globex/projects"])
    assert t["/orgs/acme/projects"] == "/orgs/{org_id}/projects"
    assert t["/orgs/globex/projects"] == "/orgs/{org_id}/projects"


def test_distinct_same_length_routes_keep_their_literal_prefix() -> None:
    # Regression for #70: two different routes of equal segment-length must NOT
    # have their resource-type literal collapsed just because the position holds
    # >=2 distinct words. They do not reconverge (`/projects` vs `/files`), so the
    # literal prefix stays and each route templates its own value slot.
    t = _templates(
        [
            "/orgs/42/projects",
            "/orgs/43/projects",
            "/workspaces/ws-a/files",
            "/workspaces/ws-b/files",
        ]
    )
    assert t["/orgs/42/projects"] == "/orgs/{org_id}/projects"
    assert t["/workspaces/ws-a/files"] == "/workspaces/{workspace_id}/files"


def test_distinct_word_routes_with_matching_suffix_still_separate() -> None:
    # Even when the leaf word matches (`/posts` vs `/posts`), differing
    # resource-type prefixes are distinct routes and stay literal (#70).
    t = _templates(["/orgs/1/posts", "/orgs/2/posts", "/users/9/posts", "/users/8/posts"])
    assert t["/orgs/1/posts"] == "/orgs/{org_id}/posts"
    assert t["/users/9/posts"] == "/users/{user_id}/posts"


def test_leaf_words_stay_distinct_routes() -> None:
    # Distinct words at a *leaf* are sibling routes, not a parameter.
    t = _templates(["/products", "/about"])
    assert t["/products"] == "/products"
    assert t["/about"] == "/about"


def test_single_interior_word_stays_literal_until_evidence() -> None:
    # Cold start: one observation keeps the word literal (revisable later).
    t = _templates(["/orgs/acme/projects"])
    assert t["/orgs/acme/projects"] == "/orgs/acme/projects"


def test_shape_of_classifies_segments() -> None:
    assert shape_of("42") == "integer"
    assert shape_of("550e8400-e29b-41d4-a716-446655440000") == "uuid"
    assert shape_of("deadbeefcafe") == "hex"
    assert shape_of("abc-123") == "id_slug"
    assert shape_of("v1") is None  # version guard
    assert shape_of("settings") is None
    assert "me" in SELF_REFERENCE_VALUES
