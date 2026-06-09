"""Deterministic path templating (slice-1 T3, deep module C).

Pure functions — no I/O, no graph, no Redis, **no LLM** (CLAUDE.md hard rule).
Implements the `ONTOLOGY.md` Step 3 / ADR-0004 templating heuristics so that
concrete request paths observed under one `(method, host)` collapse into
revisable `Endpoint` path-templates.

The single public entry point is `template_paths`: given the full set of
concrete paths observed for one `(method, host)` it returns, for each concrete
path, the inferred `path_template`, the ordered path `Parameter` specs the
template introduces, and a confidence in `[0.0, 1.0]`.

Why the whole corpus, not one path at a time: templating is a *multiplicity*
inference (ADR-0004). A position only collapses to a parameter once ≥2 distinct
id-shaped values are seen at it (or, at cold start, a single strongly-id-shaped
value at low confidence). Because Endpoint identity is a revisable inference,
re-running this over a growing corpus is how an early literal guess self-corrects
into a parameter — the caller re-templates against the latest result.

Algorithm (trie + multiplicity + shape priors + guards):

- Group concrete paths by segment count, then walk the trie position by
  position. At each position, partition the sibling segment values into
  *literal-forced* (version segments `v\\d+`, ordinary words) and *id-shaped*
  (uuid / int / hex / id-suffixed slug).
- A position collapses to a single `{name}` parameter when it has ≥2 distinct
  id-shaped values (multiplicity), or — cold start — exactly one id-shaped value
  (confidence < 1.0). Literal-forced values keep their own branch, so literal
  sibling routes win over the parameter (router precedence: `/users/settings`
  coexists with `/users/{user_id}`).
- Version segments (`v\\d+`) stay literal even under multiplicity.
- The parameter name is derived deterministically from the preceding path
  segment (`users` -> `user_id`, `orgs` -> `org_id`); with no usable predecessor
  it falls back to `id` (disambiguated by position when several appear).
- Self-reference values (`me` / `current` / `self`) are values *of* the
  parameter, flagged so downstream IDOR analysis can see them — they do not
  force a literal split.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# --- Value-shape priors (cold-start + multiplicity id-likeness). ---

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_INT_RE = re.compile(r"^[0-9]+$")
# Long hex blob (object hash / sha-ish), >= 8 hex chars and no dashes.
_HEX_RE = re.compile(r"^[0-9a-fA-F]{8,}$")
# Mixed slug carrying a digit run, e.g. `abc-123`, `def-456`, `proj_42`.
_ID_SLUG_RE = re.compile(r"^[A-Za-z0-9]+[-_][A-Za-z0-9]*[0-9]+[A-Za-z0-9]*$")
# Version segment: stays literal even under multiplicity.
_VERSION_RE = re.compile(r"^v[0-9]+$")

# Self-reference values — values of the parameter, flagged for IDOR, never a
# literal split (CONTEXT.md "self-reference value").
SELF_REFERENCE_VALUES: frozenset[str] = frozenset({"me", "current", "self"})

# Confidence for a position confirmed by multiplicity (>=2 distinct id-shaped
# values) vs a single-observation cold-start shape prior.
_MULTIPLICITY_CONFIDENCE = 1.0
_COLD_START_CONFIDENCE = 0.5

ShapeKind = str  # one of {"uuid", "integer", "hex", "id_slug"}


def shape_of(segment: str) -> ShapeKind | None:
    """Return the id-shape of a segment, or `None` if it is an ordinary literal.

    Version segments (`v\\d+`) are deliberately *not* id-shaped — they stay
    literal even under multiplicity (ADR-0004 guard).
    """

    if _VERSION_RE.match(segment):
        return None
    if _UUID_RE.match(segment):
        return "uuid"
    if _INT_RE.match(segment):
        return "integer"
    if _ID_SLUG_RE.match(segment):
        return "id_slug"
    if _HEX_RE.match(segment):
        return "hex"
    return None


def _is_version(segment: str) -> bool:
    return bool(_VERSION_RE.match(segment))


def _singularize(word: str) -> str:
    """Crude deterministic singularisation for parameter naming.

    `users` -> `user`, `orgs` -> `org`, `projects` -> `project`,
    `categories` -> `category`. Good enough for parameter names; the exactness
    that matters is *determinism*, not linguistic correctness.
    """

    lower = word.lower()
    if lower.endswith("ies") and len(lower) > 3:
        return lower[:-3] + "y"
    if lower.endswith("ses") and len(lower) > 3:
        return lower[:-2]
    if lower.endswith("s") and len(lower) > 1:
        return lower[:-1]
    return lower


def _param_name(preceding_segment: str | None) -> str:
    """Derive a path-parameter name from the preceding (collection) segment.

    `/users/{X}` -> `user_id`; `/orgs/{X}` -> `org_id`. When the predecessor is
    itself a parameter, a version segment, or absent, fall back to `id`.
    """

    if preceding_segment is None:
        return "id"
    if preceding_segment.startswith("{") and preceding_segment.endswith("}"):
        return "id"
    if _is_version(preceding_segment):
        return "id"
    base = _singularize(preceding_segment)
    if not base.isidentifier():
        return "id"
    return f"{base}_id"


@dataclass(frozen=True, slots=True)
class PathParameter:
    """One inferred path `Parameter` a template introduces.

    `index` is the 0-based segment position in the template; `name` is the
    derived parameter name; `confidence` reflects multiplicity vs cold-start;
    `shape` is the dominant id-shape observed at the position (cold-start prior).
    """

    name: str
    index: int
    confidence: float
    shape: ShapeKind | None


@dataclass(frozen=True, slots=True)
class TemplatedPath:
    """The templating result for one concrete path."""

    concrete_path: str
    path_template: str
    parameters: tuple[PathParameter, ...]
    confidence: float


def _segments(path: str) -> list[str]:
    """Split a canonical absolute path into its non-empty segments."""

    return [seg for seg in path.split("/") if seg != ""]


@dataclass(frozen=True, slots=True)
class _SlotDecision:
    """How a trie position partitions its sibling cohort.

    `param_paths` are the paths whose value at this position collapses to a
    parameter; `literal_branches` maps each literal segment value to the paths
    that keep it as a literal route (router precedence). A position may produce
    both: `/users/{user_id}` (param) and `/users/settings` (literal) coexist.
    """

    param_paths: list[str]
    literal_branches: dict[str, list[str]]
    name: str
    confidence: float
    shape: ShapeKind | None


def _word_paths_reconverge(
    word_paths: dict[str, list[str]], segmented: dict[str, list[str]], index: int
) -> bool:
    """True iff every word-valued sibling shares one *identical* downstream suffix.

    Guards Case B (issue #70). Distinct interior words collapse to a parameter only
    when the entire remaining path after this position is byte-identical across the
    cohort — strong evidence the words are values of one collection:

    - `/orgs/acme/projects` + `/orgs/globex/projects` -> suffix `("projects",)` for
      both -> collapse to `{org_id}`.
    - `/orgs/42/...` + `/workspaces/ws-a/...`, or `/orgs/42` + `/users/87`, or
      `/orgs/42/posts` + `/users/87/posts` -> suffixes differ -> these are distinct
      routes; keep the resource-type literal and template each value slot per branch.

    Comparison is **raw** (not shape-normalised): wildcarding id positions would
    make `/orgs/{id}` and `/users/{id}` look identical and wrongly merge two
    collections. Under-templating a multi-parameter word-prefixed route is the safe,
    revisable direction (ADR-0004); destroying route identity is not.
    """

    suffixes = {
        tuple(segmented[p][index + 1 :]) for ps in word_paths.values() for p in ps
    }
    return len(suffixes) == 1


def _decide_slot(
    paths: list[str],
    values_by_path: dict[str, str],
    *,
    segmented: dict[str, list[str]],
    index: int,
    preceding: str | None,
    is_leaf: bool,
) -> _SlotDecision:
    """Partition a trie position into a parameter group + literal branches.

    Self-reference values (`me`/`current`/`self`) are values *of* a parameter, so
    they ride along with the parameter group rather than forcing a literal split.
    Literal (non-id-shaped, non-self-reference) values keep their own branch and
    win over the parameter (router precedence). The position collapses to a
    parameter when ≥2 distinct id-shaped values appear (multiplicity), or — cold
    start — when its only value is a single id-shaped one.
    """

    id_shaped_paths: list[str] = []
    self_ref_paths: list[str] = []
    word_paths: dict[str, list[str]] = {}
    version_paths: dict[str, list[str]] = {}
    distinct_id_values: set[str] = set()
    id_shaped_values: list[str] = []

    for p in paths:
        seg = values_by_path[p]
        if _is_version(seg):
            # Version segments stay literal even under multiplicity (ADR-0004).
            version_paths.setdefault(seg, []).append(p)
        elif seg.lower() in SELF_REFERENCE_VALUES:
            self_ref_paths.append(p)
        elif shape_of(seg) is not None:
            id_shaped_paths.append(p)
            distinct_id_values.add(seg)
            id_shaped_values.append(seg)
        else:
            word_paths.setdefault(seg, []).append(p)

    multiplicity = len(distinct_id_values) >= 2
    cold_start = len(distinct_id_values) == 1

    # Case A: id-shaped values present. They anchor the parameter; ordinary words
    # (`settings`) and version segments keep their own literal branch and win
    # (router precedence).
    if id_shaped_paths and (multiplicity or cold_start):
        param_paths = id_shaped_paths + self_ref_paths
        confidence = _MULTIPLICITY_CONFIDENCE if multiplicity else _COLD_START_CONFIDENCE
        return _SlotDecision(
            param_paths=param_paths,
            literal_branches={**word_paths, **version_paths},
            name=_param_name(preceding),
            confidence=confidence,
            shape=_dominant_shape(id_shaped_values),
        )

    # Case B: no id-shaped anchor, but >=2 distinct ordinary words share an
    # *interior* slot that reconverges to the same fixed continuation — pure
    # multiplicity collapses them to a parameter (`/orgs/acme/projects`,
    # `/orgs/globex/projects` -> `{org_id}`). Restricted to interior positions:
    # distinct words at a *leaf* are sibling routes (`/products`, `/about`), not a
    # parameter. This is the revisable cold-start case: a single word stays
    # literal (Case C) until a second distinct word overturns the guess (ADR-0004).
    #
    # The words must also *reconverge to the same downstream route* (issue #70):
    # `/orgs/acme/projects` + `/orgs/globex/projects` share `/projects` and collapse,
    # but `/orgs/{x}/projects` and `/workspaces/{y}/files` are different routes — the
    # resource-type literal must NOT be collapsed. Without this gate, distinct
    # same-length top-level routes lose their literal prefix to a bogus `{id}`.
    if (
        not is_leaf
        and len(word_paths) >= 2
        and not id_shaped_paths
        and _word_paths_reconverge(word_paths, segmented, index)
    ):
        param_paths = [p for ps in word_paths.values() for p in ps] + self_ref_paths
        return _SlotDecision(
            param_paths=param_paths,
            literal_branches=dict(version_paths),
            name=_param_name(preceding),
            confidence=_MULTIPLICITY_CONFIDENCE,
            shape=None,
        )

    # Case C: no parameter. Every value (incl. self-reference / version) is its
    # own literal route.
    literal_branches = {**word_paths, **version_paths}
    for p in id_shaped_paths + self_ref_paths:
        literal_branches.setdefault(values_by_path[p], []).append(p)
    return _SlotDecision(
        param_paths=[],
        literal_branches=literal_branches,
        name="",
        confidence=1.0,
        shape=None,
    )


def _dominant_shape(id_shaped: list[str]) -> ShapeKind | None:
    """The most common id-shape among the id-shaped values (ties: first seen)."""

    counts: dict[ShapeKind, int] = {}
    order: list[ShapeKind] = []
    for v in id_shaped:
        s = shape_of(v)
        if s is None:
            continue
        if s not in counts:
            order.append(s)
        counts[s] = counts.get(s, 0) + 1
    if not order:
        return None
    return max(order, key=lambda s: (counts[s], -order.index(s)))


def template_paths(concrete_paths: list[str]) -> dict[str, TemplatedPath]:
    """Template a corpus of concrete paths for one `(method, host)`.

    Returns a mapping `concrete_path -> TemplatedPath`. Deterministic: the same
    input set always yields the same templates regardless of order. Paths with
    differing segment counts never share a template; literal sibling routes
    coexist with parameterised ones (router precedence).
    """

    # De-dup; templating depends only on the *set* of distinct concrete paths.
    distinct = sorted(set(concrete_paths))
    segmented = {p: _segments(p) for p in distinct}

    out: dict[str, TemplatedPath] = {}

    # Group by segment count: paths of different lengths never share a template.
    by_len: dict[int, list[str]] = {}
    for p in distinct:
        by_len.setdefault(len(segmented[p]), []).append(p)

    for paths in by_len.values():
        _template_group(paths, segmented, out)

    return out


def _template_group(
    paths: list[str],
    segmented: dict[str, list[str]],
    out: dict[str, TemplatedPath],
) -> None:
    """Template a group of equal-length paths via recursive trie descent.

    At each depth the sibling values (under one fixed templated prefix) are
    examined together so multiplicity and literal-sibling precedence apply per
    branch, not globally.
    """

    if not paths:
        return
    depth = len(segmented[paths[0]])
    # Per-path accumulation of (template_segments, params).
    templates: dict[str, list[str]] = {p: [] for p in paths}
    params: dict[str, list[PathParameter]] = {p: [] for p in paths}
    confidences: dict[str, list[float]] = {p: [] for p in paths}

    # Recurse position by position, partitioning into literal branches as we go.
    _descend(
        paths,
        segmented,
        index=0,
        max_depth=depth,
        preceding=None,
        templates=templates,
        params=params,
        confidences=confidences,
    )

    for p in paths:
        template = "/" + "/".join(templates[p]) if templates[p] else "/"
        # Overall confidence: min over parameterised positions (a single weak
        # inference drags the whole template down), 1.0 for fully-literal paths.
        conf = min(confidences[p]) if confidences[p] else 1.0
        out[p] = TemplatedPath(
            concrete_path=p,
            path_template=template,
            parameters=tuple(params[p]),
            confidence=conf,
        )


def _descend(
    paths: list[str],
    segmented: dict[str, list[str]],
    *,
    index: int,
    max_depth: int,
    preceding: str | None,
    templates: dict[str, list[str]],
    params: dict[str, list[PathParameter]],
    confidences: dict[str, list[float]],
) -> None:
    """Recursive trie descent deciding one position for a sibling cohort."""

    if index >= max_depth:
        return

    values_by_path = {p: segmented[p][index] for p in paths}
    decision = _decide_slot(
        paths,
        values_by_path,
        segmented=segmented,
        index=index,
        preceding=preceding,
        is_leaf=(index == max_depth - 1),
    )

    # Parameter branch: id-shaped (+ self-reference) values collapse to one token.
    if decision.param_paths:
        token = "{" + decision.name + "}"
        for p in decision.param_paths:
            templates[p].append(token)
            params[p].append(
                PathParameter(
                    name=decision.name,
                    index=index,
                    confidence=decision.confidence,
                    shape=decision.shape,
                )
            )
            confidences[p].append(decision.confidence)
        _descend(
            decision.param_paths,
            segmented,
            index=index + 1,
            max_depth=max_depth,
            preceding=token,
            templates=templates,
            params=params,
            confidences=confidences,
        )

    # Literal branches: each keeps its own route and is templated independently
    # downstream (router precedence — literal siblings win over the parameter).
    for value, branch_paths in decision.literal_branches.items():
        for p in branch_paths:
            templates[p].append(value)
            confidences[p].append(1.0)
        _descend(
            branch_paths,
            segmented,
            index=index + 1,
            max_depth=max_depth,
            preceding=value,
            templates=templates,
            params=params,
            confidences=confidences,
        )
