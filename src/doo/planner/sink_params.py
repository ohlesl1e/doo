"""Deterministic sink-parameter detection (ADR-0036, S6) — no LLM.

Classifies request parameters that *consume* a caller-controlled address into sink
roles — the dangerous surface no coverage C-query encodes (the canonical
`callback_url`-on-an-otherwise-clean-endpoint case). Detection is pure name + value
-shape heuristics (the same discipline as `replay_hazards.py`): a `url_sink` /
`redirect_target` / `file_path` role, or None for an ordinary parameter.

The `sink_params` generator reads these roles to pick candidate endpoints; the LLM
then proposes an SSRF / open-redirect / LFI test against the sink parameter. No LLM
here — deterministic code classifies, the model only proposes.
"""

from __future__ import annotations

import re

from doo.planner.models import SINK_ROLES, SinkRole

# Name tokens per role (substring match on a normalised name). Order mirrors
# `SINK_ROLES` precedence: a redirect-shaped name wins over a generic URL name,
# which wins over a file/path name (a `redirect`/`callback` is more specific than
# a bare `url`, and both are addresses rather than local paths).
_REDIRECT_TOKENS = (
    "redirect", "redir", "returnurl", "return_url", "returnto", "return_to",
    "callback", "next", "continue", "goto", "successurl", "failureurl",
)
_URL_TOKENS = (
    "url", "uri", "link", "href", "webhook", "endpoint", "feed", "target",
    "image_url", "imageurl", "avatar", "remote",
)
_FILE_TOKENS = (
    "path", "file", "filename", "filepath", "template", "include",
    "dir", "folder", "document", "download", "attachment",
)

# Value-shape corroboration (optional — a sink name is decisive, the value sharpens
# confidence and rescues a generic name like `target` carrying a URL).
_URL_SHAPED = re.compile(r"^\s*(https?:)?//|^\s*https?:", re.IGNORECASE)
_PATH_SHAPED = re.compile(r"(\.\./|/etc/|\\|\.[a-z0-9]{2,4}$|^/[^/])", re.IGNORECASE)


def _norm(name: str) -> str:
    """Lowercase, strip non-alphanumerics so `redirect_uri`/`redirectUri` match."""

    return re.sub(r"[^a-z0-9]", "", name.lower())


def _name_has(norm: str, tokens: tuple[str, ...]) -> bool:
    return any(tok.replace("_", "") in norm for tok in tokens)


def classify_sink_role(name: str, value: str | None = None) -> SinkRole | None:
    """Classify one parameter `(name, value?)` into a sink role, or None.

    Name is decisive (precedence redirect > url > file); a URL-shaped value also
    promotes an otherwise-generic name (`target=https://…` → `url_sink`), and a
    path-shaped value promotes a file name. Ordinary params (`id`, `q`, `page_size`)
    classify to None.
    """

    norm = _norm(name)
    url_shaped = bool(value and _URL_SHAPED.search(value))
    path_shaped = bool(value and _PATH_SHAPED.search(value))

    if _name_has(norm, _REDIRECT_TOKENS):
        return "redirect_target"
    if _name_has(norm, _URL_TOKENS) or url_shaped:
        return "url_sink"
    if _name_has(norm, _FILE_TOKENS) or path_shaped:
        # A bare `page` with no path-shaped value is too weak — require a path name
        # token OR a path-shaped value (so `?page=2` does not classify).
        if path_shaped or _name_has(norm, _FILE_TOKENS):
            return "file_path"
    return None


def sink_role_for_parameter(name: str, values: tuple[str, ...] = ()) -> SinkRole | None:
    """Sink role for a parameter given its name + any observed values (first match)."""

    if not values:
        return classify_sink_role(name)
    for v in values:
        role = classify_sink_role(name, v)
        if role is not None:
            return role
    return classify_sink_role(name)


def sink_test_class_for_role(role: SinkRole) -> str:
    """The default `test_class` a sink role suggests (the LLM may still specialise)."""

    return {
        "redirect_target": "open-redirect",
        "url_sink": "ssrf",
        "file_path": "path-traversal",
    }[role]


# Re-export for callers that want the role vocabulary.
__all__ = [
    "SINK_ROLES",
    "SinkRole",
    "classify_sink_role",
    "sink_role_for_parameter",
    "sink_test_class_for_role",
]
