"""Shared CLI environment helpers: `.env` loading + friendly connection errors.

Two papercuts these remove:

1. The `DOO_*` connection vars must be exported in every shell, and the CLI's
   built-in defaults (`password`, `minioadmin`) don't match the docker-compose
   credentials — so a fresh terminal silently fails to authenticate. `load_dotenv`
   reads a `.env` from the current directory at startup (real env vars still win).
2. A wrong/absent password surfaced as a raw Neo4j stack trace.
   `connect_neo4j_or_exit` turns it into a one-line, actionable CLI error.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import typer

if TYPE_CHECKING:
    from doo.infra.neo4j_driver import Neo4jClient


def load_dotenv(path: str | os.PathLike[str] = ".env") -> int:
    """Load `KEY=VALUE` pairs from a `.env` file into `os.environ`.

    Only sets keys that are *not already* in the environment, so an explicit
    `export` always wins over the file (standard dotenv precedence). Lines that
    are blank, comments (`#`), or have no `=` are ignored; surrounding quotes are
    stripped. Returns the number of keys set; a no-op (returns 0) if the file is
    absent.
    """

    p = Path(path)
    if not p.is_file():
        return 0
    set_count = 0
    for raw in p.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
            set_count += 1
    return set_count


def connect_neo4j_or_exit(uri: str, user: str, password: str) -> Neo4jClient:
    """Connect to Neo4j, turning auth/availability failures into a clear CLI error.

    Raises `typer.Exit(2)` with an actionable message instead of letting the raw
    `neo4j.exceptions` stack trace reach the terminal.
    """

    from neo4j.exceptions import AuthError, ServiceUnavailable

    from doo.infra.neo4j_driver import Neo4jClient

    try:
        return Neo4jClient.connect(uri, user, password)
    except AuthError as exc:
        typer.secho(
            f"Neo4j authentication failed for {user}@{uri}.\n"
            "  Check DOO_NEO4J_PASSWORD — the docker-compose stack uses "
            "'doo-dev-password' (the CLI default is 'password').\n"
            "  Export it, or copy .env.example -> .env and `set -a; source .env; set +a`.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2) from exc
    except ServiceUnavailable as exc:
        typer.secho(
            f"Cannot reach Neo4j at {uri}. Is the stack up?  docker compose up -d --wait",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2) from exc


_LLMRole = Literal["planner", "interpreter"]


def resolve_llm_api_base(role: _LLMRole) -> str | None:
    """ADR-0051 ``api_base`` precedence for ``role``: role-specific
    (``DOO_<ROLE>_API_BASE``) → shared (``DOO_LLM_API_BASE``) → ``None``.

    ``None`` is the normal state — litellm prefix-routes (``anthropic/…``,
    ``openai/…``) using its own per-provider env vars. Setting any of these is
    a *force-pin*: every call for that role goes to that one endpoint
    regardless of model prefix.
    """
    return (
        os.environ.get(f"DOO_{role.upper()}_API_BASE")
        or os.environ.get("DOO_LLM_API_BASE")
        or None
    )


def resolve_llm_api_key(role: _LLMRole) -> str | None:
    """ADR-0051 ``api_key`` precedence — same chain shape as
    :func:`resolve_llm_api_base`."""
    return (
        os.environ.get(f"DOO_{role.upper()}_API_KEY")
        or os.environ.get("DOO_LLM_API_KEY")
        or None
    )
