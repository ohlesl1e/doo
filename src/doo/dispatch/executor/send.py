"""The wire-send transport seam (ADR-0043: MCP-ready, swappable).

`Sender` is a narrow Protocol — pure `(ConcreteRequest) → HttpResponse` — so the
Dispatcher's gate sequence is testable with a stub, and a Burp-MCP /
hexstrike-ai backend (post-MVP, ADR-0043) is a transport swap, not a refactor.
The default `HttpxSender` is a thin `httpx` client; tests inject a `StubSender`.

This module is the **only** place that puts bytes on the wire. Every caller goes
through `executor.dispatcher.dispatch()` first — there is no side channel around
the kill-switch / OPA / budget gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from doo.dispatch.models import ConcreteRequest


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """The constructor-/classifier-facing response shape.

    Carries only what `executor.classify` and the agent-`RequestObservation`
    writer need: status, headers, body bytes (the writer puts the body in object
    storage and keeps only a `BlobRef`, ADR-0015), and timing.
    """

    status: int
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes = b""
    duration_ms: int | None = None


class TransportError(Exception):
    """The wire send failed before any HTTP status (DNS, connect, TLS, timeout).

    Maps to `dispatch_status = "transport_error"` (ADR-0013): the test did not
    reach the target, so it neither confirms nor refutes the hypothesis.
    """


class Sender(Protocol):
    """Pure `(ConcreteRequest) → HttpResponse` — the MCP-ready transport seam."""

    def send(self, request: ConcreteRequest) -> HttpResponse: ...


class HttpxSender:
    """`httpx`-backed `Sender`. Thin; no retry, no redirect-follow, no pooling.

    Deliberately minimal: the Dispatcher's rate/budget guards live above this,
    and following redirects would let the target steer the agent off-scope (the
    redirect target is a *new* request that must pass the gate, ADR-0046).
    """

    def __init__(self, *, timeout_s: float = 30.0) -> None:
        self._timeout_s = timeout_s

    def send(self, request: ConcreteRequest) -> HttpResponse:
        import time

        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - core dep
            raise TransportError(
                "httpx is not installed; install with `pip install -e '.[dev]'` "
                "or add httpx to the runtime environment"
            ) from exc

        started = time.monotonic()
        try:
            resp = httpx.request(
                request.method,
                request.url(),
                params=list(request.query),
                headers=list(request.headers),
                cookies=dict(request.cookies),
                content=request.body,
                timeout=self._timeout_s,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise TransportError(str(exc)) from exc
        duration_ms = int((time.monotonic() - started) * 1000)
        return HttpResponse(
            status=resp.status_code,
            headers=tuple((k, v) for k, v in resp.headers.items()),
            body=resp.content,
            duration_ms=duration_ms,
        )


@dataclass
class StubSender:
    """Test-time `Sender`: records every request, returns a canned response.

    Used by unit tests (assert no-send-on-deny) and the e2e (no real wire).
    """

    response: HttpResponse = field(
        default_factory=lambda: HttpResponse(status=200, body=b"{}")
    )
    sent: list[ConcreteRequest] = field(default_factory=list)

    def send(self, request: ConcreteRequest) -> HttpResponse:
        self.sent.append(request)
        return self.response
