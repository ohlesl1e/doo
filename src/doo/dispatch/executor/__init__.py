"""The Executor: deterministic request construction + the Dispatcher gate.

Per ADR-0043 the Executor owns one constructor per `(test_class, role)` — a pure
function of `(TestCase, evidence RequestObservation, AuthContext material)` →
`ConcreteRequest`. The Dispatcher (`executor.dispatcher`) gates every send:
kill-switch lease → OPA → budget guards → wire. The transport
(`executor.send`) is a thin `Sender` Protocol so a Burp-MCP backend can be
swapped in later (ADR-0043: MCP-ready signatures).

No LLM here — deterministic only (CLAUDE.md hard rule).
"""
