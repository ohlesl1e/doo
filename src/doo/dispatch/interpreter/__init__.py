"""The Interpreter: a per-`TestCase`, ≤N-turn confirm loop (ADR-0042/0043/0045).

After the `primary` send returns `dispatch_status = ok`, deterministic Python
drives a multi-turn `litellm.completion(tools=[…])` loop: on each `tool_use`
block, **our** code dispatches on `tool_name` to Executor functions and feeds
`tool_result` back. The LLM emits JSON; it never executes anything (CLAUDE.md
hard rule), and its only authority over what goes on the wire is which
`RequestRole` to send next — for *this* `TestCase`, in *this* `test_class`'s
role enum (the `confirm`-mode boundary, ADR-0043).

The loop ends on a forced `emit_verdict` call → typed `InterpreterVerdict`
(ADR-0045). Deterministic code records the verdict on the TestCase (the 4th
orthogonal axis) and, on `vulnerable`, commits a soft-content-addressed `Finding`
at `finding_status = proposed`.

Native tool-use loop, MCP-ready signatures (ADR-0043): wrapping the tool
functions in an MCP server later is a transport swap, not a refactor.
"""
