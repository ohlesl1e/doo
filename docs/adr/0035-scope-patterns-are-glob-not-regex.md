# Scope patterns are glob/segment, not regex

`Scope.host_patterns` and `Scope.allowed_path_patterns` use a **glob/segment** syntax, not regex. `is_in_scope` already implements this; the `ScopeRules` docstring and some fixtures wrongly described/used regex, which silently matched nothing. This ADR makes glob canonical across the docstring, loader, configs, and the future Rego.

## The syntax

- **Host pattern:** exact (case-insensitive, post-canonicalisation) match, or a single leading `*.` wildcard (`*.example.com` matches sub-domains, not the apex). IP literals match exact patterns only, never a wildcard.
- **Path pattern:** segment-wise — a `*` segment matches exactly one path-template segment (including a `{param}` placeholder); a trailing `**` matches all remaining segments. Literal segments must match exactly.
- **Regex is not supported.** `^`, `$`, `.*`, character classes, etc. are not metacharacters here — they are literal and will match nothing real.

## Why glob, not regex

ADR-0020 requires `is_in_scope` (the Python query-time/planner helper) and the OPA/Rego dispatch rule to evaluate **identically**. The Rego is currently a deny-all skeleton; its host/path rules are written in slice 4 to mirror the helper. Segment-wise glob is trivially portable to Rego; full parity between Python `re` and Rego `regex.match` is a portability minefield (engine differences, anchoring rules, ReDoS exposure). Real scope declarations — domains, wildcard subdomains, path prefixes — do not need regex, and the expressiveness regex would add is exactly the part that breaks Rego parity. The constraint (parity) outranks the convenience (expressiveness).

## Context (the bug, #55)

A real run used `host_patterns: ["^.*$"]` / `allowed_path_patterns: ["^/.*$"]` (regex). The glob matcher matched **zero** of 73 endpoints, so all four coverage queries returned empty with exit 0 and no warning — a silent false negative that reads as "doo found nothing." Switching to `host_patterns: ["172.30.146.0"]` / `["/**"]` over the same graph yielded 853 / 13 / 28 results.

## Consequences

- **Fail fast on regex.** The engagement loader rejects scope patterns containing regex-only metacharacters (`^`, `$`, unescaped `.` outside a hostname, `.*`, `[`, `(`, `|`, …) at `engagement start`, with an actionable error, rather than accepting a pattern that silently matches nothing.
- **Defense in depth.** Coverage emits a warning when a scope matches zero in-scope nodes against a non-empty graph (a likely-misconfigured-scope signal), so a silent empty result is surfaced even if a bad pattern slips through.
- **Migration.** The `ScopeRules` docstring is corrected to describe glob; regex-using fixtures (`tests/test_loader.py`) and the ad-hoc `tests/test_har/engagement*.yaml` configs are converted to glob.
- The slice-4 Rego host/path rules implement this same glob/segment semantics; the dual-path test (`tests/test_scope_dual_path.py`) is the parity guard.

## Considered options

- **Regex as canonical** (rejected): breaks the ADR-0020 parity guarantee, adds a ReDoS surface, and buys expressiveness real scope declarations don't need.
- **Leave the helper glob but the docstring regex** (rejected): that *is* the #55 bug — a contract that disagrees with the implementation, producing silent empty results.
