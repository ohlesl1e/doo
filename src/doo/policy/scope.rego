# Scope policy — slice-1 deny-all skeleton (ADR-0003, ADR-0020).
#
# Per ADR-0003 the dispatcher's authorisation decision is a PURE function of
# `input` (the proposed request, including its PayloadClass and the target's
# confidence) and `data` (the static Scope rule document). No graph access.
#
# Slice 1 ships the policy as deny-everything: `default allow = false` and no
# rule that ever sets `allow = true`. The real host/method/path/payload-class
# matching lands in slice 4, at which point this file grows the rules that must
# mirror `doo.policy.scope.is_in_scope` exactly (ADR-0020).
#
# The dual-path test (`tests/test_scope_dual_path.py`) feeds the same
# (node, scope) fixtures through both this policy and the Python helper and
# asserts identical answers. In slice 1 every fixture is constructed to be
# out-of-scope, so the Python helper returns `false` for each and agrees with
# this deny-all policy.

package doo.scope

# Deny by default. Fail closed.
default allow := false

# NOTE (slice 4): add `allow if { ... }` rules here that reproduce the Python
# helper's host-pattern / method / path-template / payload-class semantics.
# Until then there is intentionally no rule body that grants access.
