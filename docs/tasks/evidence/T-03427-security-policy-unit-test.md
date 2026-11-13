# T-03427 Evidence: Tool Registry & Taxonomy — security policy Unit Test

- Date: 2026-11-13
- Spec: [T-03424-security-policy-specification.md](T-03424-security-policy-specification.md)
- Implementation: [T-03426-security-policy-implementation.md](T-03426-security-policy-implementation.md)

## What shipped
`code/aiosh-mcp/tests/test_tool_registry_policy_unit.py` has 40 tests in the existing pytest smoke style. They assert only
observable behavior: return values, verdict fields and stderr/stdout text.

| Ledger requirement | Covered by |
|---|---|
| Valid input | `test_evaluate_is_or_only`: 8 mode × caller-grant × legacy cases, over registered, unregistered, empty and wrong-case tool names on both surfaces |
| Invalid input | `test_evaluate_never_raises_on_odd_input`: `None`, int, bytes, list, dict, 10 000 chars, NUL, RTL override. `test_unknown_surface_raises`: 4 bad surfaces |
| Boundary values | The revision changes for each security field and stays the same for title and alias changes; it ignores entry order; the cache stays bounded at `_MAX_CACHED_REVISIONS`; the suffix is ASCII and under 80 chars; all 5 suffix forms |
| Primary failure mode | `test_failure_rule`: a catalog failure fails closed only in strict. `test_unreadable_mode_fails_closed`. `test_failure_is_announced_once_per_surface`: once per surface, never on stdout |

## Standalone run
```
$ python -m pytest tests/test_tool_registry_policy_unit.py -q
40 passed in 2.26s
```

## The tests fail when the feature is broken (mutation check)
Each mutation was applied to `aiosh_mcp/tool_registry_policy.py`, then reverted with `git checkout`.

| Mutation | Result |
|---|---|
| M1: drop the caller's `require_grant` (weakening; breaks TOOLPOL-INV1) | 2 failed, 38 passed |
| M2: leave `effect` out of the revision hash (breaks TOOLPOL-INV5) | 1 failed, 39 passed |
| M3: unbounded revision cache | 1 failed, 39 passed |

## Regression
```
$ python -m pytest tests/ -q -k "tool_registry or agent_loop or audit_chain_concurrency or grant_scope or secret_masking or dispatch"
1211 passed, 2 skipped, 896 deselected, 3 warnings in 276.34s
```

## Security audit (standing rule)
- **Tests only:** no production code changed, so the attack surface is unchanged.
- **Isolation:** every test sets `AIOSH_HOME` to `tmp_path` and resets the process config, the service singleton and the
  policy state. A strict-mode test cannot leak into later tests, and nothing writes outside `tmp_path`.
- **Never-weaker is pinned:** the OR-only grid shows that no mode, surface or tool name produces a verdict weaker than the
  caller's input, and M1 shows a weakening regression is caught.
- **Fail-closed is pinned:** strict-mode failures, and an unreadable mode, require a grant. Failure text never reaches
  stdout, the MCP JSON-RPC channel.
- **Hostile input:** NUL, the bidi override, 10 KB names and non-string types never raise inside the policy. In strict they
  resolve to grant-required (D4).
- **PoR (I-2):** no gate is touched. **No bypass.**
