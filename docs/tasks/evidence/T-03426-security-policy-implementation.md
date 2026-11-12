# T-03426 Evidence: Tool Registry & Taxonomy — security policy Implementation

- Date: 2026-11-13
- Spec: [T-03424-security-policy-specification.md](T-03424-security-policy-specification.md)

## What shipped
- `aiosh_mcp/tool_registry_policy.py`: the single policy point.
  - `policy_revision()`: `trp-` plus 16 hex of SHA-256 over the sorted security fields, cached per catalog object.
  - `evaluate()`: OR-only, and fails closed iff strict was intended, using the same rule and the same stderr lines as before.
  - `grant_reason_suffix()` and `reset_process_state()`.
- `_dispatch.py`: `_registry_require_grant` is now a thin wrapper over `_registry_policy()` → `evaluate(surface="dispatch")`.
  The module-global once-flag `_REGISTRY_FAILURE_LOGGED` is gone; the policy module announces a failure once per surface.
  A grant refusal **the registry alone caused** now reads
  `tool 'X' requires explicit PEP grant (tool registry strict, catalog trp-…)`. That is the same row and column, only the text grows.
- `agent_loop_policy._registry_irreversible` is a thin wrapper over `evaluate(surface="agent_loop")`. Its duplicated try/except is gone.
- `aios_tool_registry_stats`: `data.policy_revision` added.
- Tests:
  - `conftest.py` also resets the policy module's process state.
  - Two tests that poked `_dispatch._REGISTRY_FAILURE_LOGGED` now call `tool_registry_policy.reset_process_state()`.
  - The fixed-key stats shape test includes `policy_revision`.
  - The scaffold test now pins that both consumers use the policy point.

## Failing test first
`tests/test_tool_registry_policy_impl.py` (9) was written before the implementation: `9 failed` against the scaffold stubs. After:
```
$ python -m pytest tests/test_tool_registry_policy_impl.py -q
9 passed in 4.95s
```
Covered:
- revision shape and determinism (two equal catalogs give the same revision);
- strict attribution, and none in shadow;
- a caller's own grant requirement is not attributed to the registry;
- agent-loop irreversibility in strict only;
- failure fails closed only when strict was intended, with the exact old stderr line;
- a bad surface raises;
- stats show the revision;
- end to end, a strict `dispatch()` refusal reason carries the suffix.

## Regression
```
$ python -m pytest tests/ -k "tool_registry or agent_loop or dispatch or por_conformance or compliance or task_service" -q
1 failed, 1301 passed, 6 skipped   ->  the failure was the stats fixed-key test (intended contract change); fixed, then:
```
Full aiosh-mcp suite:
```
137 failed, 1926 passed, 6 skipped, 5 warnings in 306.49s (0:05:06)
failures=137 missing-Rust-binary=136 known-baseline=1 other=0
```

## Security audit (standing rule)
- **Never weaker (TOOLPOL-INV1):** `requires_grant = require_grant or …` and `irreversible = legacy or …`. The caller's values can only be raised.
- **Shadow identical (TOOLPOL-INV2):** in shadow `enforcement()` is `{}` and `registry_added_grant` is false, so the reason text is
  byte-identical. The stderr failure lines are kept verbatim. `test_task_service_smoke` (exact reason string) still passes.
- **Fail closed (TOOLPOL-INV4):** both consumers keep the T-03379 rule. If even `intended_mode()` cannot be read, the policy now
  assumes strict; before, that exception would have escaped into the caller's own handler.
- **No new audit rows (ADR-0035 F-2):** only the text of an existing refusal row changes, and only in strict mode.
- **Injection:** the suffix holds only fixed text and a hex revision. The tool name is formatted exactly as before; no caller text is added.
- **PoR (I-2):** the grant gate is reached on the same conditions as before, and redeem-before-act (Gate #2.5) is untouched. **No bypass.**
