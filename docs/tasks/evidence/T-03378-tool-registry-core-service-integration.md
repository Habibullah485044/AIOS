# T-03378 Evidence: Tool Registry & Taxonomy — core service Integration

- Date: 2026-11-06
- The service is wired into its **two real production call paths**:
  - `_dispatch.dispatch` (every MCP tool routed to a host action): `_registry_require_grant()` runs before Gate #2.
    It calls `service().decide(tool, target, require_grant)`, reports disagreements (`surface: "dispatch"`), and in **strict** mode ORs
    the catalog's grant requirement into `require_grant`.
  - `agent_loop_policy.evaluate_step` (every agent-loop tool step): `_registry_irreversible()` reports disagreements
    (`surface: "agent_loop"`), and in strict mode ORs the catalog's irreversibility into the step's budget decision.
    Reasoning steps (no tool) do not consult it.
- **Shadow is the default** (`AIOSH_TOOL_REGISTRY_MODE` unset). Strict is opt-in.
- Both hooks **never raise and never loosen** a decision. A broken registry (bad catalog or bad mode value) falls back to the legacy
  rules, and dispatch logs that once on stderr.
- **No extra audit rows** (TOOLSVC-INV3): disagreements are a masked stderr JSON line; the audit ring is untouched.

## Tests (`code/aiosh-mcp/tests/test_tool_registry_service_integration.py`, 5)
| Test | Asserts |
|---|---|
| shadow changes nothing and reports | an unregistered tool is still allowed, with the same audit-row behaviour; one `tool_registry.disagreement` line (`unregistered`); a registered, agreeing tool is silent |
| strict only tightens dispatch | an unregistered tool without a grant is now refused with **exactly one** `refused` audit row; a registered read-only tool is unchanged |
| broken registry falls back to legacy | `service()` raising: calls behave as before, and a single stderr line is logged |
| agent-loop step, shadow vs strict | shadow keeps the legacy `irreversible=False`; strict marks an unregistered tool irreversible (budget); registered pentest stays irreversible |
| reasoning steps untouched | `evaluate_step(None, …)` is unaffected |

## TOOLSVC-INV2: shadow changes nothing (full suite)
```
$ python -m pytest tests/ -q --ignore=tests/bench_retention.py -k "not release"   (this branch, shadow default)
137 failed, 1445 passed, 5 skipped, 21 deselected, 5 warnings in 168.90s (0:02:48)
tests=1587 failures=137 errors=0 skipped=5
missing-Rust-binary failures: 136
other failures: ['tests.test_runbook_config_integration::test_integration_dynamic_session_capping_via_env :: assert True is False']
```
This is the same classified baseline as before the integration (T-03372: 136 + the same flake). No existing test changed outcome, the
agent-loop battery included.

Cross-substrate: the service reads only the Python catalog. The TS and Rust gates are not wired (out of scope, research §D).
