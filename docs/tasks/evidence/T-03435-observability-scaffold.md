# T-03435 Evidence: Tool Registry & Taxonomy — observability Scaffold

- Date: 2026-11-13
- Spec: [T-03434-spec.md](T-03434-spec.md)

## What shipped (interfaces only; bodies raise `NotImplementedError`)
- **New `aiosh_mcp/tool_registry_observability.py`:**
  - constants: `DEFAULT_WINDOW` 10 000, `MAX_WINDOW` 100 000, `DEFAULT_QUERY_DEADLINE_S` 10.0, `HEALTH_STATES`,
    `MAX_TOOL_KEYS` 64;
  - error codes `TOOLOBS_ERR_WINDOW` and `TOOLOBS_ERR_READ`;
  - the ring markers `STRICT_MARKER` / `UNAVAILABLE_MARKER` / `REDEEM_TOOL`, and `ObservabilityReadError`;
  - stubs `ring_metrics()` and `health()`.
- **`tool_registry_policy`:** `MAX_FAILURE_TYPES` 16, and a stub `policy_stats()`.
- **`capability_redeem`:**
  - `REFUSAL_CLASSES` (8, closed) and `LOGGER_NAME` (`aiosh_mcp.capability`);
  - stubs `classify_refusal()`, `capability_stats()` and `reset_stats()`.
- Nothing is wired into a live path yet. Stats and the gate are unchanged, and a test proves it.

## Build / import
```
$ python -c "import aiosh_mcp, aiosh_mcp.server, aiosh_mcp.tool_registry_observability"
import ok
$ python -m pytest tests/test_tool_registry_observability_scaffold.py tests/test_capability_redeem_security.py tests/test_tool_registry_policy_unit.py -q
74 passed in 11.70s
$ python -m pytest tests/ -q -k "tool_registry or capability_redeem or model_backend or mcp_server_core"
1110 passed, 1 skipped, 1055 deselected, 1 warning in 196.25s
```
`tests/test_tool_registry_observability_scaffold.py` (11 tests) covers:
- the constants, error codes and classes exist;
- the ring markers match the real `grant_reason_suffix` texts, so the T-03436 parser cannot drift from what dispatch
  writes;
- every stub fails loudly;
- the live stats tool and capability gate do not call the stubs.

## Security audit (standing rule)
- **No behavior change:** the stubs are unreachable from served tools (test). The gate still refuses forged tokens.
- **No new surface:** no MCP tool is registered yet. `aios_tool_registry_metrics` arrives in T-03436 with its catalog
  entry.
- **PoR (I-2):** untouched. **No bypass.**
