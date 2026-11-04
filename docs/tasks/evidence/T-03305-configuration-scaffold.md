# T-03305 Evidence: Agent Loop Hardening — configuration Scaffold

- Date: 2026-11-05
- New `code/aiosh-mcp/aiosh_mcp/agent_loop_config.py` per T-03304:
  - real constants: 64 KiB file cap, 1024-char path cap, `DEFAULT_CONFIG_PATH`, `AIOSH_AGENT_LOOP_CONFIG`, 7 `AGENTLOOPCONF_ERR_*` codes, `CONFIG_SOURCES`
  - `FieldSpec` and the `FIELDS` table (10 tunables: default, clamp bounds, type, env name) plus `LOCKED_KEYS` (9 controls)
  - stubs `default_config`, `hygiene_ok`, `validate`, `resolve`, `loop_config_for`, each raising `NotImplementedError("T-03306: ...")`
- No consumer is wired yet (that is T-03308 Integration), so behaviour is unchanged.

## Build / import
```
$ python -c "import aiosh_mcp.agent_loop_config, aiosh_mcp.server; print('import ok')"
import ok
```

## Call sites / test stubs (`tests/test_agent_loop_config_scaffold.py`, 4 cases)
- Every `FIELDS` default **equals the constant hard-coded today** (`LoopConfig` defaults, `MAX_REGISTRY_CAPACITY`,
  `TOOL_CALL_TIMEOUT_S`, `MAX_RESPONSE_BYTES`, `DEFAULT_STEPS_TAIL`, `BUSY_TIMEOUT_MS`), so adopting config is a no-op by default.
  Each env name follows `AIOSH_AGENT_LOOP_<FIELD>`.
- The clamp bounds of the 5 `LoopConfig` fields pass `LoopConfig.validate_bounds` at both edges.
- Locked keys and tunable keys are disjoint.
- All 5 stubs fail loudly.
```
197 passed, 909 deselected in 22.93s
```
