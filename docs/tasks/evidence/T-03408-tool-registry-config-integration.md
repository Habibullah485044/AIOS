# T-03408 Evidence: Tool Registry & Taxonomy — configuration Integration

- Date: 2026-11-06
- **Production path:** the configuration is read by the real MCP server (`python -m aiosh_mcp.server`) when it first builds the
  registry service (T-03406 wiring). It is visible to operators through `aios_tool_registry_stats` (`config.values`, `config.sources`,
  `config_errors`).

## Tests (`code/aiosh-mcp/tests/test_tool_registry_config_integration.py`, 3; real stdio server + MCP client)
| Test | Asserts |
|---|---|
| server applies a config file | with `AIOSH_TOOL_REGISTRY_CONFIG` → `{"mode": "strict", "report_max_lines": 3, "unregistered_samples": 7}`, stats reports exactly those values, every source is `file`, the **running service is in strict mode**, and there are no errors |
| env strict beats a file shadow | file `{"mode": "shadow"}` plus env `strict` → the service is strict, source `env` (strictest wins end to end) |
| a bad file is reported and the server still serves | a file with the locked key `catalog` → the server starts and answers, the whole file is ignored (mode stays `shadow`), and `config_errors` contains `TOOLREGCONF_ERR_LOCKED` |
```
$ python -m pytest tests/test_tool_registry_config_integration.py -q
3 passed in 12.22s
```
The closest existing suites, CI #35 (`tool_registry`) and the agent-loop battery, pass in the ship gate.
Cross-substrate: the configuration is Python-server-only. TS and Rust have no registry service to configure.
