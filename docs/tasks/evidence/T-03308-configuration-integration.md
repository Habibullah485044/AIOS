# T-03308 Evidence: Agent Loop Hardening — configuration Integration

- Date: 2026-11-05
- `agent_loop_config.resolve()` is now wired into every consumer named in T-03304 §6:

| Consumer | Setting | Where |
|---|---|---|
| `AgentLoopService(capacity=None)` | `registry_capacity` | resolved at construction (the global service is built at server import) |
| `PepCapabilityGate` | `db_busy_timeout_ms` | resolved lazily on first DB open, applied as `PRAGMA busy_timeout` |
| MCP tools | `mcp_call_timeout_s`, `history_page_bytes`, `snapshot_steps_tail` | resolved once in `register_agent_loop_mcp_tools` (new `settings=` parameter for an already-resolved dict) |
| MCP `aios_agent_loop_start`, CLI `run` | the 5 `LoopConfig` defaults | omitted budgets now come from `loop_config_for(...)`; an explicit argument or flag still wins |

## Discoverability (registration points)
- New read-only MCP tool **`aios_agent_loop_config`** (`readOnlyHint`). It returns the resolved values, the per-key `source`, and rejected inputs.
  Server catalog: 62 -> 63 tools.
- New CLI subcommand **`python -m aiosh_mcp.agent_loop_cli config [--config FILE] [--json]`**.
- CI suite `agent_loop_integration` now also runs `test_agent_loop_config_integration.py`.

## Parity
`test_mcp_config_tool_matches_cli_config`: under the same env and file, the MCP tool's `data` and the CLI's `config --json` `data`
are identical as canonical JSON. That covers a file-sourced value and a rejected `nan` env value (`env_invalid`, default kept).

## Integration smoke (registered CI command, repo root)
```
20 passed in 14.65s
PASS: ci_suites unit tests (W1..W7)
```
Covered: env capacity limits the service; env busy timeout is visible via `PRAGMA busy_timeout`; env default iterations
apply to MCP start (an explicit value still wins); env snapshot tail applies; env iteration default applies to CLI run;
a real `python -m aiosh_mcp.server` stdio session reports the env value with `source=env`.

Behaviour change: the hardening tests that monkeypatched module constants (`TOOL_CALL_TIMEOUT_S`, `MAX_RESPONSE_BYTES`) now pass
`settings=`. The scaffold test now expects 8 tools.
