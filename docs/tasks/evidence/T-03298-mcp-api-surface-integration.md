# T-03298 Evidence: Agent Loop Hardening — MCP/API surface Integration

- Date: 2026-11-05

## Production call path
The tools are registered in `server.py` (through `register_agent_loop_service_tools`, which delegates to `agent_loop_mcp`) and are
reachable over the real transport. `tests/test_agent_loop_mcp_integration.py` spawns **`python -m aiosh_mcp.server`** (stdio)
and drives it with the official MCP client (`mcp.client.stdio.stdio_client` + `ClientSession`), i.e. JSON-RPC 2.0 over pipes.

| Check | Result |
|---|---|
| `tools/list` publishes all 7 tools with the spec `ToolAnnotations` (read-only / destructive / idempotent) | PASS |
| Published `inputSchema` carries the server limits (`action_intent.maxLength` = 4096, `tokens_consumed.maximum` = 1e6) | PASS |
| start -> advance(ok) -> advance(refused) -> complete -> history -> status over the wire, using `$AIOSH_HOME/audit.db` | PASS |
| `aios_agent_loop_status` (data-model tool) sees the service loop: two-registry read fallback | PASS |
| Schema violation (`loop_id="bad"`) returns an MCP `isError` result; the server keeps running | PASS |

## Cross-substrate parity (shared SQLite ring)
The history returned by the MCP server process is **identical** (`==`) to the history read by the CLI
(`dispatch_cli history`) from the same `audit.db`. The hash chain verifies (`audit_client.verify` -> `ok`).

## Discoverability / CI
`tools/ci_suites.py` suite `agent_loop_integration` now also runs `test_agent_loop_mcp_integration.py`. The registry self-test still passes.

## Integration smoke (registered CI command, from repo root)
```
14 passed in 10.72s
PASS: ci_suites unit tests (W1..W7)
```
