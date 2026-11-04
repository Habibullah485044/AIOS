# T-03297 Evidence: Agent Loop Hardening — MCP/API surface Unit Test

- Date: 2026-11-05
- Test file: `code/aiosh-mcp/tests/test_agent_loop_mcp_unit.py` (23 cases, standalone, isolated FastMCP app + temp audit DB)

| Area | Cases |
|---|---|
| Valid / accepted edges | `loop_id` of 8 and 64 chars; `action_intent` 4096, `tool_name` 128, `tokens_consumed` 0, `reason` 1024, history `limit` 1 and 1000 |
| Rejected one step past each edge (13) | `loop_id` 7/65, token 257, `max_iterations` 101, `total_timeout_ms` 4999, empty/4097 intent, `"a b"` tool name, tokens -1/1_000_001, reason 1025, limit 0/1001. Each raises an MCP `ToolError` and writes **zero audit rows** |
| Invalid but schema-valid | missing token -> `LOOPSERV_ERR_UNAUTHORIZED` envelope and no rows; unknown loop -> `NOT_FOUND` on snapshot, advance and complete |
| Primary failures | complete twice -> `TERMINATED`; abort after complete is idempotent; another loop's grant -> `UNAUTHORIZED` |
| Read-only contract | snapshot, list and history leave the audit ring unchanged; corrupt DB -> `LOOPMCP_ERR_AUDIT_READ`; missing DB -> empty events |

## Fails when broken
Mutation: `le=MAX_TOKENS_PER_TURN` was removed from `TokensArg` (the published schema no longer matches the server limit, violating LOOPMCP-INV3).
```
FAILED tests/test_agent_loop_mcp_unit.py::test_schema_violations_rejected_before_any_write[asyncio-aios_agent_loop_advance-args9]
1 failed, 22 passed
```
After restoring with `git checkout`:
```
23 passed in 4.42s
```
