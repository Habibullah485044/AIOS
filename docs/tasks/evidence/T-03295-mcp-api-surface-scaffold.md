# T-03295 Evidence: Agent Loop Hardening — MCP/API surface Scaffold

- Date: 2026-11-05
- New `code/aiosh-mcp/aiosh_mcp/agent_loop_mcp.py`:
  - schema types `LoopIdArg`, `TokenArg`, `IntentArg`, `ReasonArg`, `ToolNameArg`, `TokensArg`, `HistoryLimitArg`. They are built with
    `typing.Annotated` + `pydantic.Field` from the **same constants** the service and CLI enforce (LOOPMCP-INV3).
  - `ToolAnnotations` presets `READ_ONLY`, `MUTATING`, `TERMINATING` and `TERMINATING_IDEMPOTENT`, plus a `TOOL_ANNOTATIONS` table for all 7 tools (LOOPMCP-INV2)
  - `register_agent_loop_mcp_tools(mcp_app, service=None, db_path=None)`, stubbed
- New stub `agent_loop_gate.read_loop_history(db_path, loop_id, limit)`
- Both stubs raise `NotImplementedError("T-03296: ...")`. `server.py` is untouched until T-03296, so the server still imports.

## Build / import
```
$ python -c "import aiosh_mcp.agent_loop_mcp, aiosh_mcp.server; print('import ok')"
import ok
```

## Call sites / test stubs (`tests/test_agent_loop_mcp_scaffold.py`)
- The annotation table covers exactly 7 tools: 3 read-only and 2 destructive.
- **T-03293 assumption A2 confirmed on SDK 1.29.1.** A probe tool on a throwaway `FastMCP` publishes `pattern`, `minimum`/`maximum` and
  `annotations.readOnlyHint` in its tool definition.
- Both stubs fail loudly.
```
153 passed, 909 deselected in 11.62s
```
