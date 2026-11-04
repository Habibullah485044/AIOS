# T-03293 Research: Agent Loop Hardening — MCP/API surface

- Date: 2026-11-05
- Scope: research only. **No code changed.**

## Facts (verified)
| # | Fact | Source |
|---|---|---|
| F1 | The server is the official MCP Python SDK's `mcp.server.fastmcp.FastMCP` (`mcp` 1.29.1); 59 tools are registered. `FastMCP.tool()` accepts `name`, `title`, `description`, `annotations`, `structured_output`. | `aiosh_mcp/server.py:38`; `inspect.signature(mcp.tool)` |
| F2 | Agent-loop tools today: `aios_agent_loop_{start,advance,abort,snapshot}` (service, T-03278) and `aios_agent_loop_{init,status}` (data model, T-03268). There is **no** MCP tool for `complete_loop` (added T-03286), for audit history, or for listing loops. | `agent_loop_service.py`, `agent_loop_data_model.py` |
| F3 | The generated input schemas carry **no constraints**: no `loop_id` pattern, no length caps, no integer ranges. Clients cannot discover limits; they hit `LOOPDATA_ERR_BOUNDS_EXCEEDED` / `LOOPSERV_ERR_INVALID_INPUT` at call time. | `tools/list` schema dump of `aios_agent_loop_advance` |
| F4 | No agent-loop tool sets MCP **tool annotations**. The MCP spec defines `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`, and SDK 1.29.1 exposes them (`mcp.types.ToolAnnotations`). | MCP spec 2025-03-26 "Tool annotations"; `ToolAnnotations.model_fields` |
| F5 | There are two envelope shapes. The service tools return `{ok, error, error_code, data}` (`LoopResultEnvelope`). The data-model tools return `{ok, error}` (no `error_code`) or `{ok, snapshot}` at the top level. | both modules |
| F6 | There are two registries. A loop started via `aios_agent_loop_start` is invisible to `aios_agent_loop_status`, and vice versa. | T-03278 evidence "Known gap" |
| F7 | `capability_token` travels as an ordinary tool argument, so it can appear in MCP client transcripts and logs. The protocol has no secret-argument channel. The impact is bounded: grants are single-use for start and loop-bound afterwards (T-03279). | MCP spec "tools/call"; T-03279 |
| F8 | The previous epic (`model_backend_adapters_api.py`) added a hand-written JSON-RPC 2.0 adapter **on top of** FastMCP. FastMCP already speaks JSON-RPC 2.0, so a second adapter is redundant. | `model_backend_adapters_api.py:1-5` |

## Upstream references
- MCP specification 2025-03-26, Server › Tools (tool definition, `inputSchema`, annotations): https://modelcontextprotocol.io/specification/2025-03-26/server/tools
- MCP Python SDK (FastMCP `@mcp.tool`, pydantic `Field` constraints become JSON Schema): https://github.com/modelcontextprotocol/python-sdk
- JSON Schema 2020-12 `pattern`, `maxLength`, `minimum`/`maximum`: https://json-schema.org/draft/2020-12/json-schema-validation

## Assumptions
- A1: Agents choose tools by schema and annotations, so exposing limits and read-only/destructive hints reduces failed calls. Annotations are **hints**, not enforcement; the server-side checks stay authoritative.
- A2: `typing.Annotated[..., pydantic.Field(...)]` in tool signatures produces the constraints in `inputSchema` under SDK 1.29.1. To be confirmed in the scaffold task.

## Decisions needed (for T-03294)
- D1: Add `aios_agent_loop_complete` (mutating), `aios_agent_loop_history` (read-only, audit-backed) and `aios_agent_loop_list` (read-only). (Recommended.)
- D2: Annotate every agent-loop tool: read-only tools `readOnlyHint=true`; abort/complete `destructiveHint=true`; start/advance `destructiveHint=false`. (Recommended.)
- D3: Put the limits into the schemas with `Annotated` + `Field` (pattern, lengths, ranges), mirroring the service constants. (Recommended.)
- D4: Unify reads: `aios_agent_loop_status` falls back to the service registry, and the data-model tools gain `error_code`, without breaking their existing keys. (Recommended.)
- D5: Do **not** add a separate JSON-RPC adapter (F8). (Recommended.)
- D6: Responses never echo `capability_token`; document F7 as a known limitation.
