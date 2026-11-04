# T-03294 Specification: Agent Loop Hardening — MCP/API surface

- Date: 2026-11-05
- Adopts T-03293 decisions D1..D6. Tool names, envelopes and error codes are **AIOS-specific**. The annotations use the MCP-spec `ToolAnnotations` fields.

## Module layout
| Status | Item |
|---|---|
| **New** | `aiosh_mcp/agent_loop_mcp.py`: `register_agent_loop_mcp_tools(mcp_app, service=None, db_path=None)` owns every `aios_agent_loop_*` service tool |
| Changed | `agent_loop_service.register_agent_loop_service_tools` becomes a one-line delegate (kept for compatibility); `server.py` keeps calling it |
| **New** | `agent_loop_gate.read_loop_history(db_path, loop_id, limit)`: read-only audit query, shared by the CLI `history` and the MCP tool (the CLI's private copy moves here) |
| Reused | `AgentLoopService` (incl. `complete_loop`), `LoopResultEnvelope`, `_error_envelope`, `PepCapabilityGate` |
| Changed (D4) | `aios_agent_loop_status` falls back to the service registry; the data-model tool errors gain `error_code` (existing keys unchanged) |

## Tools
All tools return `LoopResultEnvelope`: `{"ok": bool, "data"?: {...}, "error"?: str, "error_code"?: str}`. They never raise to the transport and never echo `capability_token`.

| Tool | Annotations | Inputs (schema constraints) | `data` on success |
|---|---|---|---|
| `aios_agent_loop_start` | readOnly=false, destructive=false, idempotent=false | `loop_id` pattern `^[a-zA-Z0-9_-]{8,64}$`; `capability_token` 1..256; `max_iterations` 1..100; `max_total_tokens` 100..1000000; `timeout_ms_per_step` 1000..120000; `total_timeout_ms` 5000..1800000; `consecutive_failure_limit` 1..10 | `snapshot` |
| `aios_agent_loop_advance` | readOnly=false, destructive=false, idempotent=false | `loop_id`; `action_intent` 1..4096; `capability_token`; `tool_name` pattern `^[A-Za-z0-9_.-]{1,128}$` or null; `tool_args` object or null; `tokens_consumed` 0..1000000; `policy_allowed` bool | `step`, `state`, `is_terminated` |
| `aios_agent_loop_abort` | readOnly=false, **destructive=true**, idempotent=true | `loop_id`; `reason` 1..1024; `capability_token` | `snapshot` |
| `aios_agent_loop_complete` **(new)** | readOnly=false, **destructive=true**, idempotent=false | `loop_id`; `capability_token` | `snapshot` |
| `aios_agent_loop_snapshot` | **readOnly=true** | `loop_id` | `snapshot` |
| `aios_agent_loop_list` **(new)** | **readOnly=true** | `include_terminated` bool (default false) | `loops`: `[{loop_id, current_state, current_iteration, total_tokens_used, is_terminated}]`, at most 256 |
| `aios_agent_loop_history` **(new)** | **readOnly=true** | `loop_id`; `limit` 1..1000 (default 100) | `loop_id`, `events` (`id, ts, tool, outcome, outcome_detail, args`) |

Schema constraints are advisory to clients. The **server re-validates everything**, so a client that ignores the schema
gets the same `LOOPDATA_ERR_BOUNDS_EXCEEDED` / `LOOPSERV_ERR_INVALID_INPUT` envelope. FastMCP's own pydantic validation
error for a schema violation is also returned as a tool error, never a crash.

## Error cases
The error codes are those of SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE §6. Additions:
`LOOPMCP_ERR_AUDIT_READ` (history: corrupt or unreadable DB).

## Persistence and audit effects
- `start`/`advance`/`abort`/`complete`: exactly the service rows (`pep.capability.redeem` once, then `aios.agent_loop.{start,step,abort,complete,timeout}`).
- `snapshot`/`list`/`history`/`status`: **no writes**. `history` opens the DB read-only (`mode=ro`) and returns an empty list if the DB or table is absent.

## Happy path
`start` (grant redeemed), then N x `advance`, then `complete`; `history` shows `start`, `step` x N, `complete`.

## Failure path
A forged token on `start` gives `ok=false`, `LOOPSERV_ERR_UNAUTHORIZED`, and no rows. A schema violation (e.g. a `loop_id` of 3 chars) gives
`ok=false` and no state change. An audit failure mid-loop gives `LOOPSERV_ERR_AUDIT` and the loop is ABORTED.

## Invariants
- LOOPMCP-INV1: every mutating tool requires a capability token; read-only tools require none and write nothing.
- LOOPMCP-INV2: every agent-loop tool carries `ToolAnnotations` matching the table above.
- LOOPMCP-INV3: the published `inputSchema` limits equal the server-side limits (one source of constants).
- LOOPMCP-INV4: responses contain no `capability_token` value and no unmasked secret.
