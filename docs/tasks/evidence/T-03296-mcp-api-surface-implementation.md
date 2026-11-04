# T-03296 Evidence: Agent Loop Hardening — MCP/API surface Implementation

- Date: 2026-11-05
- `aiosh_mcp/agent_loop_mcp.py` `register_agent_loop_mcp_tools` now owns all 7 tools. The 3 new ones are
  `aios_agent_loop_complete`, `aios_agent_loop_list` and `aios_agent_loop_history`. Each tool carries its `ToolAnnotations` and constrained input schema.
- `agent_loop_service.register_agent_loop_service_tools` is now a delegate. `server.py` is unchanged, and the server catalog grew 59 -> **62** tools.
- `agent_loop_gate.read_loop_history` is the single read-only audit reader. The CLI `history` now uses it, and its private copy was removed (reuse, no duplication).
- `aios_agent_loop_status` (data model) falls back to the service registry, which closes the read side of the two-registry gap (T-03293 D4).
- Design detail: `capability_token` has `max_length` but **no** `min_length`. A missing token therefore reaches the service and returns
  the documented `LOOPSERV_ERR_UNAUTHORIZED` envelope instead of a schema error.

## Test-first
`tests/test_agent_loop_mcp_impl.py` was written before the implementation and errored (stub raised `NotImplementedError`). After:
```
3 passed in 2.32s
155 passed, 909 deselected in 11.76s   (all agent-loop suites)
```
Covered: all 7 tools present with the spec annotations; a start/advance/list/complete/list(include_terminated)/history lifecycle;
the grant id never appears in any response (LOOPMCP-INV4).

## Behaviour change (intentional, per T-03294)
A `loop_id` that violates the published pattern is now rejected by FastMCP schema validation (`ToolError` / MCP `isError`)
before the tool body runs. The T-03278 test was updated accordingly. Out-of-range values that pass the schema still return
`LOOPDATA_ERR_BOUNDS_EXCEEDED` envelopes.

## No regression
PoR conformance and gate suites: 15 passed, 1 warning in 5.51s
