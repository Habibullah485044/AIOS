# T-03278 Evidence: Agent Loop Hardening Core Service — Integration

- Date: 2026-11-05

## Production surface
`register_agent_loop_service_tools(mcp)` in `code/aiosh-mcp/aiosh_mcp/agent_loop_service.py`,
registered in `code/aiosh-mcp/aiosh_mcp/server.py` right after the data-model tools:

| MCP tool | Kind | Maps to |
|---|---|---|
| `aios_agent_loop_start` | mutating (token) | `AgentLoopService.start_loop` |
| `aios_agent_loop_advance` | mutating (token) | `AgentLoopService.advance_turn` |
| `aios_agent_loop_abort` | mutating (token) | `AgentLoopService.abort_loop` |
| `aios_agent_loop_snapshot` | read-only | `AgentLoopService.get_snapshot` |

All tools return the ADR-0035 `LoopResultEnvelope` (`ok`, `error`, `error_code`, `data`);
service and data-model exceptions are mapped to envelopes, never raised to the transport.

## Cross-substrate parity
`test_snapshot_canonical_json_round_trip`: snapshot from the MCP surface -> canonical JSON
(sorted keys, compact separators) -> `LoopSnapshot.from_dict` -> identical canonical JSON.

## Integration smoke
`code/aiosh-mcp/tests/test_agent_loop_core_service_integration.py` (5 cases: registration,
end-to-end start/advance/refuse/snapshot/abort/terminated, fail-closed without token,
invalid-config envelope, JSON round-trip).

```
cd code/aiosh-mcp && python -m pytest tests/ -k agent_loop -q
65 passed, 909 deselected in 4.03s
```

## Full-suite baseline (known pre-existing failures)
Full `tests/` run on this branch: 833 passed, 137 failed, 4 skipped; on `main`: 823 passed, 142 failed.
All failures are `FileNotFoundError` launching `target\debug\aiosh-mcp.exe` (Rust binary not built
on this host). No new failures introduced.

## Known gap (carried to T-03279)
The data-model tool `aios_agent_loop_init` (T-03268) writes to `_GLOBAL_LOOP_REGISTRY`, while the
service owns its own registry, so a loop created by one is not visible to the other.
