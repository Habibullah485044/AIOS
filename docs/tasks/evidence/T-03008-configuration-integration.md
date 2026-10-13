# Evidence: T-03008 Incident Response Runbooks configuration Integration

## Summary
- **Task ID**: T-03008
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Area**: Incident Response Runbooks / configuration
- **Type**: Integration

## Integration Changes
1. **Production MCP Surface Wiring (`aios_runbook`)**:
   - Integrated `resolve_runbook_config` into `code/aiosh-mcp/aiosh_mcp/incident_runbook_mcp.py`.
   - Exposed `action="config"` under `aios_runbook` FastMCP tool registration.
   - Authoritative PEP dispatch executes `runbook.config` through the dispatch gate, returning the resolved 4-level precedence dictionary and recording an audit row into the SQLite audit store.
   - Dynamic session capping: `execute_runbook_core(action="start")` now uses `cfg.max_active_sessions` dynamically rather than hardcoding static limits.
2. **Rust Core Integration**:
   - Integrated `resolve_runbook_config` defaults and overrides into `incident_runbook_service`.

## Verification Results
- **MCP Server Tool Exposure & Dispatch**:
  - `aios_runbook` tool on FastMCP server documents `config` action.
  - End-to-end call `execute_runbook_action(action="config")` produces verified `audit_ring` row with tool `aios.runbook`, command `runbook.config`, and outcome `ok`.
- **Dynamic Capping Verification**:
  - `AIOSH_RUNBOOK_MAX_SESSIONS=3` dynamically bound active sessions, pruning oldest when capacity is exceeded.
- **Test Runs**:
  - `pytest code/aiosh-mcp/tests/test_incident_runbook_mcp_integration.py code/aiosh-mcp/tests/test_runbook_config_integration.py`: 5 passed in 3.60s.
  - `cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_runbook_config_integration`: 2 passed in 0.00s.
