# Evidence: T-02746 — Threat Model Configuration Integration

## Task Metadata
- **Task ID**: T-02746
- **Title**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / configuration: Integration
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Status**: Completed
- **Date**: 2026-10-03
- **Artifact Path**: `docs/tasks/evidence/T-02746-configuration-integration.md`

## Objectives
1. Integrate `ThreatModelConfig` with the surrounding runtime system and core services.
2. Connect `ThreatModelService` with `ThreatModelConfig` via `ThreatModelService::from_config`.
3. Expose the configuration inspection and validation surface in the production MCP server via `aios.threat.config`.
4. Validate cross-substrate parity across JSON files, memory stores, and SQLite audit ring logging.
5. Perform security audit against relevant CWEs (CWE-20, CWE-22, CWE-400, CWE-778).

## Integration Implementation & Findings
1. **Service Integration**:
   - Added `ThreatModelService::from_config(config: &ThreatModelConfig)` in `code/aiosh-rust/aiosh-core/src/threat_model_service.rs`.
   - Verified that configured store paths, capacity limits, and validation checks seamlessly govern service instances.
2. **MCP Tool Integration**:
   - Registered `aios.threat.config` in `tool_manifest()` in `code/aiosh-rust/aiosh-mcp/src/main.rs`.
   - Implemented `show` and `check` actions in `call_tool()` routed through `dispatch::recorded_call`.
3. **Cross-Substrate Verification**:
   - Executed `test_threat_model_config_service_integration` confirming that configurations serialized to disk instantiate operational services capable of registering threats, mitigating risks, and calculating scores.
   - Executed `test_mcp_threat_model_tools_execution` confirming that `aios.threat.config` handles `show`, `check`, and traversal rejections cleanly.

## Security Audit (CWE Analysis)
- **CWE-20 (Improper Input Validation)**: Rejections confirmed for unknown configuration actions and invalid parameter blocks.
- **CWE-22 (Path Traversal)**: Both MCP tool and core loaders reject path traversal sequences (`..`).
- **CWE-400 (Uncontrolled Resource Consumption)**: 64 KiB configuration size cap safely enforced across all integrated callers.
- **CWE-778 (Insufficient Logging)**: MCP tool calls write audit traces to SQLite WAL storage.

## Verification
- Ran: `cargo test -p aiosh-core --test test_threat_model_config_integration` (1 passed; 0 failed).
- Ran: `cargo test -p aiosh-mcp -- test_mcp_threat_model_tools_execution` (1 passed; 0 failed).
