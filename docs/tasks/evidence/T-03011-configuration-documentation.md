# Evidence: T-03011 Incident Response Runbooks configuration Documentation

## Summary
- **Task ID**: T-03011
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Area**: Incident Response Runbooks / configuration
- **Type**: Documentation

## Documentation Deliverables
1. **Updated Specification**:
   - Updated [SPEC-INCIDENT-RUNBOOK-CONFIG.md](../../SPEC-INCIDENT-RUNBOOK-CONFIG.md) to `SHIPPED` status.
   - Documented complete 4-level precedence ladder, parameter bounds, error codes, and source provenance tags.
2. **Copy-Pasteable Invocation Examples**:
   - Added FastMCP tool invocation snippet for `aios_runbook(action="config")` with sample response payload.
   - Added Python SDK examples for strict resolution (`resolve_runbook_config`) and hardened envelopes (`safe_resolve_runbook_config`).
   - Added Rust substrate examples with `RunbookConfigOverrides` and `SafeResolvedRunbookConfig`.
3. **Recorded Constraints & Limitations**:
   - Immutable configuration posture over MCP RPC interface.
   - 64 KiB config file hard cap (`MAX_CONFIG_FILE_BYTES`).
   - Rejection of directory traversal tokens (`..`).
   - Absence of inotify file watchers (polling/on-demand evaluation).
4. **Evidence Cross-Links**:
   - Linked complete task trail (T-03003 through T-03010).
