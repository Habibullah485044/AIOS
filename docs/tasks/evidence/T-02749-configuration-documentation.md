# Documentation Evidence: Threat Model Configuration (T-02749)

## Overview
Documents the operational interface and configuration specification for the Threat Model Maintenance subsystem in `aiosh-core` and `aiosh-mcp`.

## Shipped Deliverables
1. **Specification**: Updated [`docs/SPEC-THREAT-MODEL-CONFIG.md`](../../SPEC-THREAT-MODEL-CONFIG.md) to `IMPLEMENTED & VERIFIED`.
2. **MCP Tool Documentation**: Documented `aios.threat.config` (`show` and `check` actions) with input schemas and responses.
3. **Rust API Reference**: Detailed `ThreatModelConfig` structure, boundaries, validation invariants (`THREATCONF1`..`THREATCONF5`), and environment variables.
4. **Copy-Pasteable Working Examples**:
   - MCP `aios.threat.config` `show` action.
   - MCP `aios.threat.config` `check` action for syntax/bounds validation.
   - Rust code showing `ThreatModelConfig::from_env()` and `ThreatModelService::from_config(&config)`.
5. **Operational Limits & Limitations**:
   - Symlinks forbidden (CWE-59).
   - Single-file storage capped at 16 MiB.
   - Capacity capped at 4,096 threats.
   - Configuration files capped at 64 KiB.
   - No background hot-reloading; requires service re-instantiation.

## Cross References
- Spec: `docs/SPEC-THREAT-MODEL-CONFIG.md`
- Research Evidence: `docs/tasks/evidence/T-02741-configuration-research.md`
- Security Review: `docs/tasks/evidence/T-02747-configuration-security-review.md`
- Hardening Evidence: `docs/tasks/evidence/T-02748-configuration-hardening.md`
