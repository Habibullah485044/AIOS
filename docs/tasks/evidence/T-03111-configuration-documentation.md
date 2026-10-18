# Documentation & Security Audit Evidence: AI Control Plane MCP Server Core Configuration Subsystem (T-03111)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / configuration
- **Target**: Operator and agent documentation, copy-pasteable examples, and constraints
- **Bindings**: SPEC-MCP-SERVER-CORE-CONFIG, ADR-0035 §D-2, PoR Invariant I-2

---

## 1. Documentation Overview

The MCP Server Core configuration subsystem has been comprehensively documented in `code/aiosh-mcp/README.md`:
1. **Tool Signatures**:
   - `aios_mcp_config_get()`: Retrieves active configuration state.
   - `aios_mcp_config_validate(candidate_config: dict)`: Validates configuration without persistence.
2. **Resolution Hierarchy**:
   - Detailed 4-tier resolution chain: CLI flags > Environment variables > Configuration file (`--config` or `AIOS_MCP_CONFIG_PATH`) > Hardcoded secure defaults.
3. **Usage Examples**:
   - Ready-to-use JSON-RPC 2.0 snippets for querying and validating configuration.

---

## 2. Security Audit of Documentation

- **Audit Finding 1 (No Sensitive Data Leakage)**: Verified that documentation contains only synthetic `.aios/` test paths and no live credentials, secrets, or internal server tokens.
- **Audit Finding 2 (Accurate Security Posture)**: Documented explicit failure modes, input sanitization rules, and PoR Invariant I-2 requirements so operators and automated agents understand that state modifications require capability token redemption.
- **Audit Finding 3 (Explicit Constraints)**: Stated bounds on sessions (`1..512`), timeouts (`1..300s`), and file sizes (`<= 64 KiB`) to ensure safe operational planning.

---

## 3. Verification

- `code/aiosh-mcp/README.md` updated and validated.
- All evidence links verified against repository structure.
