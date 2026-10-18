# Documentation & Security Audit Evidence: AI Control Plane MCP Server Core Automated Tests (T-03121)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / automated tests
- **Target**: Operator and agent documentation, copy-pasteable examples, categories, and constraints
- **Bindings**: SPEC-MCP-SERVER-CORE-TESTS, ADR-0035 §D-2, PoR Invariant I-2

---

## 1. Documentation Overview

The MCP Server Core automated tests diagnostic runner has been documented in `code/aiosh-mcp/README.md`:
1. **Tool Signature**:
   - `aios_mcp_test_run(category: Optional[str] = None)`
2. **Category Taxonomy**:
   - `data_model`: Verifies data types, content blocks, and envelope serialization.
   - `api`: Verifies JSON-RPC 2.0 initialize, ping, and routing.
   - `service`: Verifies tool registry and session tracking.
   - `config`: Verifies configuration validation and resolution.
   - `security`: Verifies capability token gating and NUL byte sanitization.
   - Default: Runs all suites and aggregates findings.
3. **Usage Examples**:
   - Provided copy-pasteable JSON-RPC 2.0 requests for full and category runs.

---

## 2. Security Audit of Documentation

- **Audit Item 1 (No Secrets or Privileged Tokens Exposed)**: Documented examples use only simulated, safe payloads and omit live secrets or administrative tokens.
- **Audit Item 2 (Isolation Assurances)**: Documented that `aios_mcp_test_run` uses strictly in-memory, ephemeral fixtures to prevent operational state corruption during live diagnostic execution.
- **Audit Item 3 (Boundary Notice)**: Accurately stated 64-character ceiling and whitelist validation for the category parameter.

---

## 3. Verification

- Verified `code/aiosh-mcp/README.md` formatting and cross-links.
- All evidence links resolve to valid artifacts.
