# Research Evidence: AI Control Plane MCP Server Core Recovery & Validation (T-03153)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / recovery & validation
- **Artifact**: `docs/tasks/evidence/T-03153-recovery-validation-research.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MCP-SERVER-CORE-CONFIG

---

## 1. Facts, Constraints, and Prior Art

### 1.1 Established Facts (Authoritative)
1. **MCP Core State Persistence & Vulnerabilities**:
   - MCP Server Core relies on on-disk configuration files (`AIOS_MCP_CONFIG_PATH` or `--config`) and session stores.
   - Sudden power cuts, uncoordinated process termination, or disk truncation can leave state files malformed, unparseable, or partially written.
2. **Prior Art in Subsystems**:
   - `session_recovery.rs`, `service_recovery.rs`, and `compliance_recovery.py` establish non-destructive self-healing protocols:
     - Deep validation before usage.
     - Corrupted files quarantined to `<path>.bak.<timestamp>` with restricted `0600` permissions.
     - Atomic replacement via PID-isolated temp files (`.tmp.<pid>.<nanos>`).
3. **Dual-Substrate Architecture**:
   - Python substrate (`aiosh_mcp.mcp_server_core_recovery`): Diagnostic inspector and non-destructive repair coordinator.
   - Rust substrate (`aiosh-core::mcp_server_core_recovery`): High-efficiency file integrity validation and quarantine engine.
4. **Proof-of-Restraint Gating (PoR Invariant I-2)**:
   - Integrity checks (`check`) are pure queries (`READ_ONLY`) and require no capability tokens.
   - Repairs and quarantine actions (`repair`) modify filesystem state and strictly require explicit capability tokens (`STATE_CHANGING` / PEP gated).

### 1.2 Identified Assumptions (vs. Facts)
1. *Assumption*: Unparseable JSON files should immediately be overwritten by default configurations.
   - *Fact*: Destructive overwriting destroys forensics and operator data. Damaged state must be quarantined to a timestamped backup before initializing a clean state.
2. *Assumption*: Integrity validation requires loading the complete file into arbitrary memory structures.
   - *Fact*: File size checks must precede JSON parsing (`MAX_STORE_SIZE = 10 MiB`, `MAX_CONFIG_SIZE = 64 KiB`) to prevent denial-of-service via memory exhaustion.

### 1.3 Constraints & Boundaries
1. **Path Safety**:
   - Target store and config paths must be validated against path traversal (`..`), directory separators outside boundary, and embedded NUL bytes (`\0`).
2. **Quarantine Permissions**:
   - Backups must be written with `0600` (read/write only by owner) to prevent unauthorized read access to potentially sensitive configurations.
3. **Mathematical Invariants (`MCPRECV-INV1..MCPRECV-INV5`)**:
   - `Total == Valid + Invalid`
   - `Healthy == (Errors.is_empty() and Invalid == 0)`
   - `Invalid > 0 implies len(Errors) >= Invalid`

---

## 2. Decisions & Implementation Roadmap

- **Decision 1**: Create `code/aiosh-mcp/aiosh_mcp/mcp_server_core_recovery.py` and `code/aiosh-rust/aiosh-core/src/mcp_server_core_recovery.rs`.
- **Decision 2**: Expose `aios_mcp_recovery_check` (read-only) and `aios_mcp_recovery_repair` (gated with capability token) via FastMCP.
- **Decision 3**: No code changes in this research task; begin implementation in scaffold (`T-03155`).
