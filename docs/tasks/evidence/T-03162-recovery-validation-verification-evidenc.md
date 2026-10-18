# Verification & Evidence: AI Control Plane MCP Server Core Recovery & Validation (T-03162)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / recovery & validation
- **Artifact**: `docs/tasks/evidence/T-03162-recovery-validation-verification-evidenc.md`
- **Milestone Span**: `T-03153` .. `T-03162`
- **Log Entry**: [docs/proof-of-restraint/LOG.md](../../proof-of-restraint/LOG.md)

---

## 1. Subsystem Verification Battery

### 1.1 Python Test Suite Execution
Executed all unit, integration, scaffold, implementation, and hardening test suites:
```
platform win32 -- Python 3.14.6, pytest-9.1.1
collected 21 items

code/aiosh-mcp/tests/test_mcp_server_core_recovery_scaffold.py ..        [  9%]
code/aiosh-mcp/tests/test_mcp_server_core_recovery_impl.py ....          [ 28%]
code/aiosh-mcp/tests/test_mcp_server_core_recovery_unit.py .....         [ 52%]
code/aiosh-mcp/tests/test_mcp_server_core_recovery_integration.py ....  [ 71%]
code/aiosh-mcp/tests/test_mcp_server_core_recovery_hardening.py ......    [100%]

============================= 21 passed in 3.63s ==============================
```

### 1.2 Proof of Restraint Demonstration & Invariant I-2 Check
Executed `python -u tools/demo_por.py`:
- Step 1: Normal activity + shadow action, mint unused capability (`gr_demo_untouched`).
- Step 2: Anchor audit ring with signed Ed25519 checkpoints.
- Step 3: Generate restraint proof (`por_...`) for unused grant -> `PROVABLY_RESTRAINED`.
- Step 4: Standalone verifier exit code 0 (`valid: true`).
- Step 5: Attacker tampers by deleting shadow row and re-chaining -> Standalone verifier exit code 1 (`HEAD_HASH_MISMATCH`, `valid: false`).
- Result: **PASS** (Zero Escalation / Proof of Restraint verified).

---

## 2. Invariants Certified

- **`MCPRECV-INV1` (Accounting Sum Invariant)**: `total_records == valid_records + invalid_records` strictly conserved across all validation reports.
- **`MCPRECV-INV2` (Binary Health Equivalence)**: `is_healthy == (len(issues) == 0 and invalid_records == 0)` verified.
- **`MCPRECV-INV3` (Non-Destructive Quarantine)**: Corrupted files copied to `<path>.bak.<timestamp>` with `0600` permissions prior to reinitialization.
- **`MCPRECV-INV4` (Path Traversal & Injection Immunity)**: Traversal sequences (`..`), NUL bytes, ADS colons (`:`), and reserved Windows device names (`CON`, `PRN`, etc.) fail closed.
- **`MCPRECV-INV5` (PoR Invariant I-2 Gating)**: Read-only validation (`validate_mcp_store`, `aios_mcp_recovery_check`) requires zero tokens; mutations (`recover_mcp_store`, `aios_mcp_recovery_repair`) strictly require a capability token grant.

---

## 3. Upstream Tasks Shipped in Feature Block

| Task ID | Stage | Shipped Evidence / Commit |
| :--- | :--- | :--- |
| `T-03153` | Research | `docs/tasks/evidence/T-03153-recovery-validation-research.md` |
| `T-03154` | Specification | `docs/SPEC-MCP-SERVER-CORE-RECOVERY.md` |
| `T-03155` | Scaffold | `mcp_server_core_recovery.py` & `.rs` |
| `T-03156` | Implementation | `validate_mcp_store` & `recover_mcp_store` |
| `T-03157` | Unit Test | Invariant test battery (`MCPRECV-INV1..5`) |
| `T-03158` | Integration | FastMCP tools `aios_mcp_recovery_check`, `aios_mcp_recovery_repair` |
| `T-03159` | Security Review | 5 abuse scenarios, DoS and quarantine permission defense |
| `T-03160` | Hardening | Reserved device names, ADS rejection, path sanitization |
| `T-03161` | Documentation | Updated `code/aiosh-mcp/README.md` |
| `T-03162` | Verification & Evidence | This artifact, PoR log entry, tests green |
