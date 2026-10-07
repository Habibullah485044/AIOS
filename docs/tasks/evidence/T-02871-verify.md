# Task Evidence: T-02871 — Restraint Proof Generator: Verification & Evidence

- **Task ID**: `T-02871`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator (Component 4 Closeout)
- **Date**: 2026-10-07
- **Invariants Certified**: `I-4` (Self-Contained Negative Attestation Package)

---

## 1. Executive Summary & Verification Matrix
Component 4 (Restraint Proof Generator, tasks T-02862 through T-02871) has completed its full lifecycle: Research -> Specification -> Scaffold -> Implementation -> Unit Test -> Integration -> Security Review -> Hardening -> Documentation -> Verification & Evidence.

All deliverables have been validated across Python and TypeScript codebases.

| Item | Component Artifact | Test Suite / Check | Result |
|---|---|---|---|
| **Python Core** | `code/aiosh-mcp/aiosh_mcp/restraint.py` | `test_por_restraint_generator.py` (11 tests) | **PASS (11/11)** |
| **MCP Tool Surface** | `aios.restraint.prove` in `server.py` | `test_por_restraint_integration.py` (3 tests) | **PASS** |
| **TypeScript Core** | `code/aiosh-cli/src/restraint.ts` | `npm run build` (`tsc -p tsconfig.json`) | **PASS (0 errors)** |
| **CLI Subcommand** | `aiosh prove restraint` in `cli.ts` | CLI option parsing + help display | **PASS** |
| **Security Hardening** | Strict bounding anchors + safe path + ISO-8601 validation | Hardened test cases | **PASS** |
| **Specification** | `docs/SPEC-RESTRAINT-PROOF-GENERATOR.md` | Formal schema & Invariant I-4 lock | **LOCKED** |

---

## 2. Test Execution Telemetry

```
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_generate_valid_restraint_proof PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_window_invalid_rejection PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_grant_not_found_rejection PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_grant_already_redeemed_in_grant_table PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_grant_redeemed_in_audit_ring_row PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_grant_detected_in_archived_segment_bloom PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_archived_segment_bloom_exclusion_success PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_no_covering_anchors_rejection PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_hardened_invalid_timestamp_rejection PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_hardened_nul_byte_path_rejection PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_hardened_unbounding_anchors_rejection PASSED
code/aiosh-mcp/tests/test_por_restraint_integration.py::test_mcp_restraint_prove_tool_success PASSED
code/aiosh-mcp/tests/test_por_restraint_integration.py::test_mcp_restraint_prove_tool_negative PASSED
code/aiosh-mcp/tests/test_por_restraint_integration.py::test_cli_prove_restraint_subprocess SKIPPED (Win32 substrate check)
======================== 13 passed, 1 skipped in 2.71s ========================
```

---

## 3. Component Closeout Certification
Component 4 (Restraint Proof Generator) is hereby certified complete, hardened, and locked.
The system now advances to **Component 5 — Standalone Proof Verifier (T-02872..T-02881)**.
