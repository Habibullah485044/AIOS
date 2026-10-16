# Unit Tests: Incident Response Runbooks Recovery & Validation Subsystem (T-03057)

**Task ID**: T-03057 (Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / recovery & validation: Unit Test)  
**Contract Reference**: `docs/tasks/evidence/T-03054-spec.md`  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: COMPLETE — 4 comprehensive unit test cases implemented and passing standalone across Rust core and Python MCP.

---

## 1. Unit Test Cases Implemented

1. **Case 1: Valid Input (Happy Path & Non-Destructive Integrity)**:
   - Validates canonical baseline state file (`RunbookCatalogSnapshot::canonical_baseline()`).
   - Asserts `RunbookCatalogStatus::Healthy`, 0 issues, and verified count of runbooks.
   - Tests backup creation (`create_backup`), ensuring `.bak` file is created atomically.
   - Verifies that invoking `repair_runbook_state` on a healthy catalog is a non-destructive no-op (`action_taken="noop"`).

2. **Case 2: Invalid Input (Path Traversal, Syntax, Duplicate IDs)**:
   - Evaluates path traversal attempts (`../../etc/shadow`), verifying immediate rejection with `InvalidPathTraversal` and `status=Corrupted`.
   - Tests malformed JSON payload (`{bad-json`), verifying rejection with `InvalidJsonSyntax` and `status=Corrupted`.
   - Tests missing schema arrays (`{}`), verifying rejection with `SchemaMismatch`.
   - Tests duplicate runbook identifiers, verifying detection of `DuplicateRunbookId` and classification as `status=Degraded`.

3. **Case 3: Boundary Values (Payload Caps & Quarantine Rotation)**:
   - Tests payload size bounding against `MAX_RUNBOOK_STATE_SIZE = 10 MiB`. Payloads exceeding limit are rejected with `OversizedPayload`.
   - Tests quarantine file rotation: generates 15 `.corrupt.` files and calls `prune_old_quarantine_files`. Confirms exactly 5 oldest files are pruned, capping total quarantine files at `MAX_QUARANTINE_FILES = 10`.

4. **Case 4: Primary Failure Mode (Corrupted State Quarantine & Repair)**:
   - Seeds a state file with corrupted broken content.
   - Calls `repair_runbook_state`: verifies that the corrupted file is preserved into a timestamped `.corrupt.<pid>.<ts>` quarantine file.
   - Confirms that state is safely restored from canonical baseline (`action_taken="canonical_reinitialized"`).
   - Verifies that post-repair health check confirms `RunbookCatalogStatus::Healthy` with all canonical runbooks present.

---

## 2. Test Execution Results

- **Rust Suite**: `code/aiosh-rust/aiosh-core/tests/test_incident_runbook_recovery_unit.rs`
  - Result: 4 passed; 0 failed (0.13s)
- **Python Suite**: `code/aiosh-mcp/tests/test_incident_runbook_recovery_unit.py`
  - Result: 4 passed; 0 failed (0.76s)
