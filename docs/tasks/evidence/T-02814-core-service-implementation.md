# Implementation Evidence: Compliance Mapping Core Service (T-02814)

- **Task ID**: T-02814
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Compliance Mapping / core service
- **Status**: Completed
- **Document Date**: 2026-10-04

## 1. Minimal Working Implementation
Implemented runtime engine in `code/aiosh-rust/aiosh-core/src/compliance_service.rs`:
- Implemented `ComplianceService` lifecycle:
  - `new` & `with_canonical_baseline`: Instantiation and baseline initialization.
  - `validate_path`: Enforces strict path safety (prohibits `..`, control characters, UNC roots, symlinks).
  - `load_from_path`: Size-capped reading (1 MiB max) and JSON deserialization into snapshot memory.
  - `save_to_path`: Crash-consistent atomic persistence via `.tmp.{pid}.{nanos}` and rename.
  - `register_mapping`, `get_mapping`, `update_status`, `remove_mapping`.
  - Filter queries: `find_by_framework`, `find_by_control`, `find_by_status`.
  - `assess_framework`: Dynamic calculation of framework-scoped or overall compliance posture, compliance percentage, and gap control listings.
  - `verify_pep_coverage` and `uncovered_pep_gates`: Verifies that critical PEP enforcement gates are backed by active compliance mappings.

## 2. Invariants Satisfied
- `COMPLYSVC1`: Non-destructive queries and assessment generation.
- `COMPLYSVC2`: Crash-consistent atomic file updates.
- `COMPLYSVC3`: Rejection of path traversal and symlinks.
- `COMPLYSVC4`: Hard 1 MiB store file size limit.
- `COMPLYSVC5`: Quantitative compliance assessment reporting.
