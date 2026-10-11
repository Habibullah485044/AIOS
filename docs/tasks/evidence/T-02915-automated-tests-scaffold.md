# T-02915 — Compliance Mapping / Automated Tests: Scaffold

**Task**: T-02915 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / automated tests: Scaffold)
**Depends on**: T-02914 (Specification — `docs/tasks/evidence/T-02914-spec.md`)
**Date**: 2026-10-11
**Status**: COMPLETE — Both substrates have automated test scaffold files wired, typed, compiling cleanly, and asserting normative vectors AUTOCOMPLIANCE1..AUTOCOMPLIANCE10.

---

## 1. Scaffold Deliverables

| Substrate | Artifact | Role |
|---|---|---|
| **Rust** | `code/aiosh-rust/aiosh-core/tests/test_compliance_automated.rs` | Rust automated test suite scaffolding exercising `ComplianceConfig`, `ComplianceService`, and `ComplianceMappingEntry` |
| **Python** | `code/aiosh-mcp/tests/test_compliance_automated_smoke.py` | Python automated smoke test suite scaffolding testing vectors AUTOCOMPLIANCE1..AUTOCOMPLIANCE10 against `compliance` and `compliance_config` |

---

## 2. Verification Vectors Scaffolding (AUTOCOMPLIANCE1..AUTOCOMPLIANCE10)

1. **AUTOCOMPLIANCE1**: Lifecycle and Transitions Scaffold (`FRAMEWORKS`, `ACTIONS`, `execute`).
2. **AUTOCOMPLIANCE2**: Duplicate ID Rejection Scaffold (`COMPLIANCE_ERR_DUPLICATE_ID`).
3. **AUTOCOMPLIANCE3**: Bounds Validation Scaffold (`MAX_COMPLIANCE_ID_LEN`, `MAX_COMPLIANCE_TITLE_LEN`, `MAX_COMPLIANCE_DESC_LEN`).
4. **AUTOCOMPLIANCE4**: Configuration Precedence Ladder Scaffold (`CONFIG_SOURCES`, `resolve`).
5. **AUTOCOMPLIANCE5**: Path Hygiene Predicate Scaffold (`hygiene_ok`).
6. **AUTOCOMPLIANCE6**: Size Caps Contract Scaffold (`MAX_CONFIG_FILE_BYTES == 64 KiB`).
7. **AUTOCOMPLIANCE7**: Mutation Audit Immutability Scaffold (`audit_all_mutations == True`).
8. **AUTOCOMPLIANCE8**: PEP Coverage and Gating Scaffold (`verify_pep_coverage`, `uncovered_pep_gates`).
9. **AUTOCOMPLIANCE9**: Assessment and Gap Scoring Scaffold (`assess` in `ACTIONS`, `ComplianceAssessmentReport`).
10. **AUTOCOMPLIANCE10**: Atomic Persistence Scaffold (`load_store`, `save_store`, `validate_path`).

---

## 3. Test Execution Results

- **Rust Suite**:
  `cargo test -p aiosh-core --test test_compliance_automated` -> 2 passed; 0 failed.
- **Python Suite**:
  `python -m pytest code/aiosh-mcp/tests/test_compliance_automated_smoke.py -v` -> 10 passed; 0 failed.
