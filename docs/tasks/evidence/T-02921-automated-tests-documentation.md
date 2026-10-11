# T-02921 — Compliance Mapping / Automated Tests: Documentation

**Task**: T-02921 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / automated tests: Documentation)
**Normative Specification**: `docs/SPEC-COMPLIANCE-AUTOMATED-TESTS.md`
**Date**: 2026-10-11
**Status**: COMPLETE — Normative specification, test matrix, invocation guides, copy-pasteable examples, and constraints documented.

---

## 1. Documentation Delivered

1. **Normative Specification Document**:
   - `docs/SPEC-COMPLIANCE-AUTOMATED-TESTS.md`:
     - Test vectors matrix (`AUTOCOMPLIANCE1`..`AUTOCOMPLIANCE10`) with tested invariants.
     - Invocation guides for Python test suites (`test_compliance_automated_smoke.py`, `test_compliance_automated_unit.py`, `test_compliance_integration.py`).
     - Invocation guides for Rust test suites (`test_compliance_automated.rs`, `test_compliance_automated_unit.rs`).
     - Copy-pasteable CLI commands (`aiosh compliance init/register/status/assess`).
     - Copy-pasteable Python / MCP wire tool calls.
     - Honest constraints and limitations recorded.
     - Bidirectional links to task evidence files T-02913 through T-02920.

---

## 2. Invocation Quick Reference

```bash
# Python automated suites
python -m pytest code/aiosh-mcp/tests/test_compliance_automated_smoke.py -v
python -m pytest code/aiosh-mcp/tests/test_compliance_automated_unit.py -v
python -m pytest code/aiosh-mcp/tests/test_compliance_integration.py -v

# Rust core automated suites
cargo test -p aiosh-core --test test_compliance_automated
cargo test -p aiosh-core --test test_compliance_automated_unit
```
