# Artifact: T-02887 Continuous Restraint Conformance Integration

- **Task**: T-02887
- **Primary Evidence**: T-02887-integration.md (docs/tasks/evidence/)
- **Status**: Complete
- **Deliverables**: `por_conformance` suite registered in `tools/ci_suites.py` (index 29, tail append) so `ci/run_all_smokes.sh` enforces I-5; `tools/ci_run.py` bash-resolution portability fix (System32/WSL shadowing).
- **Known blocker**: pre-existing `rust_smoke` cargo-test failure (64 passed / 2 failed) stops the fail-fast pipeline before suite 30 on this host; the conformance suite's own CI command is green (`CONFORMANT: C1..C6 PASS`).
