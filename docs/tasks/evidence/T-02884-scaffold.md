# Task Evidence: T-02884 — Continuous Restraint Conformance: Scaffold

- **Task ID**: `T-02884`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / continuous restraint conformance (Component 6)
- **Date**: 2026-10-07
- **Invariants Researched**: `I-5` (Continuous Conformance Gate)

## Scaffold Delivered

1. **`code/aiosh-mcp/tests/test_por_conformance.py`** — CRCS scenario scaffold:
   - Module docstring carries the normative contract (T-02883-spec.md) and criteria map C1..C6 with drift classes.
   - Shared sandbox fixtures `conform_env` (isolated `AIOSH_HOME` + temp `audit.db`, zero network) and `anchor_keys` (deterministic Ed25519 material).
   - 14 test nodes covering every criterion: C1.1–C1.3 (non-bypassability incl. the "new tool additions" coverage clause), C2.1–C2.2 (mint/redeem parity), C3.1–C3.3 (untouched-grant stability + idempotence), C4.1–C4.2 (touched-grant invalidation, catastrophic direction), C5.1–C5.2 (substrate oracle parity), C6.1–C6.2 (anchor continuity + window bounding).
   - Scaffold contract honored: every body calls `_pending(criterion)` and fails loudly (`NotImplementedError`) until T-02885.

2. **`tools/test_por_conformance_suites.py`** — criteria battery runner scaffold:
   - `CRITERIA = C1..C6` with `CRITERIA_TESTS` node-id map (mirrors `tools/test_fs_layout_suites.py` style).
   - Fail-closed `main()`: prints per-criterion PASS/FAIL, exits non-zero on any failure with `NON-CONFORMANT: <criteria>`; scaffold bodies raise until T-02885.

## Verification
```
python3 -m pytest code/aiosh-mcp/tests/test_por_conformance.py --collect-only -q
============================= 14 tests collected in 0.09s ====================
python3 -c "import test_por_conformance_suites"
criteria: C1,C2,C3,C4,C5,C6   (imports cleanly)
```

## Next
T-02885 (Implementation) fills all fixture and test bodies against the T-02883 contract.
