# T-02714: Threat Model Maintenance Core Service Implementation

- **Task**: `T-02714`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / core service
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Implementation Scope
Implemented `ThreatModelService` in `code/aiosh-rust/aiosh-core/src/threat_model_service.rs`:
1. **Catalog Lifecycle**:
   - `new()`: Initializes default empty snapshot version "1.0.0".
   - `with_canonical_threats()`: Pre-seeds 7 baseline STRIDE threats covering PEP impersonation, ledger tampering, audit dropping, secret disclosure, DoS spawning, kernel privilege escalation, and supply chain poisoning.
   - `register_threat()`: Enforces capacity (`MAX_THREAT_ENTRIES_CAPACITY = 512`) and uniqueness.
   - `get_threat()` / `list_threats()`: Catalog inspection.
   - `update_status()`: Enforces deterministic state transitions.
   - `attach_mitigation()`: Appends verified mitigations.
2. **Risk Assessment Engine (`assess_risk`)**:
   - Evaluates aggregated threat posture across identified, under-review, mitigated, accepted, and resolved entries.
   - Identifies `critical_unmitigated_count`.
   - Computes weighted `overall_risk_score`.
3. **Persistence & Path Sanitization**:
   - `validate_path()`: Rejects `..`, UNC paths (`\\\\`, `//`), and control characters.
   - `load_from_path()`: Validates size bounds (`MAX_THREAT_MODEL_STORE_SIZE = 1 MiB`) and parses JSON snapshot.
   - `save_to_path()`: Atomic staged write to `<path>.tmp.threat` and rename to `<path>`.

## 2. Compiler Output
```
    Checking aiosh-core v0.1.0 (C:\Users\OBSESSION\Desktop\AIOS_MERGED\code\aiosh-rust\aiosh-core)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 8.40s
```
