# T-02713: Threat Model Maintenance Core Service Scaffold

- **Task**: `T-02713`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / core service
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Scaffold Scope
Scaffolded the Threat Model Core Service subsystem:
1. Created `code/aiosh-rust/aiosh-core/src/threat_model_service.rs`.
2. Declared core constants:
   - `DEFAULT_THREAT_MODEL_PATH = "docs/threat_model.json"`.
   - `MAX_THREAT_ENTRIES_CAPACITY = 512`.
   - `MAX_THREAT_MODEL_STORE_SIZE = 1 MiB`.
3. Declared error codes (`THREATSVC_ERR_*`).
4. Declared `ThreatRiskAssessment` and `ThreatModelService` with path validation helper.
5. Registered `pub mod threat_model_service;` in `code/aiosh-rust/aiosh-core/src/lib.rs`.
6. Verified compilation via `cargo check -p aiosh-core`.

## 2. Compiler Output
```
    Checking aiosh-core v0.1.0 (C:\Users\OBSESSION\Desktop\AIOS_MERGED\code\aiosh-rust\aiosh-core)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 15s
```
