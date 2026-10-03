# T-02712: Threat Model Maintenance Core Service Specification

- **Task**: `T-02712`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / core service
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Specification Delivered
Authored `docs/SPEC-THREAT-MODEL-SERVICE.md` specifying:
1. Invariants `THREATSVC1`..`THREATSVC5` covering capacity limits, store file size, atomic rename persistence, path hygiene, and zero disclosure.
2. `ThreatRiskAssessment`: Metrics structure capturing total threats, status breakdowns, critical unmitigated counts, and overall risk scores.
3. `ThreatModelService`: Core contract providing catalog lifecycle methods (`register_threat`, `get_threat`, `list_threats`, `update_status`, `attach_mitigation`, `assess_risk`, `load_from_path`, `save_to_path`).
4. Error constants and boundary thresholds.
