# T-02719: Threat Model Maintenance Core Service Documentation

- **Task**: `T-02719`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / core service
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Documentation Scope
Synchronized architectural and API specifications for `ThreatModelService` in `docs/SPEC-THREAT-MODEL-SERVICE.md`:
1. Updated specification status to `IMPLEMENTED & VERIFIED`.
2. Documented full set of invariants (`THREATSVC1` to `THREATSVC6`) including capacity bounds, store size bounds, atomic staged temporary write sequencing (`.{fname}.tmp.{pid}.{nanos}`), symlink prohibition, and zero-disclosure rules.
3. Detailed the public service API methods (`new`, `with_canonical_threats`, `load_from_path`, `save_to_path`, `register_threat`, `get_threat`, `list_threats`, `update_status`, `attach_mitigation`, `assess_risk`).
4. Documented the 7 canonical STRIDE baseline threats pre-populated by the core service.
5. Cataloged error codes and operational constraints.
