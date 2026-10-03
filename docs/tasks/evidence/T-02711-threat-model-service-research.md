# T-02711: Threat Model Maintenance Core Service Research

- **Task**: `T-02711`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / core service
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Research Objectives & Service Architecture
The Threat Model Core Service (`ThreatModelService`) provides the runtime engine for managing, evaluating, persisting, and auditing the system threat catalog:
1. **Authoritative Persistence & Storage Invariants**:
   - Default catalog path: `docs/threat_model.json`.
   - File size bound: `MAX_THREAT_MODEL_STORE_SIZE = 1 MiB` (1,048,576 bytes).
   - Capacity ceiling: `MAX_THREAT_ENTRIES_CAPACITY = 512` threats.
   - Staged atomic write: Writes to `<path>.tmp` followed by atomic filesystem replacement (`std::fs::rename`).
2. **Catalog Lifecycle Operations**:
   - `register_threat(entry)`: Enforces uniqueness, capacity, and field validation.
   - `get_threat(id)`: O(1) or index lookup by threat identifier.
   - `list_threats(filter)`: Categorical and severity filtered queries.
   - `update_threat_status(id, new_status)`: Enforces state machine transitions.
   - `attach_mitigation(id, mitigation)`: Appends verified security controls.
3. **Risk Posture & Assessment Engine**:
   - `assess_risk()` computes aggregated security metrics:
     - Total threats tracked.
     - Active vs. mitigated vs. accepted threats.
     - Critical unmitigated threat count.
     - Overall risk score index.
4. **Security & Zero-Disclosure Invariants**:
   - Strict path traversal (`..`), UNC paths, and control character refusal.
   - Zero-disclosure validation refusing secret or private key fragments.

## 2. Research Conclusion
The service will be implemented in `code/aiosh-rust/aiosh-core/src/threat_model_service.rs` backed by `ThreatModelSnapshot` and `ThreatEntry`.
