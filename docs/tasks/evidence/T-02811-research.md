# Research Document: Compliance Mapping Core Service (T-02811)

- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Compliance Mapping / core service
- **Focus**: Runtime Catalog Management, Atomic Store Persistence, Assessment Generation, and PEP Policy Hooks
- **Bindings**: ADR-0035 §C-2, ADR-0036 §S-3

## 1. Executive Summary
The Compliance Mapping Core Service (`ComplianceService`) operates as the runtime controller and assessment engine for the AIOS compliance catalog. It bridges static control requirements with live PEP fabric gates, audit logs, and threat models. It provides thread-safe runtime state management, atomic file persistence, framework-scoped posture assessment, and compliance policy verification.

## 2. Invariants & Core Architecture

| Invariant | Name | Description |
|:---|:---|:---|
| `COMPLYSVC1` | **Side-Effect-Free Assessment** | Assessments and queries are strictly read-only and generate deterministic reports without mutating store state. |
| `COMPLYSVC2` | **Crash-Consistent Atomic Persistence** | All writes to `compliance_map.json` execute via PID/nanosecond-tagged temporary files (`.tmp.{pid}.{nanos}`) and atomic renames. |
| `COMPLYSVC3` | **Strict Path & Link Sanitization (CWE-22/59)** | Rejection of directory climbing (`..`), UNC network roots, control characters, and symbolic links. |
| `COMPLYSVC4` | **Resource & Memory Bounds (CWE-400)** | Storage files capped at 1 MiB (`MAX_COMPLIANCE_STORE_SIZE`); in-memory catalog capped at 1024 entries. |
| `COMPLYSVC5` | **Quantitative Compliance Auditing** | Assessment output computes framework-specific and overall compliance coverage percentages, identifying gaps and non-compliant controls. |

## 3. Persistence & Service Contracts
- Default store path: `docs/compliance_map.json`.
- Methods:
  - `load_from_path(path: &Path) -> Result<Self, String>`
  - `save_to_path(&self, path: &Path) -> Result<(), String>`
  - `register_mapping(&mut self, entry: ComplianceMappingEntry) -> Result<(), String>`
  - `assess_compliance(&self, framework: Option<ComplianceFramework>) -> ComplianceAssessmentReport`
  - `verify_pep_coverage(&self, gate_id: &str) -> bool`

## 4. Next Steps
- `T-02812`: Author formal specification `SPEC-COMPLIANCE-SERVICE.md`.
- `T-02813`: Scaffold `compliance_service.rs` in `aiosh-core`.
