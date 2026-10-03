# Specification: Threat Model Maintenance Core Service (SPEC-THREAT-MODEL-SERVICE)

- **Status**: SPECIFIED
- **Date**: 2026-10-03
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Maintenance Core Service
- **Binding**: ADR-0036 §B-1

## 1. Overview
The Threat Model Maintenance Core Service (`ThreatModelService`) provides the runtime engine for managing, evaluating, persisting, and auditing the system threat catalog.

## 2. Invariants & Rulesets

| Invariant | Name | Description |
|---|---|---|
| `THREATSVC1` | **Capacity Bound** | The threat catalog is capped at `MAX_THREAT_ENTRIES_CAPACITY = 512` entries. |
| `THREATSVC2` | **Store Size Bound** | Stored catalog files must not exceed `MAX_THREAT_MODEL_STORE_SIZE = 1 MiB` (1,048,576 bytes). |
| `THREATSVC3` | **Atomic Persistence** | Mutations write to `<path>.tmp` and execute an atomic rename (`std::fs::rename`). |
| `THREATSVC4` | **Path Traversal Hygiene** | Target file paths reject relative climbing (`..`), UNC paths (`\\\\`, `//`), and control characters. |
| `THREATSVC5` | **Zero-Disclosure Principle** | No secret credentials, API keys, or private key blocks are allowed in catalog storage or risk reports. |

## 3. Data Structures

```rust
pub const DEFAULT_THREAT_MODEL_PATH: &str = "docs/threat_model.json";
pub const MAX_THREAT_ENTRIES_CAPACITY: usize = 512;
pub const MAX_THREAT_MODEL_STORE_SIZE: u64 = 1024 * 1024; // 1 MiB

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatRiskAssessment {
    pub total_threats: usize,
    pub identified_count: usize,
    pub under_review_count: usize,
    pub mitigated_count: usize,
    pub accepted_count: usize,
    pub resolved_count: usize,
    pub critical_unmitigated_count: usize,
    pub overall_risk_score: u32,
    pub evaluated_at: String,
}

pub struct ThreatModelService {
    snapshot: ThreatModelSnapshot,
}
```

## 4. API Specification
- `ThreatModelService::new() -> Self`
- `ThreatModelService::load_from_path(path: &Path) -> Result<Self, String>`
- `ThreatModelService::save_to_path(&self, path: &Path) -> Result<(), String>`
- `ThreatModelService::register_threat(&mut self, entry: ThreatEntry) -> Result<(), String>`
- `ThreatModelService::get_threat(&self, id: &str) -> Option<&ThreatEntry>`
- `ThreatModelService::list_threats(&self) -> &[ThreatEntry]`
- `ThreatModelService::update_status(&mut self, id: &str, new_status: ThreatStatus) -> Result<(), String>`
- `ThreatModelService::attach_mitigation(&mut self, id: &str, mitigation: &str) -> Result<(), String>`
- `ThreatModelService::assess_risk(&self) -> ThreatRiskAssessment`

## 5. Error Constants
- `THREATSVC_ERR_NOT_FOUND`: "THREATSVC_ERR_NOT_FOUND"
- `THREATSVC_ERR_CAPACITY_EXCEEDED`: "THREATSVC_ERR_CAPACITY_EXCEEDED"
- `THREATSVC_ERR_FILE_SIZE`: "THREATSVC_ERR_FILE_SIZE"
- `THREATSVC_ERR_PATH_TRAVERSAL`: "THREATSVC_ERR_PATH_TRAVERSAL"
- `THREATSVC_ERR_IO`: "THREATSVC_ERR_IO"
- `THREATSVC_ERR_PARSE`: "THREATSVC_ERR_PARSE"
