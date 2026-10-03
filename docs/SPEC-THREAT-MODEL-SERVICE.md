# Specification: Threat Model Maintenance Core Service (SPEC-THREAT-MODEL-SERVICE)

- **Status**: IMPLEMENTED & VERIFIED
- **Date**: 2026-10-03
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Maintenance Core Service
- **Binding**: ADR-0036 §B-1

## 1. Overview
The Threat Model Maintenance Core Service (`ThreatModelService`) provides the runtime engine for managing, evaluating, persisting, and auditing the system threat catalog across all STRIDE threat boundaries.

## 2. Invariants & Rulesets

| Invariant | Name | Description |
|---|---|---|
| `THREATSVC1` | **Capacity Bound** | The threat catalog is capped at `MAX_THREAT_ENTRIES_CAPACITY = 512` entries. |
| `THREATSVC2` | **Store Size Bound** | Stored catalog files must not exceed `MAX_THREAT_MODEL_STORE_SIZE = 1 MiB` (1,048,576 bytes). |
| `THREATSVC3` | **Atomic Persistence** | Mutations write to `.{fname}.tmp.{pid}.{nanos}` and execute an atomic rename (`std::fs::rename`) with fail-closed cleanup. |
| `THREATSVC4` | **Path Traversal Hygiene** | Target file paths reject relative climbing (`..`), UNC paths (`\\\\`, `//`), control characters, non-json extensions, and path depths > 16. |
| `THREATSVC5` | **Symlink Protection** | Symlinks and Windows reparse points are forbidden for threat model storage files (`fs::symlink_metadata`). |
| `THREATSVC6` | **Zero-Disclosure Principle** | No secret credentials, API keys, or private key blocks are allowed in catalog storage or risk reports. |

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
    pub snapshot: ThreatModelSnapshot,
}
```

## 4. API Specification
- `ThreatModelService::new() -> Self`: Initialize empty threat catalog snapshot.
- `ThreatModelService::with_canonical_threats() -> Self`: Initialize catalog pre-populated with 7 canonical STRIDE baseline threats.
- `ThreatModelService::load_from_path(path: &Path) -> Result<Self, String>`: Safely load and validate threat model from disk.
- `ThreatModelService::save_to_path(&self, path: &Path) -> Result<(), String>`: Safely and atomically persist threat model snapshot to disk.
- `ThreatModelService::register_threat(&mut self, entry: ThreatEntry) -> Result<(), String>`: Register a new threat with capacity boundary validation.
- `ThreatModelService::get_threat(&self, id: &str) -> Option<&ThreatEntry>`: Retrieve threat entry by ID.
- `ThreatModelService::list_threats(&self) -> &[ThreatEntry]`: List all registered threats.
- `ThreatModelService::update_status(&mut self, id: &str, new_status: ThreatStatus) -> Result<(), String>`: Transition threat lifecycle status.
- `ThreatModelService::attach_mitigation(&mut self, id: &str, mitigation: &str) -> Result<(), String>`: Attach mitigation to threat entry.
- `ThreatModelService::assess_risk(&self) -> ThreatRiskAssessment`: Generate composite risk scoring and metrics.

## 5. Canonical Threats Baseline
1. `THREAT-SPOOF-01` (Spoofing / Critical): Unauthenticated Agent Token Impersonation.
2. `THREAT-TAMP-01` (Tampering / High): Task Ledger State Tampering.
3. `THREAT-REPU-01` (Repudiation / High): Audit Event Dropping & Disavowal.
4. `THREAT-INFO-01` (Information Disclosure / Critical): Plaintext Vault Credential Leakage.
5. `THREAT-DOS-01` (Denial of Service / Medium): Resource Exhaustion via Unbounded Subprocess Spawning.
6. `THREAT-EOP-01` (Elevation of Privilege / Critical): Userspace Escalation to System Kernel Privilege.
7. `THREAT-SUPPLY-01` (Supply Chain / High): Compromised Base Container Image.

## 6. Error Constants
- `THREATSVC_ERR_NOT_FOUND`: "THREATSVC_ERR_NOT_FOUND"
- `THREATSVC_ERR_CAPACITY_EXCEEDED`: "THREATSVC_ERR_CAPACITY_EXCEEDED"
- `THREATSVC_ERR_FILE_SIZE`: "THREATSVC_ERR_FILE_SIZE"
- `THREATSVC_ERR_PATH_TRAVERSAL`: "THREATSVC_ERR_PATH_TRAVERSAL"
- `THREATSVC_ERR_IO`: "THREATSVC_ERR_IO"
- `THREATSVC_ERR_PARSE`: "THREATSVC_ERR_PARSE"
