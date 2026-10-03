# Specification: Threat Model Maintenance Data Model (SPEC-THREAT-MODEL-DATA-MODEL)

- **Status**: SPECIFIED
- **Date**: 2026-10-03
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Maintenance Data Model
- **Binding**: ADR-0036 §A-1

## 1. Overview
The Threat Model Maintenance Data Model (`THREAT1`..`THREAT5`) establishes the domain primitives, STRIDE categories, risk scoring tiers, and lifecycle transition rules for the AIOS security architecture threat catalog.

## 2. Invariants & Rulesets

| Invariant | Name | Description |
|---|---|---|
| `THREAT1` | **Valid Identifier Law** | Threat IDs must be non-empty, alphanumeric with hyphens/underscores (`^[A-Za-z0-9_-]+$`), and capped at `MAX_THREAT_ID_LEN` (64 bytes). |
| `THREAT2` | **Severity Precedence** | Discrete risk severity tiers ordered by impact: `Low` (1) < `Medium` (2) < `High` (3) < `Critical` (4). |
| `THREAT3` | **Cardinality & Buffer Ceilings** | Titles capped at 128 bytes, descriptions at 2048 bytes, mitigations at 2048 bytes, and CWE associations at 16 entries. Control characters are rejected fail-closed. |
| `THREAT4` | **Zero-Disclosure Principle** | Threat descriptions and mitigation specifications must never store plaintext secrets, API keys, or memory addresses. |
| `THREAT5` | **State Transition Integrity** | Lifecycle states follow deterministic transitions (`Identified` -> `UnderReview` -> `Mitigated` / `Accepted` -> `Resolved`), with regressions requiring explicit reopen reasons. |

## 3. Data Structures

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    Spoofing,
    Tampering,
    Repudiation,
    InformationDisclosure,
    DenialOfService,
    ElevationOfPrivilege,
    SupplyChainRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatStatus {
    Identified,
    UnderReview,
    Mitigated,
    Accepted,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatEntry {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: ThreatCategory,
    pub severity: ThreatSeverity,
    pub status: ThreatStatus,
    pub component: String,
    pub cwe_ids: Vec<String>,
    pub mitigations: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatModelSnapshot {
    pub version: String,
    pub threats: Vec<ThreatEntry>,
    pub generated_at: String,
}
```

## 4. Error Constants
- `THREAT_ERR_INVALID_ID`: "THREAT_ERR_INVALID_ID"
- `THREAT_ERR_INVALID_TITLE`: "THREAT_ERR_INVALID_TITLE"
- `THREAT_ERR_BOUNDS_EXCEEDED`: "THREAT_ERR_BOUNDS_EXCEEDED"
- `THREAT_ERR_INVALID_TRANSITION`: "THREAT_ERR_INVALID_TRANSITION"
- `THREAT_ERR_CONTROL_CHARS`: "THREAT_ERR_CONTROL_CHARS"
