# Scaffold Evidence: Threat Model Security Policy (T-02763)

## Overview
Creates the module skeleton and interfaces for the Threat Model Security Policy subsystem (`T-02761`..`T-02770`) in `code/aiosh-rust/aiosh-core/src/threat_model_policy.rs` and re-exports it in `aiosh-core/src/lib.rs`.

## Interfaces Scaffolded
- `ThreatPolicyMode`: Enum (`Enforcing`, `Permissive`, `Disabled`) with Default.
- `ThreatPolicyVerdict`: Enum (`Permit`, `PermitWithWarning`, `Deny`).
- `ThreatModelSecurityPolicy`: Struct with defaults and fields:
  - `version: String`
  - `mode: ThreatPolicyMode`
  - `require_cwe_mapping: bool`
  - `disallow_unmitigated_critical: bool`
  - `prohibited_categories: Vec<ThreatCategory>`
  - `max_catalog_threats: usize`
  - `max_critical_threats: usize`
  - `allow_canonical_override: bool`
- Invariant & Evaluation Signatures:
  - `validate(&self) -> Result<(), String>`
  - `evaluate_registration(&self, entry: &ThreatEntry) -> ThreatPolicyVerdict`
  - `evaluate_transition(&self, entry: &ThreatEntry, next_status: ThreatStatus) -> ThreatPolicyVerdict`
  - `evaluate_mitigation(&self, entry: &ThreatEntry, mitigation: &str) -> ThreatPolicyVerdict`
  - `evaluate_assessment(&self, assessment: &ThreatRiskAssessment) -> ThreatPolicyVerdict`
  - `load_from_path<P: AsRef<Path>>(path: P) -> Result<Self, String>`
  - `save_to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), String>`

## Build Verification
- `cargo check -p aiosh-core` passed cleanly with 0 errors and 0 warnings.
