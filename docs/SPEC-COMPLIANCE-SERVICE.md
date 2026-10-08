# Specification & Operator Guide: Compliance Mapping Core Service (SPEC-COMPLIANCE-SERVICE)

- **Status**: IMPLEMENTED & VERIFIED
- **Date**: 2026-10-04
- **Scope**: Runtime service engine, persistence, assessment reporting, and PEP integration for Compliance Mapping.

## 1. Overview
The Compliance Mapping Core Service (`ComplianceService`) maintains the live repository of mapped compliance controls against AIOS security primitives (PEP gates, capabilities, audit rings, and threat mitigations). It enables automated auditing against regulatory standards (NIST SP 800-53, SOC 2, ISO 27001, CIS) and verifies PEP gate compliance coverage.

## 2. API Usage & Code Examples

### 2.1 Managing Mappings & Persistence

```rust
use std::path::Path;
use aiosh_core::compliance_data_model::*;
use aiosh_core::compliance_service::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store_path = Path::new("docs/compliance_map.json");

    // 1. Initialize service with canonical standard baseline
    let mut service = ComplianceService::with_canonical_baseline();

    // 2. Register an additional control mapping
    let new_mapping = ComplianceMappingEntry::new(
        "MAP-ISO-A8-ACCESS",
        "A.8.2",
        ComplianceFramework::Iso27001,
        SubstrateTargetType::PepGate,
        "privileged_execution_gate",
        vec!["T-EOP-001".to_string()],
        ComplianceStatus::Compliant,
        "Privileged access governed by mandatory capability token verification.",
        vec!["access_control".to_string()],
    )?;
    service.register_mapping(new_mapping)?;

    // 3. Persist atomically
    service.save_to_path(store_path)?;

    // 4. Reload from disk
    let reloaded = ComplianceService::load_from_path(store_path)?;
    println!("Loaded {} compliance mappings.", reloaded.snapshot.mappings.len());

    Ok(())
}
```

### 2.2 Framework Assessment & PEP Gate Coverage

```rust
use aiosh_core::compliance_data_model::ComplianceFramework;
use aiosh_core::compliance_service::ComplianceService;

let service = ComplianceService::with_canonical_baseline();

// Generate NIST SP 800-53 posture report
let nist_report = service.assess_framework(Some(ComplianceFramework::NistSp80053Rev5));
println!("NIST Compliance: {:.1}% ({} compliant, {} gaps)",
    nist_report.compliance_percentage,
    nist_report.compliant_count,
    nist_report.gap_control_ids.len());

// Check if critical PEP gates are mapped and compliant
let is_covered = service.verify_pep_coverage("pep_enforce_gate");
assert!(is_covered);

let missing = service.uncovered_pep_gates(&["pep_enforce_gate", "custom_network_gate"]);
println!("Uncovered gates: {:?}", missing);
```

## 3. Invariants & Security Guarantees
- `COMPLYSVC1`: Non-destructive queries and assessment generation.
- `COMPLYSVC2`: Crash-consistent atomic writes using PID/nanosecond-tagged temporary files (`.tmp.{pid}.{nanos}`) with guaranteed cleanup.
- `COMPLYSVC3`: Path traversal (CWE-22) and symlink (CWE-59) rejection.
- `COMPLYSVC4`: Hard 1 MiB store file size cap (`MAX_COMPLIANCE_STORE_SIZE`) enforced on **load** (bounded read, TOCTOU-safe) and on **save** (payload refused before any file handle is created — a store that could never be re-loaded is never written; both substrates, T-02900).
- `COMPLYSVC5`: Quantitative compliance assessment reporting.

## 4. Constraints & Known Limitations
- Storage file size cannot exceed 1 MiB (load **and** save; the write path refuses oversized payloads up front).
- Storage file paths must have `.json` extension.
- File system depth cannot exceed 16 path components.
- The MCP tool surface (`aios_compliance`) is Python-only; the Rust side is CLI-only (`aiosh compliance`). Parity is through the shared canonical-JSON store, integration-proven (T-02898).
- Every status transition is legal (Rust `_ => true` fallback, mirrored and test-pinned); only the transition **to `compliant`** carries a guard (mitigation summary or explicit reason required).

## 5. Evidence Artifacts
- Research: [T-02811 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02811-core-service-research.md)
- Specification: [T-02812 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02812-core-service-specification.md)
- Scaffold: [T-02813 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02813-core-service-scaffold.md)
- Implementation: [T-02814 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02814-core-service-implementation.md)
- Unit Tests: [T-02815 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02815-core-service-unit-test.md)
- Integration: [T-02816 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02816-core-service-integration.md)
- Security Review: [T-02817 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02817-core-service-security-review.md)
- Hardening: [T-02818 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02818-core-service-hardening.md)
- MCP/API surface — spec: [T-02894 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02894-spec.md)
- MCP/API surface — integration: [T-02898 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02898-mcp-api-surface-integration.md)
- MCP/API surface — security review: [T-02899 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02899-mcp-api-surface-security-review.md)
- MCP/API surface — hardening: [T-02900 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02900-mcp-api-surface-hardening.md)
- MCP/API surface — documentation: [T-02901 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02901-mcp-api-surface-documentation.md)
