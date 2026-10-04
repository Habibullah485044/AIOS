# Specification & Operator Guide: Compliance Mapping Data Model (SPEC-COMPLIANCE-DATA-MODEL)

- **Status**: IMPLEMENTED & VERIFIED
- **Date**: 2026-10-04
- **Scope**: Data structures, standards taxonomy, bounds enforcement, and lifecycle state machines for Compliance Mapping.

## 1. Overview
The Compliance Mapping data model provides formal representations mapping regulatory standards (NIST SP 800-53 Rev 5, SOC 2 Type II, ISO/IEC 27001, CIS Controls v8, HIPAA, PCI DSS) to AIOS technical enforcement mechanisms (PEP gates, capability tokens, audit rings, and constitution rules).

## 2. API Usage & Code Examples

### 2.1 Instantiating Controls and Mappings

```rust
use aiosh_core::compliance_data_model::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Define a regulatory compliance control
    let control = ComplianceControl::new(
        "AC-3",
        ComplianceFramework::NistSp80053Rev5,
        "Access Enforcement",
        "Enforces approved authorizations for logical access to information.",
        "Access Control",
    )?;

    // 2. Map control to an internal AIOS PEP gate
    let mapping = ComplianceMappingEntry::new(
        "MAP-NIST-AC3-PEP",
        &control.id,
        control.framework,
        SubstrateTargetType::PepGate,
        "pep_enforce_gate",
        vec!["T-EOP-001".to_string()],
        ComplianceStatus::Compliant,
        "Enforced via AIOS Security Kernel PEP gate validation on all syscalls.",
        vec!["access_control".to_string(), "kernel".to_string()],
    )?;

    // 3. Manage snapshots and queries
    let mut catalog = ComplianceCatalogSnapshot::new("1.0.0");
    catalog.add_mapping(mapping)?;

    let nist_controls = catalog.find_by_framework(ComplianceFramework::NistSp80053Rev5);
    println!("NIST controls mapped: {}", nist_controls.len());
    println!("Compliance ratio: {:.2}%", catalog.compliance_ratio() * 100.0);

    Ok(())
}
```

### 2.2 Using Canonical Baseline

```rust
use aiosh_core::compliance_data_model::{ComplianceCatalogSnapshot, ComplianceFramework};

let baseline = ComplianceCatalogSnapshot::canonical_baseline();
assert!(!baseline.mappings.is_empty());

let soc2_entries = baseline.find_by_framework(ComplianceFramework::Soc2Type2);
println!("SOC 2 entries: {}", soc2_entries.len());
```

## 3. Invariants Enforced
- `COMPLY1`: Clean alphanumeric ID syntax (`[a-zA-Z0-9_.-]`), control characters prohibited.
- `COMPLY2`: Non-empty substrate target references.
- `COMPLY3`: Status transitions to `Compliant` validate mitigation descriptions.
- `COMPLY4`: Bounded string lengths and collection sizes (IDs <= 64, titles <= 128, descriptions <= 2048, tags <= 16, threats <= 16, entries <= 1024).
- `COMPLY5`: Pre-seeded canonical baseline available out of the box.

## 4. Constraints & Known Limitations
- Maximum catalog size per snapshot is 1024 mappings (`MAX_COMPLIANCE_ENTRIES_CAPACITY`).
- Maximum number of threat tags or tag strings per entry is 16 (`MAX_TAGS_COUNT`, `MAX_THREAT_IDS_COUNT`).
- Transitioning to `Compliant` requires non-empty technical mitigation details.

## 5. Evidence Artifacts
- Research: [T-02801 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02801-data-model-research.md)
- Specification: [T-02802 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02802-data-model-specification.md)
- Scaffold: [T-02803 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02803-data-model-scaffold.md)
- Implementation: [T-02804 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02804-data-model-implementation.md)
- Unit Tests: [T-02805 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02805-data-model-unit-test.md)
- Integration: [T-02806 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02806-data-model-integration.md)
- Security Review: [T-02807 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02807-data-model-security-review.md)
- Hardening: [T-02808 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02808-data-model-hardening.md)
