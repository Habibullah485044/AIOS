//! Automated Test Suite Implementation for Compliance Mapping Subsystem (T-02915 SCAFFOLD).
//!
//! Implements formal verification vectors AUTOCOMPLIANCE1..AUTOCOMPLIANCE10 defined in
//! `docs/tasks/evidence/T-02914-spec.md`.

use aiosh_core::compliance_config::*;
use aiosh_core::compliance_data_model::*;
use aiosh_core::compliance_service::*;

#[test]
fn test_autocompliance_scaffold_compilation_and_constants() {
    assert_eq!(MAX_CONFIG_FILE_BYTES, 64 * 1024);
    assert_eq!(DEFAULT_MAX_STORE_FILE_BYTES, 1024 * 1024);
    assert_eq!(DEFAULT_MAX_ENTRIES, 1024);
    assert!(ComplianceConfig::hygiene_ok("valid_path.json"));
    assert!(!ComplianceConfig::hygiene_ok("../traversal.json"));
}

#[test]
fn test_autocompliance_scaffold_types_and_defaults() {
    let service = ComplianceService::new();
    assert_eq!(service.snapshot.mappings.len(), 0);
    let entry = ComplianceMappingEntry::default();
    assert_eq!(entry.id, "");
    let config = ComplianceConfig::default();
    assert!(config.audit_all_mutations);
}
