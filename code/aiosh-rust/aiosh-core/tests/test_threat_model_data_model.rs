//! Unit Tests for Threat Model Data Model (T-02705).

use aiosh_core::threat_model_data_model::*;

#[test]
fn test_threat_category_and_severity() {
    assert_eq!(ThreatCategory::parse_category("spoofing"), Some(ThreatCategory::Spoofing));
    assert_eq!(ThreatCategory::parse_category("tampering"), Some(ThreatCategory::Tampering));
    assert_eq!(ThreatCategory::parse_category("eop"), Some(ThreatCategory::ElevationOfPrivilege));
    assert_eq!(ThreatCategory::parse_category("invalid"), None);

    assert!(ThreatSeverity::Low < ThreatSeverity::Medium);
    assert!(ThreatSeverity::Medium < ThreatSeverity::High);
    assert!(ThreatSeverity::High < ThreatSeverity::Critical);
    assert_eq!(ThreatSeverity::Critical.score(), 4);
    assert_eq!(ThreatSeverity::parse_severity("crit"), Some(ThreatSeverity::Critical));
}

#[test]
fn test_threat_status_state_machine() {
    let mut entry = ThreatEntry::new(
        "THREAT-001",
        "Arbitrary File Read",
        "Relative path traversal in config loader",
        ThreatCategory::InformationDisclosure,
        ThreatSeverity::High,
        "config_loader",
        vec!["CWE-22".into()],
        vec!["Path sanitization".into()],
    ).expect("valid threat entry");

    assert_eq!(entry.status, ThreatStatus::Identified);

    // Valid transition: Identified -> UnderReview
    assert!(entry.transition_to(ThreatStatus::UnderReview).is_ok());
    assert_eq!(entry.status, ThreatStatus::UnderReview);

    // Valid transition: UnderReview -> Mitigated
    assert!(entry.transition_to(ThreatStatus::Mitigated).is_ok());
    assert_eq!(entry.status, ThreatStatus::Mitigated);

    // Valid transition: Mitigated -> Resolved
    assert!(entry.transition_to(ThreatStatus::Resolved).is_ok());
    assert_eq!(entry.status, ThreatStatus::Resolved);

    // Invalid transition: Resolved cannot transition directly to UnderReview
    assert!(entry.transition_to(ThreatStatus::UnderReview).is_err());
}

#[test]
fn test_threat_entry_validation_and_bounds() {
    // Empty ID
    assert!(ThreatEntry::new(
        "", "Title", "Desc", ThreatCategory::Tampering, ThreatSeverity::Low, "comp", vec![], vec![]
    ).is_err());

    // Invalid characters in ID
    assert!(ThreatEntry::new(
        "THREAT/001", "Title", "Desc", ThreatCategory::Tampering, ThreatSeverity::Low, "comp", vec![], vec![]
    ).is_err());

    // Control characters in title
    assert!(ThreatEntry::new(
        "THREAT-002", "Title\x00Bad", "Desc", ThreatCategory::Tampering, ThreatSeverity::Low, "comp", vec![], vec![]
    ).is_err());

    // Title too long
    let long_title = "a".repeat(MAX_THREAT_TITLE_LEN + 1);
    assert!(ThreatEntry::new(
        "THREAT-003", &long_title, "Desc", ThreatCategory::Tampering, ThreatSeverity::Low, "comp", vec![], vec![]
    ).is_err());
}

#[test]
fn test_threat_entry_mutations() {
    let mut entry = ThreatEntry::new(
        "THREAT-004",
        "Audit Log Forgery",
        "Operator terminal ANSI injection",
        ThreatCategory::Repudiation,
        ThreatSeverity::Medium,
        "audit_ring",
        vec!["CWE-150".into()],
        vec![],
    ).expect("valid threat");

    assert!(entry.add_mitigation("Sanitize terminal outputs with U+FFFD").is_ok());
    assert_eq!(entry.mitigations.len(), 1);

    // Adding duplicate mitigation is no-op
    assert!(entry.add_mitigation("Sanitize terminal outputs with U+FFFD").is_ok());
    assert_eq!(entry.mitigations.len(), 1);

    // Adding CWE
    assert!(entry.add_cwe("CWE-116").is_ok());
    assert_eq!(entry.cwe_ids.len(), 2);
}

#[test]
fn test_threat_model_snapshot() {
    let mut snapshot = ThreatModelSnapshot::new("1.0.0");

    let t1 = ThreatEntry::new(
        "THREAT-010", "Denial of Service via Loop", "Resource exhaustion",
        ThreatCategory::DenialOfService, ThreatSeverity::High, "scheduler", vec!["CWE-400".into()], vec![]
    ).unwrap();

    let t2 = ThreatEntry::new(
        "THREAT-011", "Privilege Escalation in Kernel", "Improper capability check",
        ThreatCategory::ElevationOfPrivilege, ThreatSeverity::Critical, "pep_gate", vec!["CWE-250".into()], vec![]
    ).unwrap();

    assert!(snapshot.add_entry(t1).is_ok());
    assert!(snapshot.add_entry(t2).is_ok());

    // Duplicate ID error
    let dup = ThreatEntry::new(
        "THREAT-010", "Duplicate", "Desc",
        ThreatCategory::Tampering, ThreatSeverity::Low, "comp", vec![], vec![]
    ).unwrap();
    assert!(snapshot.add_entry(dup).is_err());

    // Query filters
    assert_eq!(snapshot.filter_by_category(ThreatCategory::DenialOfService).len(), 1);
    assert_eq!(snapshot.filter_by_severity(ThreatSeverity::Critical).len(), 1);
    assert_eq!(snapshot.filter_by_severity(ThreatSeverity::High).len(), 2);
    assert_eq!(snapshot.filter_by_status(ThreatStatus::Identified).len(), 2);
}

#[test]
fn test_threat_model_hardening() {
    let mut entry = ThreatEntry::new(
        "THREAT-HARDEN-1", "Harden Test", "Safe desc",
        ThreatCategory::Tampering, ThreatSeverity::High, "kernel", vec![], vec![]
    ).unwrap();

    // 1. Transition to Mitigated without mitigations is rejected fail-closed
    assert!(entry.transition_to(ThreatStatus::Mitigated).is_err());

    // 2. Add mitigation, then transition succeeds
    assert!(entry.add_mitigation("Apply cryptographically signed payload").is_ok());
    assert!(entry.transition_to(ThreatStatus::Mitigated).is_ok());

    // 3. Secret pattern in mitigation rejected
    assert!(entry.add_mitigation("Key: -----BEGIN PRIVATE KEY----- secret").is_err());

    // 4. Secret pattern in description rejected
    assert!(ThreatEntry::new(
        "THREAT-HARDEN-2", "Key leak", "Desc with -----BEGIN RSA PRIVATE KEY-----",
        ThreatCategory::InformationDisclosure, ThreatSeverity::Critical, "store", vec![], vec![]
    ).is_err());
}
