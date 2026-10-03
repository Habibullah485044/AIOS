//! Integration Tests for Threat Model Data Model (T-02706).

use std::fs;
use aiosh_core::*;

#[test]
fn test_threat_model_json_serialization_roundtrip() {
    let mut snapshot = ThreatModelSnapshot::new("1.0.0");

    let entry = ThreatEntry::new(
        "THREAT-STRIDE-001",
        "Privilege Boundary Breach via PEP Bypass",
        "Adversary submits unverified token to gain kernel execution rights",
        ThreatCategory::ElevationOfPrivilege,
        ThreatSeverity::Critical,
        "pep_fabric",
        vec!["CWE-250".into(), "CWE-285".into()],
        vec!["Enforce cryptographic verification of PEP grant token".into()],
    ).expect("valid threat entry");

    snapshot.add_entry(entry).expect("add entry to snapshot");

    // Serialize to JSON string
    let json_str = serde_json::to_string_pretty(&snapshot).expect("serialize snapshot");
    assert!(json_str.contains("THREAT-STRIDE-001"));
    assert!(json_str.contains("elevation_of_privilege"));
    assert!(json_str.contains("critical"));

    // Deserialize back
    let roundtrip: ThreatModelSnapshot = serde_json::from_str(&json_str).expect("deserialize snapshot");
    assert_eq!(roundtrip.version, "1.0.0");
    assert_eq!(roundtrip.threats.len(), 1);

    let retrieved = roundtrip.get_entry("THREAT-STRIDE-001").expect("entry retrieved");
    assert_eq!(retrieved.severity, ThreatSeverity::Critical);
    assert_eq!(retrieved.status, ThreatStatus::Identified);
    assert_eq!(retrieved.cwe_ids.len(), 2);
    assert_eq!(retrieved.mitigations.len(), 1);
}

#[test]
fn test_threat_model_disk_persistence_integration() {
    let tmp_dir = std::env::temp_dir().join("test_threat_model_disk_integration");
    let _ = fs::create_dir_all(&tmp_dir);
    let snapshot_file = tmp_dir.join("threat_model.json");

    let mut snapshot = ThreatModelSnapshot::new("2026.1");
    let t1 = ThreatEntry::new(
        "THREAT-DOS-01",
        "Audit Ring Buffer Exhaustion",
        "Flooding unauthenticated events overflows log ring",
        ThreatCategory::DenialOfService,
        ThreatSeverity::High,
        "audit_ring",
        vec!["CWE-400".into()],
        vec!["Fixed size memory ring buffer with overwrite policy".into()],
    ).unwrap();
    snapshot.add_entry(t1).unwrap();

    let json = serde_json::to_string_pretty(&snapshot).unwrap();
    fs::write(&snapshot_file, json).unwrap();

    // Reload from disk
    let content = fs::read_to_string(&snapshot_file).unwrap();
    let loaded: ThreatModelSnapshot = serde_json::from_str(&content).unwrap();
    assert_eq!(loaded.threats.len(), 1);
    assert_eq!(loaded.threats[0].id, "THREAT-DOS-01");

    let _ = fs::remove_dir_all(&tmp_dir);
}
