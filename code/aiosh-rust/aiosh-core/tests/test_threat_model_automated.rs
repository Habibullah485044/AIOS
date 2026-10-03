//! Automated Test Suite Implementation for Threat Model Maintenance Subsystem (T-02751..T-02760).
//!
//! Implements formal verification vectors AUTOTHREAT1..AUTOTHREAT10 defined in
//! `docs/SPEC-THREAT-MODEL-AUTOMATED-TESTS.md`.

use std::sync::{Arc, Mutex};
use std::thread;
use tempfile::tempdir;

use aiosh_core::threat_model_data_model::*;
use aiosh_core::threat_model_service::*;

/// AUTOTHREAT1: Full Threat Lifecycle & Invariant Transitions
#[test]
fn test_autothreat1_lifecycle_and_transitions() {
    let mut catalog = ThreatModelService::new();
    let entry = ThreatEntry::new(
        "THREAT-AUTO-1",
        "Unauthorized Process Execution",
        "Non-root process escalates privileges",
        ThreatCategory::ElevationOfPrivilege,
        ThreatSeverity::High,
        "kernel.pep",
        vec!["CWE-250".into()],
        vec![],
    ).expect("Valid threat entry creation");

    assert!(catalog.register_threat(entry).is_ok());

    let loaded = catalog.get_threat("THREAT-AUTO-1").expect("Threat should exist");
    assert_eq!(loaded.status, ThreatStatus::Identified);

    // 1. Valid transition: Identified -> UnderReview
    assert!(catalog.update_status("THREAT-AUTO-1", ThreatStatus::UnderReview).is_ok());
    assert_eq!(catalog.get_threat("THREAT-AUTO-1").unwrap().status, ThreatStatus::UnderReview);

    // 2. Invalid transition: UnderReview -> Mitigated without mitigation fails
    assert!(catalog.update_status("THREAT-AUTO-1", ThreatStatus::Mitigated).is_err());

    // 3. Attach mitigation and advance to Mitigated
    assert!(catalog.attach_mitigation("THREAT-AUTO-1", "Apply seccomp-bpf privilege filter").is_ok());
    assert!(catalog.update_status("THREAT-AUTO-1", ThreatStatus::Mitigated).is_ok());
    assert_eq!(catalog.get_threat("THREAT-AUTO-1").unwrap().status, ThreatStatus::Mitigated);

    // 4. Advance from Mitigated to Resolved
    assert!(catalog.update_status("THREAT-AUTO-1", ThreatStatus::Resolved).is_ok());
    assert_eq!(catalog.get_threat("THREAT-AUTO-1").unwrap().status, ThreatStatus::Resolved);

    // 5. Test UnderReview -> Accepted path on a second threat
    let entry2 = ThreatEntry::new(
        "THREAT-AUTO-2",
        "Legacy Protocol Accepted Risk",
        "Legacy protocol allowed on internal network",
        ThreatCategory::InformationDisclosure,
        ThreatSeverity::Low,
        "legacy.net",
        vec![],
        vec![],
    ).unwrap();
    catalog.register_threat(entry2).unwrap();
    assert!(catalog.update_status("THREAT-AUTO-2", ThreatStatus::UnderReview).is_ok());
    assert!(catalog.update_status("THREAT-AUTO-2", ThreatStatus::Accepted).is_ok());
    assert_eq!(catalog.get_threat("THREAT-AUTO-2").unwrap().status, ThreatStatus::Accepted);

    // 6. Nonexistent threat transition fails with NOT_FOUND
    let err = catalog.update_status("NONEXISTENT", ThreatStatus::Mitigated).unwrap_err();
    assert!(err.contains(THREATSVC_ERR_NOT_FOUND));
}

/// AUTOTHREAT2: STRIDE Taxonomy Classification & Severity Matrix
#[test]
fn test_autothreat2_stride_matrix() {
    let mut catalog = ThreatModelService::new();
    let categories = [
        ThreatCategory::Spoofing,
        ThreatCategory::Tampering,
        ThreatCategory::Repudiation,
        ThreatCategory::InformationDisclosure,
        ThreatCategory::DenialOfService,
        ThreatCategory::ElevationOfPrivilege,
        ThreatCategory::SupplyChainRisk,
    ];

    for (idx, cat) in categories.iter().enumerate() {
        let entry = ThreatEntry::new(
            &format!("STRIDE-{}", idx),
            &format!("Test Threat for {:?}", cat),
            "Description of threat",
            *cat,
            ThreatSeverity::Medium,
            "test.component",
            vec!["CWE-20".into()],
            vec![],
        ).expect("Valid entry");
        assert!(catalog.register_threat(entry).is_ok());
    }

    assert_eq!(catalog.list_threats().len(), 7);

    // Verify parsing of all category string forms
    assert_eq!(ThreatCategory::parse_category("spoofing"), Some(ThreatCategory::Spoofing));
    assert_eq!(ThreatCategory::parse_category("tampering"), Some(ThreatCategory::Tampering));
    assert_eq!(ThreatCategory::parse_category("repudiation"), Some(ThreatCategory::Repudiation));
    assert_eq!(ThreatCategory::parse_category("information_disclosure"), Some(ThreatCategory::InformationDisclosure));
    assert_eq!(ThreatCategory::parse_category("denial_of_service"), Some(ThreatCategory::DenialOfService));
    assert_eq!(ThreatCategory::parse_category("elevation_of_privilege"), Some(ThreatCategory::ElevationOfPrivilege));
    assert_eq!(ThreatCategory::parse_category("supply_chain_risk"), Some(ThreatCategory::SupplyChainRisk));
}

/// AUTOTHREAT3: Secret & Private Key Scrubbing Invariant
#[test]
fn test_autothreat3_key_scrubbing() {
    // 1. RSA Private Key rejection
    let rsa_desc = "Leaked key: -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----";
    let entry_rsa = ThreatEntry::new(
        "THREAT-SCRUB-1",
        "RSA Key Leakage",
        rsa_desc,
        ThreatCategory::InformationDisclosure,
        ThreatSeverity::Critical,
        "auth.keys",
        vec!["CWE-312".into()],
        vec![],
    );
    assert!(entry_rsa.is_err());
    assert!(entry_rsa.unwrap_err().contains(THREAT_ERR_BOUNDS_EXCEEDED));

    // 2. Generic Private Key rejection
    let gen_desc = "Private cert: -----BEGIN PRIVATE KEY-----\nMIICdgIBADANBgkqh\n-----END PRIVATE KEY-----";
    let entry_gen = ThreatEntry::new(
        "THREAT-SCRUB-2",
        "Generic Key Leakage",
        gen_desc,
        ThreatCategory::InformationDisclosure,
        ThreatSeverity::Critical,
        "auth.keys",
        vec!["CWE-312".into()],
        vec![],
    );
    assert!(entry_gen.is_err());
    assert!(entry_gen.unwrap_err().contains(THREAT_ERR_BOUNDS_EXCEEDED));

    // 3. Control character rejection
    let ctrl_title = ThreatEntry::new(
        "THREAT-CTRL",
        "Bad\x00Title",
        "Clean desc",
        ThreatCategory::Tampering,
        ThreatSeverity::Low,
        "comp",
        vec![],
        vec![],
    );
    assert!(ctrl_title.is_err());
}

/// AUTOTHREAT4: Strict Path Traversal & File Boundary Defense
#[test]
fn test_autothreat4_path_traversal() {
    // Traversal components
    assert!(ThreatModelService::validate_path(std::path::Path::new("../etc/threat_store.json")).is_err());
    assert!(ThreatModelService::validate_path(std::path::Path::new("safe/../../threat_store.json")).is_err());

    // UNC share
    assert!(ThreatModelService::validate_path(std::path::Path::new("\\\\unc\\share\\threat_store.json")).is_err());

    // Wrong extension
    assert!(ThreatModelService::validate_path(std::path::Path::new("safe/threat_store.txt")).is_err());

    // Empty path
    assert!(ThreatModelService::validate_path(std::path::Path::new("")).is_err());
}

/// AUTOTHREAT5: Multi-Threaded Concurrency Safety
#[test]
fn test_autothreat5_concurrency() {
    let service = Arc::new(Mutex::new(ThreatModelService::new()));
    let mut handles = vec![];

    for i in 0..8 {
        let svc = Arc::clone(&service);
        handles.push(thread::spawn(move || {
            let entry = ThreatEntry::new(
                &format!("THREAT-CONC-{}", i),
                &format!("Concurrent Threat {}", i),
                "Concurrent worker evaluation",
                ThreatCategory::DenialOfService,
                ThreatSeverity::Low,
                "concurrency.worker",
                vec![],
                vec![],
            ).unwrap();
            let mut lock = svc.lock().unwrap();
            let _ = lock.register_threat(entry);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let lock = service.lock().unwrap();
    assert_eq!(lock.list_threats().len(), 8);
}

/// AUTOTHREAT6: Composite Risk Monotonicity & Real-Time Scoring
#[test]
fn test_autothreat6_risk_scoring() {
    let mut catalog = ThreatModelService::new();
    let r0 = catalog.assess_risk();
    assert_eq!(r0.overall_risk_score, 0);

    // Register Low threat
    catalog.register_threat(ThreatEntry::new("T-LOW", "Low", "Desc", ThreatCategory::Spoofing, ThreatSeverity::Low, "c", vec![], vec![]).unwrap()).unwrap();
    let r1 = catalog.assess_risk();
    assert!(r1.overall_risk_score >= r0.overall_risk_score);

    // Register High threat
    catalog.register_threat(ThreatEntry::new("T-HIGH", "High", "Desc", ThreatCategory::Tampering, ThreatSeverity::High, "c", vec![], vec![]).unwrap()).unwrap();
    let r2 = catalog.assess_risk();
    assert!(r2.overall_risk_score > r1.overall_risk_score);

    // Register Critical threat
    catalog.register_threat(ThreatEntry::new("T-CRIT", "Crit", "Desc", ThreatCategory::ElevationOfPrivilege, ThreatSeverity::Critical, "c", vec![], vec![]).unwrap()).unwrap();
    let r3 = catalog.assess_risk();
    assert!(r3.overall_risk_score > r2.overall_risk_score);
    assert_eq!(r3.critical_unmitigated_count, 1);
}

/// AUTOTHREAT7: Capacity Boundary & DoS Resistance
#[test]
fn test_autothreat7_capacity_bounds() {
    let mut catalog = ThreatModelService::new();

    for i in 0..512 {
        let entry = ThreatEntry::new(
            &format!("T-CAP-{}", i),
            &format!("Threat {}", i),
            "Description of threat",
            ThreatCategory::Spoofing,
            ThreatSeverity::Low,
            "core",
            vec![],
            vec![],
        ).unwrap();
        assert!(catalog.register_threat(entry).is_ok());
    }
    assert_eq!(catalog.list_threats().len(), 512);

    let excess = ThreatEntry::new(
        "T-CAP-EXCESS",
        "Excess Threat",
        "Description",
        ThreatCategory::Spoofing,
        ThreatSeverity::Low,
        "core",
        vec![],
        vec![],
    ).unwrap();

    let err = catalog.register_threat(excess).unwrap_err();
    assert!(err.contains(THREATSVC_ERR_CAPACITY_EXCEEDED));
}

/// AUTOTHREAT8: Serialization Roundtrip & Invariant Preservation
#[test]
fn test_autothreat8_serialization_roundtrip() {
    let mut snapshot = ThreatModelSnapshot::new("1.0.0");
    let entry = ThreatEntry::new(
        "T-SER",
        "Serialization",
        "Roundtrip verification",
        ThreatCategory::Tampering,
        ThreatSeverity::Medium,
        "comp",
        vec!["CWE-20".into()],
        vec!["Mitigation 1".into()],
    ).unwrap();
    snapshot.add_entry(entry).unwrap();

    let json = serde_json::to_string(&snapshot).unwrap();
    let restored: ThreatModelSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.version, "1.0.0");
    assert_eq!(restored.threats.len(), 1);

    let e = restored.get_entry("T-SER").unwrap();
    assert_eq!(e.title, "Serialization");
    assert_eq!(e.cwe_ids, vec!["CWE-20"]);
    assert_eq!(e.mitigations, vec!["Mitigation 1"]);
}

/// AUTOTHREAT9: Atomic Persistence & Zero-Leak File Handling
#[test]
fn test_autothreat9_atomic_persistence() {
    let dir = tempdir().unwrap();
    let store_path = dir.path().join("threats_atomic.json");

    let mut catalog = ThreatModelService::new();
    catalog.register_threat(ThreatEntry::new("T-ATOM", "Atomicity", "Test write", ThreatCategory::Spoofing, ThreatSeverity::Low, "core", vec![], vec![]).unwrap()).unwrap();

    assert!(catalog.save_to_path(&store_path).is_ok());
    assert!(store_path.exists());

    let loaded = ThreatModelService::load_from_path(&store_path).unwrap();
    assert_eq!(loaded.list_threats().len(), 1);
}

/// AUTOTHREAT10: Canonical Baseline Reset & Idempotent Init
#[test]
fn test_autothreat10_canonical_init() {
    let catalog = ThreatModelService::with_canonical_threats();
    assert_eq!(catalog.list_threats().len(), 7);

    // Verify all 7 are mitigated
    for t in catalog.list_threats() {
        assert_eq!(t.status, ThreatStatus::Mitigated);
        assert!(!t.mitigations.is_empty());
    }
}
