//! Automated Test Suite for Threat Model Maintenance Subsystem (T-02751..T-02760).
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

    // Transition to UnderReview
    assert!(catalog.update_status("THREAT-AUTO-1", ThreatStatus::UnderReview).is_ok());
    assert_eq!(catalog.get_threat("THREAT-AUTO-1").unwrap().status, ThreatStatus::UnderReview);

    // Transition to Mitigated without mitigation fails
    assert!(catalog.update_status("THREAT-AUTO-1", ThreatStatus::Mitigated).is_err());

    // Attach mitigation
    assert!(catalog.attach_mitigation("THREAT-AUTO-1", "Apply seccomp-bpf privilege filter").is_ok());
    assert!(catalog.update_status("THREAT-AUTO-1", ThreatStatus::Mitigated).is_ok());
    assert_eq!(catalog.get_threat("THREAT-AUTO-1").unwrap().status, ThreatStatus::Mitigated);
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
    ];

    for (idx, cat) in categories.iter().enumerate() {
        let entry = ThreatEntry::new(
            &format!("STRIDE-{}", idx),
            &format!("Test Threat for {:?}", cat),
            "Description of threat",
            *cat,
            ThreatSeverity::Medium,
            "test.component",
            vec![],
            vec![],
        ).expect("Valid entry");
        assert!(catalog.register_threat(entry).is_ok());
    }

    assert_eq!(catalog.list_threats().len(), 6);
}

/// AUTOTHREAT3: Secret & Private Key Scrubbing Invariant
#[test]
fn test_autothreat3_key_scrubbing() {
    let raw_desc = "Leaked key: -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----";
    let entry_res = ThreatEntry::new(
        "THREAT-SCRUB",
        "Key Leakage",
        raw_desc,
        ThreatCategory::InformationDisclosure,
        ThreatSeverity::Critical,
        "auth.keys",
        vec!["CWE-312".into()],
        vec![],
    );

    assert!(entry_res.is_err());
    let err = entry_res.unwrap_err();
    assert!(err.contains(THREAT_ERR_BOUNDS_EXCEEDED));
    assert!(err.contains("Secret or private key material detected"));
}

/// AUTOTHREAT4: Strict Path Traversal & File Boundary Defense
#[test]
fn test_autothreat4_path_traversal() {
    let traversal_res = ThreatModelService::validate_path(std::path::Path::new("../etc/threat_store.json"));
    assert!(traversal_res.is_err());

    let unc_res = ThreatModelService::validate_path(std::path::Path::new("\\\\unc\\share\\threat_store.json"));
    assert!(unc_res.is_err());
}

/// AUTOTHREAT5: Multi-Threaded Concurrency Safety
#[test]
fn test_autothreat5_concurrency() {
    let service = Arc::new(Mutex::new(ThreatModelService::new()));
    let mut handles = vec![];

    for i in 0..4 {
        let svc = Arc::clone(&service);
        handles.push(thread::spawn(move || {
            let entry = ThreatEntry::new(
                &format!("THREAT-CONC-{}", i),
                &format!("Concurrent Threat {}", i),
                "Concurrent thread test",
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
    assert_eq!(lock.list_threats().len(), 4);
}

/// AUTOTHREAT6: Composite Risk Monotonicity & Real-Time Scoring
#[test]
fn test_autothreat6_risk_scoring() {
    let mut catalog = ThreatModelService::new();
    let initial_assessment = catalog.assess_risk();
    assert_eq!(initial_assessment.total_threats, 0);
    assert_eq!(initial_assessment.overall_risk_score, 0);

    let critical_threat = ThreatEntry::new(
        "THREAT-RISK-1",
        "Critical Threat",
        "Critical unmitigated vulnerability",
        ThreatCategory::ElevationOfPrivilege,
        ThreatSeverity::Critical,
        "kernel",
        vec![],
        vec![],
    ).unwrap();
    catalog.register_threat(critical_threat).unwrap();

    let post_assessment = catalog.assess_risk();
    assert_eq!(post_assessment.total_threats, 1);
    assert_eq!(post_assessment.critical_unmitigated_count, 1);
    assert!(post_assessment.overall_risk_score > 0);
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
        vec![],
    ).unwrap();
    snapshot.add_entry(entry).unwrap();

    let json = serde_json::to_string(&snapshot).unwrap();
    let restored: ThreatModelSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.version, "1.0.0");
    assert_eq!(restored.threats.len(), 1);
    assert_eq!(restored.get_entry("T-SER").unwrap().title, "Serialization");
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
