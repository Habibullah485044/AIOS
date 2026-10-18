//! Unit tests for AI Control Plane Model Backend Adapters Data Model (T-03167).

use aiosh_core::model_backend_adapters_data_model::*;

#[test]
fn test_modadapt_inv1_rust_role_canonicalization() {
    assert_eq!(validate_role("system").unwrap(), "system");
    assert_eq!(validate_role("USER").unwrap(), "user");
    assert_eq!(validate_role("Assistant").unwrap(), "assistant");
    assert_eq!(validate_role("tool").unwrap(), "tool");

    assert!(validate_role("invalid").is_err());
    assert!(validate_role("").is_err());
}

#[test]
fn test_modadapt_inv2_rust_usage_invariants() {
    let usage = ModelUsage::new(20, 30);
    assert_eq!(usage.total_tokens, 50);
    assert!(usage.validate_invariants().is_ok());

    let mut bad_usage = usage;
    bad_usage.total_tokens = 999;
    assert!(bad_usage.validate_invariants().is_err());
}

#[test]
fn test_modadapt_inv3_and_inv4_rust_endpoint_validation() {
    let valid = ModelEndpointConfig {
        backend_id: "ep-1".into(),
        provider: ModelProviderType::Mock,
        model_name: "mock-v1".into(),
        base_url: None,
        api_key_env: Some("AIOS_KEY".into()),
        timeout_ms: 5000,
        max_retries: 3,
        capabilities: ModelCapabilities::default(),
        is_active: true,
    };
    assert!(valid.validate().is_ok());

    // Secret leak rejection
    let mut leak = valid.clone();
    leak.api_key_env = Some("sk-live-123456789".into());
    assert!(leak.validate().is_err());

    // Temperature bounds
    assert_eq!(validate_temperature(0.0).unwrap(), 0.0);
    assert_eq!(validate_temperature(2.0).unwrap(), 2.0);
    assert!(validate_temperature(-0.1).is_err());
    assert!(validate_temperature(2.1).is_err());
}
