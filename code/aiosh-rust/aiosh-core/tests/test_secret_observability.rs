//! Unit Tests for Secrets Handling Observability (T-02675).

use aiosh_core::secret_data_model::{SecretEntry, SecretKind, SecretScope};
use aiosh_core::secret_service::SecretService;
use aiosh_core::secret_observability::{
    sanitize_telemetry_text, SecretObservabilityReport,
    MAX_TELEMETRY_TEXT_LEN, SECOBS_ERR_VALIDATION,
};

fn make_test_entry(id: &str, kind: SecretKind, scope: SecretScope, val: &[u8]) -> SecretEntry {
    SecretEntry::new(id, &format!("Name {}", id), kind, scope, val).expect("valid entry")
}

#[test]
fn test_observability_empty_vault() {
    let service = SecretService::new();
    let report = SecretObservabilityReport::generate(&service, None).expect("report generation succeeds");

    assert_eq!(report.total_secrets, 0);
    assert_eq!(report.active_secrets_count, 0);
    assert_eq!(report.expired_secrets_count, 0);
    assert_eq!(report.secrets_by_scope.len(), 0);
    assert_eq!(report.secrets_by_kind.len(), 0);
    assert_eq!(report.policy_mode, "enforcing");
    assert!(report.is_healthy);
    assert_eq!(report.recent_audit_events_count, 0);
    assert!(report.validate().is_ok());
}

#[test]
fn test_observability_populated_vault() {
    let mut service = SecretService::new();
    service.store_secret(make_test_entry("s1", SecretKind::ApiKey, SecretScope::Global, b"key1")).unwrap();
    service.store_secret(make_test_entry("s2", SecretKind::DatabaseCredential, SecretScope::Actor("user1".into()), b"pass2")).unwrap();
    service.store_secret(make_test_entry("s3", SecretKind::ApiKey, SecretScope::Actor("user2".into()), b"key3")).unwrap();

    let report = SecretObservabilityReport::generate(&service, None).expect("report succeeds");

    assert_eq!(report.total_secrets, 3);
    assert_eq!(report.active_secrets_count, 3);
    assert_eq!(report.expired_secrets_count, 0);

    assert_eq!(report.secrets_by_kind.get("api_key"), Some(&2));
    assert_eq!(report.secrets_by_kind.get("database_credential"), Some(&1));

    assert_eq!(report.secrets_by_scope.get("global"), Some(&1));
    assert_eq!(report.secrets_by_scope.get("actor:user1"), Some(&1));
    assert_eq!(report.secrets_by_scope.get("actor:user2"), Some(&1));
    assert!(report.is_healthy);
}

#[test]
fn test_observability_sanitize_text() {
    let input_with_control = "hello\x00\x1fworld\n\r\t";
    let cleaned = sanitize_telemetry_text(input_with_control);
    assert_eq!(cleaned, "helloworld");

    let long_input = "a".repeat(500);
    let truncated = sanitize_telemetry_text(&long_input);
    assert_eq!(truncated.len(), MAX_TELEMETRY_TEXT_LEN);
}

#[test]
fn test_observability_zero_disclosure_invariant() {
    let mut service = SecretService::new();
    let secret_payload = b"super_secret_unmasked_token_xyz987";
    service.store_secret(make_test_entry("token1", SecretKind::OAuthToken, SecretScope::Global, secret_payload)).unwrap();

    let report = SecretObservabilityReport::generate(&service, None).expect("report succeeds");
    let json_str = serde_json::to_string(&report).expect("serializes to json");

    // Plaintext payload MUST NEVER be leaked into telemetry
    assert!(!json_str.contains("super_secret_unmasked_token_xyz987"));
}

#[test]
fn test_observability_validation_rejection() {
    let service = SecretService::new();
    let mut report = SecretObservabilityReport::generate(&service, None).unwrap();

    report.generated_at_utc = "  ".to_string();
    let err = report.validate().unwrap_err();
    assert!(err.contains(SECOBS_ERR_VALIDATION));
    assert!(err.contains("timestamp cannot be empty"));
}
