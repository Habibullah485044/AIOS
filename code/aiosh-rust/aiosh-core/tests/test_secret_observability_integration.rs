//! Integration Tests for Secrets Handling Observability (T-02676).

use tempfile::tempdir;

use aiosh_core::secret_data_model::{SecretEntry, SecretKind, SecretScope};
use aiosh_core::secret_observability::SecretObservabilityReport;
use aiosh_core::secret_service::SecretService;
use aiosh_core::secret_policy::{SecretPolicyMode, SecretSecurityPolicy};

#[test]
fn test_secret_observability_end_to_end_integration() {
    let tmp = tempdir().unwrap();
    let vault_path = tmp.path().join("vault.json");

    let mut service = SecretService::new();
    let mut policy = SecretSecurityPolicy::default();
    policy.mode = SecretPolicyMode::Permissive;
    service.set_policy(policy);

    // 1. Populate secrets across multiple scopes and kinds
    let sec1 = SecretEntry::new(
        "api_prod_key",
        "Production API Key",
        SecretKind::ApiKey,
        SecretScope::Global,
        b"api_secret_12345",
    ).unwrap();

    let sec2 = SecretEntry::new(
        "db_master_pass",
        "Master Database Credential",
        SecretKind::DatabaseCredential,
        SecretScope::Actor("db_operator".into()),
        b"db_secret_pass_67890",
    ).unwrap();

    let sec3 = SecretEntry::new(
        "oauth_client_token",
        "OAuth Service Token",
        SecretKind::OAuthToken,
        SecretScope::Session("sess_abc123".into()),
        b"oauth_tok_55555",
    ).unwrap();

    service.store_secret(sec1).unwrap();
    service.store_secret(sec2).unwrap();
    service.store_secret(sec3).unwrap();

    // 2. Persist to disk and reload in a new service instance
    service.save_to_path(&vault_path).unwrap();
    assert!(vault_path.exists());

    let mut loaded_service = SecretService::load_from_path(&vault_path).unwrap();
    loaded_service.set_policy(service.policy().clone());

    // 3. Generate observability report
    let report = SecretObservabilityReport::generate(&loaded_service, None).expect("report succeeds");

    assert_eq!(report.total_secrets, 3);
    assert_eq!(report.active_secrets_count, 3);
    assert_eq!(report.expired_secrets_count, 0);
    assert_eq!(report.policy_mode, "permissive");
    assert!(report.is_healthy);

    // Verify scope and kind distributions
    assert_eq!(report.secrets_by_kind.get("api_key"), Some(&1));
    assert_eq!(report.secrets_by_kind.get("database_credential"), Some(&1));
    assert_eq!(report.secrets_by_kind.get("oauth_token"), Some(&1));

    assert_eq!(report.secrets_by_scope.get("global"), Some(&1));
    assert_eq!(report.secrets_by_scope.get("actor:db_operator"), Some(&1));
    assert_eq!(report.secrets_by_scope.get("session:sess_abc123"), Some(&1));

    // 4. Verify Zero-Disclosure Invariant on serialized JSON
    let json_output = serde_json::to_string_pretty(&report).unwrap();
    assert!(!json_output.contains("api_secret_12345"));
    assert!(!json_output.contains("db_secret_pass_67890"));
    assert!(!json_output.contains("oauth_tok_55555"));
}
