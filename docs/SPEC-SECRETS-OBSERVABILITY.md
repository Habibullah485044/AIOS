# Specification: Secrets Handling Observability (SPEC-SECRETS-OBSERVABILITY)

- **Status**: SPECIFIED
- **Date**: 2026-10-03
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Secrets Handling Observability
- **Binding**: ADR-0035 §F-2

## 1. Overview
The Secrets Handling Observability subsystem provides point-in-time telemetry aggregation, distribution tracking across scopes and kinds, audit event correlation, and operational health assessment for the AIOS secrets vault.

## 2. Core Invariants
1. **Zero-Disclosure Invariant**:
   - Under no circumstances shall plaintext secrets, decrypted payloads, raw hex sequences, or decryption keys be included in telemetry structures, logs, or error strings.
   - All reports aggregate strictly high-level counts, categorization maps, and sanitised operational statuses.
2. **Deterministic Sanitisation**:
   - String labels and telemetry fields must pass through `sanitize_telemetry_text()` which strips ASCII and Unicode control characters and truncates to `MAX_TELEMETRY_TEXT_LEN` (256 bytes).
3. **Bounded Collections**:
   - Distribution maps (`secrets_by_scope`, `secrets_by_kind`) are capped at `MAX_OUTCOME_DISTRIBUTION_ENTRIES` (128 entries) to prevent unbounded memory growth under arbitrary key insertion.

## 3. Data Structures

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretObservabilityReport {
    pub generated_at_utc: String,
    pub total_secrets: usize,
    pub secrets_by_scope: HashMap<String, usize>,
    pub secrets_by_kind: HashMap<String, usize>,
    pub active_secrets_count: usize,
    pub expired_secrets_count: usize,
    pub policy_mode: String,
    pub is_healthy: bool,
    pub recent_audit_events_count: usize,
}
```

## 4. Error Constants
- `SECOBS_ERR_VALIDATION`: "SECOBS_ERR_VALIDATION" — Raised when report metrics violate internal range or sanity checks.
- `SECOBS_ERR_SERVICE_INACCESSIBLE`: "SECOBS_ERR_SERVICE_INACCESSIBLE" — Raised when the underlying secret service is inaccessible or corrupted.

## 5. Interfaces
- **Rust Library API**:
  `SecretObservabilityReport::generate(service: &SecretService, ring: Option<&AuditRing>) -> Result<Self, String>`
- **CLI Command**:
  `aiosh secret observability [--json]`
- **MCP Tool**:
  `aios.secret.observability`
