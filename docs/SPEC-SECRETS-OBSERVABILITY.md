# Specification: Secrets Handling Observability (SPEC-SECRETS-OBSERVABILITY)

- **Status**: IMPLEMENTED & HARDENED
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
   - String labels and telemetry fields pass through `sanitize_telemetry_text()` which strips ASCII and Unicode control characters and truncates to `MAX_TELEMETRY_TEXT_LEN` (256 bytes).
3. **Bounded Collections**:
   - Distribution maps (`secrets_by_scope`, `secrets_by_kind`) are capped at `MAX_OUTCOME_DISTRIBUTION_ENTRIES` (128 entries) to prevent unbounded memory growth under arbitrary key insertion.
4. **Audit Query Bound**:
   - Audit ring tail queries are bounded to `MAX_AUDIT_LOG_TAIL_ITEMS = 1000` rows to guarantee constant-time telemetry generation.

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
- `SECOBS_ERR_VALIDATION`: "SECOBS_ERR_VALIDATION" — Raised when report metrics violate internal range, RFC3339 timestamp format, or key sanitization checks.
- `SECOBS_ERR_SERVICE_INACCESSIBLE`: "SECOBS_ERR_SERVICE_INACCESSIBLE" — Raised when the underlying secret service is inaccessible or corrupted.

## 5. Operational Invocation Examples

### 5.1 CLI Surface
Inspect the current secrets vault telemetry in human-readable tabular format:
```bash
aiosh secret observability
```

Inspect in structured JSON format (ideal for automated monitors and CI validation):
```bash
aiosh secret observability --json
```

Query a custom vault location:
```bash
aiosh secret metrics --store /var/lib/aios/secrets.json --json
```

### 5.2 Rust Core API
```rust
use aiosh_core::secret_service::SecretService;
use aiosh_core::secret_observability::SecretObservabilityReport;

let service = SecretService::load_from_path(vault_path)?;
let report = SecretObservabilityReport::generate(&service, None)?;
println!("Total vaulted secrets: {}", report.total_secrets);
```

## 6. Constraints & Known Limitations
1. **In-Memory Cardinality**: Scope and kind distributions cap out at 128 distinct categories; any additional unique scopes or kinds are omitted from distribution counting.
2. **Read-Only Telemetry**: Generating an observability report does not mutate vault state or update secret timestamps.
3. **Store Path Hygiene**: Path traversal (`..`), empty path strings, and control characters in `--store` flags are strictly rejected with exit code 2.

## 7. Evidence & Verification Links
- [T-02671 Observability Research](evidence/T-02671-observability-research.md)
- [T-02672 Observability Specification](evidence/T-02672-observability-specification.md)
- [T-02673 Observability Scaffold](evidence/T-02673-observability-scaffold.md)
- [T-02674 Observability Implementation](evidence/T-02674-observability-implementation.md)
- [T-02675 Observability Unit Tests](evidence/T-02675-observability-unit-test.md)
- [T-02676 Observability Integration](evidence/T-02676-observability-integration.md)
- [T-02677 Observability Security Review](evidence/T-02677-observability-security-review.md)
- [T-02678 Observability Hardening](evidence/T-02678-observability-hardening.md)
