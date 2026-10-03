# T-02671: Secrets Handling Observability Research

- **Task**: `T-02671`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Secrets Handling / observability
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Research Objectives
Establish authoritative facts, security constraints, telemetry invariants, and prior art for the observability subsystem of Secrets Handling (`code/aiosh-rust/aiosh-core/src/secret_observability.rs`).

## 2. Established Facts vs Assumptions

### Established Architectural Facts
1. **Zero-Disclosure Observability Invariant**:
   - Observability and metrics must **NEVER** expose plaintext secret values, unmasked key data, or base64/hex payloads in metrics, logs, or error reports.
   - Only counts, distributions by `SecretKind` and `SecretScope`, version counters, expiration status, and redaction fingerprints may appear in telemetry records.
2. **Prior Subsystem Patterns (`privilege_observability.rs`, `pep_grant_observability.rs`)**:
   - Error code definitions (e.g. `SECOBS_ERR_VALIDATION`).
   - Hard upper bounds on strings (`MAX_TELEMETRY_TEXT_LEN = 256`) and collection capacities (`MAX_OUTCOME_DISTRIBUTION_ENTRIES = 128`).
   - String sanitization (`sanitize_telemetry_text`) stripping control and non-printable characters.
   - Point-in-time snapshot generation (`generate(&SecretService, Option<&AuditRing>) -> Result<SecretObservabilityReport, String>`).
   - JSON serialization support via Serde.
3. **Audit Ring Event Surface**:
   - Subsystem emissions record events: `secret.store`, `secret.get`, `secret.rotate`, `secret.delete`, `secret.policy_violation`.
   - Telemetry must correlate with audit tail records without blocking service operations.

### Assumptions to Validate
1. *Assumption*: `SecretObservabilityReport` can inspect in-memory or persisted `SecretService` state with zero disk writes. (Confirmed: report generation is strictly read-only).
2. *Assumption*: CLI command `aiosh secret metrics` or `aiosh secret observability` can query the report in both human-readable text and compact JSON modes.
3. *Assumption*: MCP surface can expose `aios.secret.observability` tool conforming to JSON-RPC -32602 schema validation.

## 3. Decisions Needed for Specification (T-02672)
1. **Contract Name**: Specify `docs/SPEC-SECRETS-OBSERVABILITY.md` covering report schema, metrics keys, error conditions, and CLI/MCP wire formats.
2. **Data Model**:
   - `SecretObservabilityReport`: `generated_at_utc`, `total_secrets`, `secrets_by_scope`, `secrets_by_kind`, `expired_secrets_count`, `active_secrets_count`, `policy_mode`, `is_healthy`.
3. **Scaffold Target**:
   - `code/aiosh-rust/aiosh-core/src/secret_observability.rs` (module export in `lib.rs`).
4. **Integration Surface**:
   - CLI: `aiosh secret observability` / `metrics`
   - MCP: `aios.secret.observability`
