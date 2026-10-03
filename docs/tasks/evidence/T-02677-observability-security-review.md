# T-02677: Secrets Handling Observability Security Review

- **Task**: `T-02677`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Secrets Handling / observability
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Security Architecture & Threat Model
Reviewed the Secrets Handling Observability subsystem against 5 primary threat scenarios:

| Threat Scenario | CWE | Attack Vector | Security Control & Status |
|---|---|---|---|
| Plaintext Secret Exfiltration | CWE-200 | Attempting to leak secret material via telemetry/metrics payload | **RESOLVED**: Core Zero-Disclosure Invariant enforced. Telemetry structures only inspect metadata counts; secret values are never read or stored. |
| Telemetry Cardinality Memory DoS | CWE-400 | Seeding unbounded scopes/kinds to exhaust memory in distribution maps | **RESOLVED**: Distribution maps (`secrets_by_scope`, `secrets_by_kind`) bounded by `MAX_OUTCOME_DISTRIBUTION_ENTRIES = 128`. |
| Terminal / Log Injection | CWE-116 | Injecting ANSI escapes or control chars in scope/kind names | **RESOLVED**: `sanitize_telemetry_text()` removes all control characters and limits strings to 256 bytes. |
| Path Traversal on Store File | CWE-22 | Supplying traversal paths (`--store ../../target`) | **RESOLVED**: `SecretService::validate_path()` rejects any `..` component and control characters before touching the filesystem. |
| Audit Ring Query Exhaustion | CWE-770 | Large audit rings causing slow queries or process hangs | **RESOLVED**: Bound queries to `MAX_AUDIT_LOG_TAIL_ITEMS = 1000` rows with non-blocking error handling. |

## 2. Hardening Opportunities for T-02678
- Ensure that `SecretObservabilityReport::validate()` explicitly enforces that `recent_audit_events_count` cannot be negative and that distribution map string keys conform to `MAX_TELEMETRY_TEXT_LEN`.
- Ensure error messages sanitized with `sanitize_terminal()` across all CLI output paths.
