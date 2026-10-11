# Hardening Evidence: Compliance Mapping Observability (T-02940)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Observability
- **Task ID**: `T-02940`
- **Scope**: Hardening Rust and Python implementations against failure modes, malformed timestamps, zero-width characters, resource exhaustion, and unhandled errors.

## 1. Hardening Defenses Applied

1. **Zero-Width & Unicode Sanitization**:
   - `sanitize_telemetry_text` explicitly strips invisible characters (`\u{200b}`, `\u{200c}`, `\u{200d}`, `\u{feff}`) in addition to ASCII control characters.
   - Validation fails closed if distribution keys contain forbidden characters.
2. **Numeric & Floating-Point Sanitization**:
   - Strict finiteness assertions: `compliance_percentage.is_finite() && !compliance_percentage.is_nan() && (0.0..=100.0).contains(...)`.
   - Bounded percentage scaling: `capacity_utilization_percent <= 100`.
3. **Audit Log Tail Ceiling**:
   - Explicit assertion that `recent_audit_events_count <= MAX_AUDIT_LOG_TAIL_ITEMS` (1000 items), preventing unbounded query expansion.
4. **Custom Timestamp Verification**:
   - `generate_with_timestamp` verifies supplied timestamps strictly match RFC 3339 format, rejecting malformed inputs with `COMPOBS_ERR_VALIDATION`.
5. **Fail-Closed Envelope & Resource Cleanup**:
   - In MCP surface `aios.compliance(action="stats")`, failure modes return `{ok: false, action: "stats", error: str(exc)}`, and `_recorded_call` commits an honest audit row to `audit_ring` without leaking open file handles or SQLite locks.

## 2. Verification Battery

- `cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_compliance_observability_unit --test test_compliance_observability_integration`: PASS (11/11 tests passed).
- `python -m pytest code/aiosh-mcp/tests/test_compliance_observability_unit.py code/aiosh-mcp/tests/test_compliance_observability_integration.py`: PASS (11/11 tests passed).
