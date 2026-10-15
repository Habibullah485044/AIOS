# Specification & Guide: Incident Response Runbooks Automated Tests Subsystem

**Status**: Shipped & Hardened (Tasks T-03013 .. T-03022)  
**Contract Reference**: `docs/tasks/evidence/T-03014-spec.md`, `docs/tasks/evidence/T-03016-automated-tests-implementation.md`, `docs/tasks/evidence/T-03019-security.md`, `docs/tasks/evidence/T-03020-automated-tests-hardening.md`  
**Date**: 2026-10-15  

---

## 1. Overview & Test Vectors

The Incident Response Runbooks Automated Test battery provides deterministic verification of runbook execution, operator confirmation gating, forensic IOC pattern scanning, configuration resolution, and concurrency capping.

### Test Vectors
- `AUTORUNBOOK1`: Canonical baseline snapshot integrity (`RB-IR-MALWARE-01`, `RB-IR-ACCESS-01`).
- `AUTORUNBOOK2`: State machine transitions (`Pending` -> `Running` -> `Completed` / `Failed`).
- `AUTORUNBOOK3`: High-risk confirmation gate enforcement (`AwaitingConfirmation`).
- `AUTORUNBOOK4`: Parameter interpolation and injection defense.
- `AUTORUNBOOK5`: Forensic file pattern scanning (depth $\le 32$, size $\le 16$ MiB).
- `AUTORUNBOOK6`: Network & web port scanning hygiene.
- `AUTORUNBOOK7`: 4-level configuration resolution (`argument` > `env` > `file` > `default`).
- `AUTORUNBOOK8`: Dynamic concurrency bounds & memory eviction.
- `AUTORUNBOOK9`: Proof-of-Restraint (Invariant I-2) conformance.
- `AUTORUNBOOK10`: Fail-closed structured result envelopes.

---

## 2. Invocation Examples

### Rust Test Battery
```bash
# Run end-to-end automated battery
cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_incident_runbook_automated

# Run focused unit tests
cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_incident_runbook_automated_unit

# Run integration tests
cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_incident_runbook_automated_integration

# Run hardening tests
cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_incident_runbook_automated_hardening
```

### Python FastMCP Battery
```bash
# Run automated test battery
python -m pytest code/aiosh-mcp/tests/test_incident_runbook_automated_smoke.py

# Run unit tests
python -m pytest code/aiosh-mcp/tests/test_incident_runbook_automated_unit.py

# Run integration tests
python -m pytest code/aiosh-mcp/tests/test_incident_runbook_automated_integration.py

# Run hardening tests
python -m pytest code/aiosh-mcp/tests/test_incident_runbook_automated_hardening.py
```

---

## 3. Constraints & Limitations
- **Timeout Bounds**: Default step timeout is clamped $\in [1, 300]$ seconds.
- **Session Capacity**: Concurrent sessions bounded by `max_active_sessions` (default 100, clamped $[1, 10000]$).
- **Scan Depth**: Directory recursion depth strictly capped at $\le 32$ levels.
- **Zero Raw Shell Passes**: Dynamic action templates only substitute validated alphanumeric identifiers.
