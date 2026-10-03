# Specification: Threat Model Maintenance Automated Tests (SPEC-THREAT-MODEL-AUTOMATED-TESTS)

- **Status**: IMPLEMENTED & VERIFIED
- **Date**: 2026-10-03
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Maintenance Automated Tests
- **Binding**: ADR-0035 §F-2, ADR-0036 §B-1
- **Tasks**: T-02751 (Research), T-02752 (Spec), T-02753 (Scaffold), T-02754 (Impl), T-02755 (Unit Test), T-02756 (Integration), T-02757 (Security Review), T-02758 (Hardening), T-02759 (Documentation), T-02760 (Milestone Verification)

## 1. Overview
The Threat Model Maintenance automated test suite provides deterministic verification of threat catalog state transitions, STRIDE taxonomy coverage, sensitive data/private-key fail-closed rejection, path traversal guards, atomic persistence, composite risk calculation, and multi-threaded concurrency safety across the AIOS security kernel.

## 2. Test Vectors

| Vector ID | Name | Description | Invariants Tested | Status |
|:---|:---|:---|:---|:---|
| `AUTOTHREAT1` | Full Threat Lifecycle & Invariant Transitions | Verifies transitions across `Identified` -> `UnderReview` -> `Mitigated` -> `Resolved` and `UnderReview` -> `Accepted`, rejecting illegal transitions and requiring mitigation before `Mitigated`/`Resolved` | `THREAT1`, `THREAT2` | **VERIFIED** |
| `AUTOTHREAT2` | STRIDE Taxonomy & Severity Matrix | Validates representation and handling of all 6 STRIDE categories (`Spoofing`, `Tampering`, `Repudiation`, `InformationDisclosure`, `DenialOfService`, `ElevationOfPrivilege`) plus SupplyChainRisk | `THREAT3`, `THREAT4` | **VERIFIED** |
| `AUTOTHREAT3` | Secret & Private Key Scrubbing Invariant | Guarantees fail-closed rejection of PEM/SSH private keys (`-----BEGIN ... PRIVATE KEY-----`) in title, description, and mitigation fields | `THREAT7`, CWE-312 | **VERIFIED** |
| `AUTOTHREAT4` | Path Traversal & Symlink Defense | Enforces strict path validation (`..` rejection, UNC share rejection, length limit $\le 1024$, control characters rejection, symlink rejection) | `THREATCONF2`, CWE-22, CWE-59 | **VERIFIED** |
| `AUTOTHREAT5` | Multi-Threaded Concurrency Safety | Validates thread safety and race-free concurrent mutations and queries under multi-threaded load (8 concurrent threads) | Kernel Thread Safety | **VERIFIED** |
| `AUTOTHREAT6` | Risk Monotonicity & Composite Scoring | Verifies monotonic increase of composite risk with higher severity counts and attenuation by mitigations | `THREAT5` | **VERIFIED** |
| `AUTOTHREAT7` | Capacity Ceiling & DoS Resistance | Validates rejection of threat additions beyond configured capacity limit (512 threats) with `THREATSVC_ERR_CAPACITY_EXCEEDED` | `THREATCONF3`, `THREAT8` | **VERIFIED** |
| `AUTOTHREAT8` | Serialization Roundtrip & Invariant Preservation | Validates JSON snapshot serialization roundtripping with preservation of timestamps, CWEs, and mitigations | `THREAT6` | **VERIFIED** |
| `AUTOTHREAT9` | Atomic Persistence & Zero-Leak File Handling | Verifies atomic rename persistence, no leftover temp files on error paths, and clean error envelopes | `THREATCONF5` | **VERIFIED** |
| `AUTOTHREAT10` | Canonical Baseline Reset & Idempotent Init | Verifies canonical STRIDE threat seeding and non-destructive overwrite guards unless `force` is asserted | `THREAT1` | **VERIFIED** |

## 3. Test Suites & Invocation

### 3.1 Rust Core Automated Test Suite
Run the 14 automated unit and boundary tests in isolation:
```bash
cargo test -p aiosh-core --test test_threat_model_automated
```

### 3.2 Production MCP Surface Integration Tests
Run the production MCP tool suite executing the automated vectors with SQLite `audit_ring` validation:
```bash
cargo test -p aiosh-mcp -- test_mcp_threat_model_automated_vectors
```

### 3.3 Full Subsystem Regression Suite
```bash
cargo test -p aiosh-core --test test_threat_model_config
cargo test -p aiosh-core --test test_threat_model_config_integration
cargo test -p aiosh-core --test test_threat_model_data_model
cargo test -p aiosh-core --test test_threat_model_service
cargo test -p aiosh-core --test test_threat_model_service_integration
cargo test -p aiosh-core --test test_threat_model_integration
cargo test -p aiosh-mcp -- test_mcp_threat_model
```

## 4. Constraints & Known Limitations
1. **In-Memory Lock Contention**: While `ThreatModelService` is safe across concurrent threads via standard Mutex synchronization, highly concurrent write spikes may experience mutex latency.
2. **Fixed Maximum Catalog Size**: The maximum entries capacity is strictly bounded at 512 entries (configurable up to 4,096 in `ThreatModelConfig`).
3. **No Dynamic Hot-Reloading**: In-memory threat catalogs do not watch disk files for asynchronous external alterations.
4. **Fail-Closed Secrets Rejection**: Any threat title or description containing PEM private key patterns is rejected outright with an error rather than silently sanitized.

## 5. Evidence Cross References
- [Research Evidence (T-02751)](tasks/evidence/T-02751-automated-tests-research.md)
- [Specification Evidence (T-02752)](tasks/evidence/T-02752-automated-tests-specification.md)
- [Scaffold Evidence (T-02753)](tasks/evidence/T-02753-automated-tests-scaffold.md)
- [Implementation Evidence (T-02754)](tasks/evidence/T-02754-automated-tests-implementation.md)
- [Unit Test Evidence (T-02755)](tasks/evidence/T-02755-automated-tests-unit-test.md)
- [Integration Evidence (T-02756)](tasks/evidence/T-02756-automated-tests-integration.md)
- [Security Review (T-02757)](tasks/evidence/T-02757-security.md)
- [Hardening Evidence (T-02758)](tasks/evidence/T-02758-automated-tests-hardening.md)
