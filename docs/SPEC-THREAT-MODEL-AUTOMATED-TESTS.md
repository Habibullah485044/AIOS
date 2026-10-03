# Specification: Threat Model Maintenance Automated Tests (SPEC-THREAT-MODEL-AUTOMATED-TESTS)

- **Status**: APPROVED
- **Date**: 2026-10-03
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Maintenance Automated Tests
- **Binding**: ADR-0035 §F-2, ADR-0036 §B-1

## 1. Overview
The Threat Model Maintenance automated test suite provides deterministic verification of threat catalog state transitions, STRIDE taxonomy coverage, sensitive data/private-key scrubbing, path traversal guards, atomic persistence, composite risk calculation, and multi-threaded concurrency safety across the AIOS security kernel.

## 2. Test Vectors

| Vector ID | Name | Description | Invariants Tested |
|:---|:---|:---|:---|
| `AUTOTHREAT1` | Full Threat Lifecycle & Invariant Transitions | Verifies transitions across `Identified` -> `UnderReview` -> `Mitigated` -> `Accepted` -> `Resolved`, rejecting illegal transitions and requiring mitigation before `Mitigated`/`Resolved` | `THREAT1`, `THREAT2` |
| `AUTOTHREAT2` | STRIDE Taxonomy & Severity Matrix | Validates representation and handling of all 6 STRIDE categories (`Spoofing`, `Tampering`, `Repudiation`, `InformationDisclosure`, `DenialOfService`, `ElevationOfPrivilege`) with severity scaling | `THREAT3`, `THREAT4` |
| `AUTOTHREAT3` | Secret & Private Key Scrubbing Invariant | Guarantees automatic redacting of PEM/SSH private keys (`-----BEGIN ... PRIVATE KEY-----`) in title, description, and mitigation fields | `THREAT7`, CWE-312 |
| `AUTOTHREAT4` | Path Traversal & Symlink Defense | Enforces strict path validation (`..` rejection, length limit $\le 1024$, control characters rejection, symlink rejection) | `THREATCONF2`, CWE-22, CWE-59 |
| `AUTOTHREAT5` | Multi-Threaded Concurrency Safety | Validates thread safety and race-free concurrent mutations and queries under multi-threaded load | Kernel Thread Safety |
| `AUTOTHREAT6` | Risk Monotonicity & Composite Scoring | Verifies monotonic increase of composite risk with higher severity counts and attenuation by mitigations | `THREAT5` |
| `AUTOTHREAT7` | Capacity Ceiling & DoS Resistance | Validates rejection of threat additions beyond configured capacity limit (`THREAT_ERR_CAPACITY_EXCEEDED`) | `THREATCONF3`, `THREAT8` |
| `AUTOTHREAT8` | Serialization Roundtrip & Invariant Preservation | Validates JSON snapshot serialization roundtripping with preservation of timestamps and metadata | `THREAT6` |
| `AUTOTHREAT9` | Atomic Persistence & Zero-Leak File Handling | Verifies atomic rename persistence, no leftover temp files on error paths, and clean error envelopes | `THREATCONF5` |
| `AUTOTHREAT10` | Canonical Baseline Reset & Idempotent Init | Verifies canonical STRIDE threat seeding and non-destructive overwrite guards unless `force` is asserted | `THREAT1` |

## 3. Test Suites & Execution

### 3.1 Rust Core Automated Test Suite
Located in `code/aiosh-rust/aiosh-core/tests/test_threat_model_automated.rs`:
```bash
cargo test -p aiosh-core --test test_threat_model_automated
```

### 3.2 Cross-Surface Regression Verification
```bash
cargo test -p aiosh-core --test test_threat_model_config
cargo test -p aiosh-core --test test_threat_model_config_integration
cargo test -p aiosh-core --test test_threat_model_service
cargo test -p aiosh-core --test test_threat_model_service_integration
cargo test -p aiosh-mcp -- test_mcp_threat_model
```
