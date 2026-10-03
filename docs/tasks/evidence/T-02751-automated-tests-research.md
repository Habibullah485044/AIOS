# Research: Threat Model Automated Test Vectors (T-02751)

## 1. Overview & Objective
This research establishes the test design, invariants, authoritative citations, and formal verification vectors for automated testing of the Threat Model Maintenance subsystem (`T-02751`..`T-02760`), ensuring conformance with ADR-0035, ADR-0036, NIST SP 800-154, and Microsoft STRIDE methodologies.

## 2. Authoritative Sources & Citations
- **Microsoft STRIDE Threat Modeling**: Shostack, Adam. *Threat Modeling: Designing for Security* (Wiley, 2014). Defines the 6 core threat categories: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.
- **NIST SP 800-154**: *Guide to Data-Centric System Threat Modeling*. Mandates explicit threat cataloging, mitigation traceability, and risk prioritization.
- **ADR-0035**: PEP Fabric and Audit Ring Invariant Specifications. Requires that all queries and mutations write immutable audit events.
- **ADR-0036**: Security Architecture & Invariant Rulesets (`THREAT1`..`THREAT8`, `THREATCONF1`..`THREATCONF5`).
- **CWE-59**: Improper Link Resolution (Symbolic Link Following).
- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal).
- **CWE-312 / CWE-532**: Cleartext Storage / Logging of Sensitive Information (Private Key Exposure).

## 3. Fact vs. Assumption Separation

| Item | Status | Details |
|---|---|---|
| STRIDE Enumeration | **Fact** | All 6 STRIDE categories are implemented in `ThreatCategory` enum in `threat_model_data_model.rs`. |
| Lifecycle Transitions | **Fact** | `ThreatStatus` allows transitions from Identified -> UnderReview -> Mitigated -> Accepted -> Resolved; invalid transitions return `THREAT_ERR_INVALID_TRANSITION`. |
| Private Key Scrubbing | **Fact** | `ThreatEntry::new` automatically identifies and sanitizes PEM private key headers (`-----BEGIN ... PRIVATE KEY-----`). |
| Multi-Threaded Concurrency | **Fact** | Thread safety requires `Arc<Mutex<ThreatModelService>>` or read-copy-update semantics across concurrent threads. |
| Configuration Bounds | **Fact** | Max threats capped at 4096; max store size capped at 16 MiB. |
| Test Execution Framework | **Fact** | Automated test suite in `aiosh-core/tests/test_threat_model_automated.rs` integrates natively with `cargo test`. |
| Integration with PEP | **Assumption** | In automated test vectors, service operations can be evaluated both in isolated units and wrapped in MCP dispatch contexts. |

## 4. Formal Verification Vectors (AUTOTHREAT1..AUTOTHREAT8)
1. **`AUTOTHREAT1`**: Full Threat Lifecycle & Invariant Transitions (Identified -> UnderReview -> Mitigated -> Accepted -> Resolved; mitigation required for Mitigated/Resolved).
2. **`AUTOTHREAT2`**: STRIDE Categorization & Severity Matrix (Validation across all 6 STRIDE classes and Low/Medium/High/Critical severities).
3. **`AUTOTHREAT3`**: Secret / Private Key Scrubbing Defense (Scrubbing RSA, EC, and OPENSSH private key blocks in titles, descriptions, and mitigation fields).
4. **`AUTOTHREAT4`**: Path Traversal & Symlink Defense (Validation rejection of `../`, absolute paths outside boundaries, control characters, and symlinks).
5. **`AUTOTHREAT5`**: Concurrent Concurrency & Disk Persistence Atomicity (Multi-threaded mutation without race conditions or torn writes).
6. **`AUTOTHREAT6`**: Composite Risk Monotonicity (Risk score increases monotonically as severities increase or statuses degrade).
7. **`AUTOTHREAT7`**: Capacity Boundary & DoS Resistance (Capping catalog at capacity limit, rejecting over-capacity additions with explicit error).
8. **`AUTOTHREAT8`**: Snapshot Roundtrip & Schema Invariant Preservation (Complete JSON serialization/deserialization integrity).

## 5. Unknowns & Explicit Decisions
- **Decision 1**: Vectors `AUTOTHREAT1`..`AUTOTHREAT8` will be implemented in a dedicated test file `code/aiosh-rust/aiosh-core/tests/test_threat_model_automated.rs`.
- **Decision 2**: Tests will run standalone under standard `cargo test -p aiosh-core --test test_threat_model_automated` with zero external network or OS-level dependencies.
