# Specification: Compliance Mapping Automated Tests (SPEC-COMPLIANCE-AUTOMATED-TESTS)

- **Status**: IMPLEMENTED & VERIFIED
- **Date**: 2026-10-11
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Compliance Mapping Automated Tests
- **Binding**: ADR-0035 §F-2, ADR-0037 Invariant I-2, `docs/tasks/evidence/T-02914-spec.md`
- **Tasks**: T-02913 (Research), T-02914 (Spec), T-02915 (Scaffold), T-02916 (Impl), T-02917 (Unit Test), T-02918 (Integration), T-02919 (Security Review), T-02920 (Hardening), T-02921 (Documentation), T-02922 (Verification & Evidence)

---

## 1. Overview

The Compliance Mapping automated test suite provides deterministic verification of compliance catalog lifecycle transitions, multi-standard taxonomy coverage (NIST SP 800-53 Rev 5, SOC 2 Type II, ISO 27001:2022, CIS Controls v8, HIPAA Security, PCI DSS v4), duplicate control rejection, boundary validation, 4-level configuration ladder resolution, CWE-15/CWE-22 path traversal defense, pre-parse size caps (CWE-400), audit logging immutability, Proof-of-Restraint PEP capability gating (Invariant I-2), and atomic persistence.

---

## 2. Test Vectors (`AUTOCOMPLIANCE1`..`AUTOCOMPLIANCE10`)

| Vector ID | Name | Description | Invariants Tested | Status |
|:---|:---|:---|:---|:---|
| `AUTOCOMPLIANCE1` | Full Compliance Lifecycle & Status Transitions | Verifies transitions across `non_compliant` -> `partially_compliant` -> `compliant` and `not_applicable`, requiring mitigation justification before transition to `compliant` | `COMPLY1`, `COMPLY2` | **VERIFIED** |
| `AUTOCOMPLIANCE2` | Duplicate Control & Collision Rejection | Guarantees primary key uniqueness for mapping identifiers; duplicate attempts fail closed with `COMPLIANCE_ERR_DUPLICATE_ID` with zero store mutation | `COMPLY3`, Primary Key Integrity | **VERIFIED** |
| `AUTOCOMPLIANCE3` | Identifier, Text & Array Bounds Validation | Enforces strict bounds: ID $\le 64$ chars, title $\le 128$ bytes, description $\le 2048$ bytes, threat IDs $\le 16$, tags $\le 16$, catalog capacity $\le 1024$ | `COMPLY4`, CWE-1284 | **VERIFIED** |
| `AUTOCOMPLIANCE4` | 4-Level Precedence Ladder Resolution | Asserts deterministic precedence: explicit argument (`--path`) > environment variable (`AIOSH_COMPLIANCE_MAP_PATH`) > config file (`--config` / `AIOSH_COMPLIANCE_CONFIG`) > default store | `COMPLYCONF1`, Deterministic Hierarchy | **VERIFIED** |
| `AUTOCOMPLIANCE5` | CWE-15 / CWE-22 Hygiene Predicate Defense | Rejects directory traversal (`..`), null bytes (`\0`), control characters, empty strings, and paths $> 1024$ chars via `hygiene_ok()` | `COMPLYCONF2`, CWE-15, CWE-22 | **VERIFIED** |
| `AUTOCOMPLIANCE6` | Pre-Parse File Size Bounds & CWE-400 DoS Defense | Prevents memory exhaustion via pre-parse byte bounds (64 KiB config file cap, 1 MiB store cap) before JSON deserialization | `COMPLYCONF3`, CWE-400 | **VERIFIED** |
| `AUTOCOMPLIANCE7` | Audit Immutability & Audit Logging Guarantee | Enforces immutable mutation logging: attempts to set `audit_all_mutations: false` clamp to `true`; mutating calls write to `audit_ring` | `COMPLYCONF4`, ADR-0035 §F-2 | **VERIFIED** |
| `AUTOCOMPLIANCE8` | Proof of Restraint & PEP Gating (Invariant I-2) | Enforces single-use capability token redemption (`grant_id`); ungranted mutating requests are refused fail-closed (`PEP_DENIED`) | `ADR-0037`, PoR Invariant I-2 | **VERIFIED** |
| `AUTOCOMPLIANCE9` | Assessment Scoring & Statistics Consistency | Computes coverage percentages (`(compliant / total) * 100`) and orders compliance gap control IDs across filtered frameworks | Mathematical Consistency | **VERIFIED** |
| `AUTOCOMPLIANCE10` | Concurrency Safety & Atomic Persistence | Validates atomic file write and rename via temporary file staging (`.tmp.<nanos>`), rollback on error, and traversal path rejection in `validate_path` | `COMPLY5`, ACID Storage | **VERIFIED** |

---

## 3. Test Suites & Invocation

### 3.1 Python MCP Test Suites
Run the automated smoke, unit, and end-to-end integration tests:
```bash
# Automated smoke suite (Vectors AUTOCOMPLIANCE1..10)
python -m pytest code/aiosh-mcp/tests/test_compliance_automated_smoke.py -v

# Automated unit suite (Four quadrants: valid, invalid, bounds, primary failure)
python -m pytest code/aiosh-mcp/tests/test_compliance_automated_unit.py -v

# Cross-substrate wire integration suite (MCP over wire stdio + Rust CLI)
python -m pytest code/aiosh-mcp/tests/test_compliance_integration.py -v
```

### 3.2 Rust Core Automated Test Suites
Run the Rust test binaries:
```bash
# Automated test vectors suite
cargo test -p aiosh-core --test test_compliance_automated

# Dedicated automated unit suite
cargo test -p aiosh-core --test test_compliance_automated_unit
```

---

## 4. Copy-Pasteable Usage Examples

### 4.1 CLI Command Line Example
```bash
# 1. Initialize store with canonical baseline
aiosh compliance init --path test_compliance_map.json

# 2. Register mapping under SOC 2 Type II
aiosh compliance register \
  --id MAP-SOC2-CC61 \
  --control CC6.1 \
  --framework soc2 \
  --target-type pep_gate \
  --target-ref pep.boundary.firewall \
  --mitigation "Enforce edge egress firewall filters" \
  --path test_compliance_map.json

# 3. Transition control status to compliant
aiosh compliance status MAP-SOC2-CC61 compliant \
  --reason "Firewall rule verified by audit" \
  --path test_compliance_map.json

# 4. Generate framework assessment report
aiosh compliance assess --framework soc2 --json --path test_compliance_map.json
```

### 4.2 Python / MCP Wire Tool Call Example
```python
from aiosh_mcp import compliance

# Assess NIST framework compliance
result = compliance.execute(
    action="assess",
    framework="nist_sp_800_53_rev5"
)
print("Compliance report:", result["report"])
```

---

## 5. Constraints & Known Limitations
1. **Catalog Capacity Ceiling**: Hard cap of 1,024 entries per store (`MAX_COMPLIANCE_ENTRIES_CAPACITY`) to guarantee bounded memory and execution time.
2. **Mitigation Mandatory for Compliant Status**: Status `compliant` cannot be set without an accompanying mitigation summary or transition reason.
3. **Audit Immutability**: Mutation auditing (`audit_all_mutations`) cannot be disabled through configuration files or runtime parameters.
4. **Pre-Parse File Size Bounds**: Store files > 1 MiB (or 16 MiB max clamp) and config files > 64 KiB fail closed before parsing.

---

## 6. Evidence Cross References
- [Research Evidence (T-02913)](tasks/evidence/T-02913-research.md)
- [Specification Evidence (T-02914)](tasks/evidence/T-02914-spec.md)
- [Scaffold Evidence (T-02915)](tasks/evidence/T-02915-automated-tests-scaffold.md)
- [Implementation Evidence (T-02916)](tasks/evidence/T-02916-automated-tests-implementation.md)
- [Unit Test Evidence (T-02917)](tasks/evidence/T-02917-automated-tests-unit-test.md)
- [Integration Evidence (T-02918)](tasks/evidence/T-02918-automated-tests-integration.md)
- [Security Review Evidence (T-02919)](tasks/evidence/T-02919-security.md)
- [Hardening Evidence (T-02920)](tasks/evidence/T-02920-automated-tests-hardening.md)
