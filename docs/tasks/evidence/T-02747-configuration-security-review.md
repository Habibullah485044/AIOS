# Evidence: T-02747 — Threat Model Configuration Security Review

## Task Metadata
- **Task ID**: T-02747
- **Title**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / configuration: Security Review
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Status**: Completed
- **Date**: 2026-10-03
- **Artifact Path**: `docs/tasks/evidence/T-02747-configuration-security-review.md`

## Executive Summary
A comprehensive security review of the Threat Model Configuration subsystem (`code/aiosh-rust/aiosh-core/src/threat_model_config.rs`) was performed. The evaluation covered environment parameter sanitization, input validation bounds, directory traversal defenses, memory consumption caps, and audit integration. Zero security policy bypasses or unhandled failure vectors were identified.

## Threat Vector & Abuse Scenario Analysis

### Abuse Scenario 1: Untrusted Environment Variable Tampering (CWE-15)
- **Attack Vector**: An adversary with partial process control modifies environment variables (`AIOS_THREAT_CAPACITY`, `AIOS_THREAT_MODEL_PATH`, `AIOS_THREAT_MODEL_CONFIG`) to point to sensitive system files (`/etc/passwd` or SAM registry) or set capacity to 0 / infinity to induce denial of service.
- **Defense Mechanism**:
  - `from_env()` performs strict sanitization:
    - Path inputs are sanitized to exclude control characters and directory traversal (`..`).
    - Path length capped at 1024 bytes.
    - Numerical capacity inputs are parsed and clamped strictly within `[MIN_MAX_THREAT_CAPACITY..=MAX_MAX_THREAT_CAPACITY]` (`[1, 4096]`). Invalid numbers fall back to safe defaults.
- **Verdict**: SECURE (attack mitigated).

### Abuse Scenario 2: Path Traversal & Symlink Attacks (CWE-22)
- **Attack Vector**: An attacker crafts a configuration file or config path targeting symlinks or directory escapes (`../../sensitive/threats.json`).
- **Defense Mechanism**:
  - `validate()` disallows `..` and control characters in `store_path`.
  - `load_from_path()` inspects file metadata using `std::fs::symlink_metadata()` and immediately rejects any file that is a symbolic link.
  - MCP `aios.threat.config` rejects any `config_path` containing `..`.
- **Verdict**: SECURE (attack mitigated).

### Abuse Scenario 3: Resource Exhaustion via Config Flooding (CWE-400)
- **Attack Vector**: An attacker points the configuration loader to a special character device (`/dev/urandom`) or a massive 10 GB file to exhaust memory.
- **Defense Mechanism**:
  - `load_from_path()` checks metadata length prior to reading, rejecting any file larger than `MAX_CONFIG_FILE_BYTES` (64 KiB) with a `THREATCONF_ERR_BOUNDS` error.
- **Verdict**: SECURE (attack mitigated).

### Abuse Scenario 4: Silent Failure & Audit Evasion (CWE-778)
- **Attack Vector**: An operator or agent modifies configuration without leaving an audit record.
- **Defense Mechanism**:
  - All MCP interactions via `aios.threat.config` pass through `dispatch::recorded_call`.
  - Every inspection or validation emits an immutable row into the SQLite `audit_ring` table with cryptographic hash chaining.
- **Verdict**: SECURE (attack mitigated).

## Audit Findings Matrix
| Weakness ID | Description | Severity | Mitigation Status |
| :--- | :--- | :--- | :--- |
| **CWE-15** | External Control of Configuration | High | Mitigated (environment variable clamping & validation) |
| **CWE-20** | Improper Input Validation | High | Mitigated (strict `validate()` method & boundary limits) |
| **CWE-22** | Path Traversal | High | Mitigated (symlink rejection, `..` disallowed) |
| **CWE-400** | Resource Exhaustion | High | Mitigated (64 KiB config size limit) |
| **CWE-778** | Insufficient Logging | High | Mitigated (PEP dispatch & audit ring recording) |

## Conclusion
The Threat Model Configuration subsystem satisfies all Phase 2 security kernel requirements. No open security defects remain.
