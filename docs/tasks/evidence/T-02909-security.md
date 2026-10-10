# Security Review: Compliance Mapping Configuration (T-02909)

**Task ID**: T-02909  
**Component**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / configuration: Security Review  
**Auditor**: Antigravity Security & PEP Kernel Auditor  
**Date**: 2026-10-10  
**Scope**: `code/aiosh-mcp/aiosh_mcp/compliance_config.py`, `code/aiosh-rust/aiosh-core/src/compliance_config.rs`, `code/aiosh-rust/aiosh-cli/src/main.rs`, `code/aiosh-mcp/aiosh_mcp/server.py`  
**Normative Spec**: `docs/tasks/evidence/T-02904-spec.md`  

---

## 1. Executive Summary

This security review audits the configuration subsystem for Compliance Mapping across both Python (MCP) and Rust (CLI / core) substrates. The configuration subsystem introduces a 4-level precedence ladder (`--path > AIOSH_COMPLIANCE_MAP_PATH > config file (--config / AIOSH_COMPLIANCE_CONFIG / default) > default store`).

The review confirms that:
1. All path inputs from untrusted sources (environment variables, config files) are filtered through a strict CWE-15 / CWE-22 hygiene gate (`hygiene_ok`).
2. Config file ingestion enforces pre-parse size limits (64 KiB), preventing CWE-400 memory exhaustion attacks.
3. Numerical bounds are clamped within declared limits, preventing allocation explosions.
4. Mutation auditing (`audit_all_mutations`) cannot be disabled via configuration—any attempt to set `audit_all_mutations: false` is forced to `true`.
5. Configuration resolution is completely side-effect-free (creates no files, mutates no databases).
6. [PoR] Invariant I-2 is preserved: all state-changing operations continue to require valid capability tokens with pre-execution redemption.

---

## 2. Threat Modeling & Abuse Scenarios

| Threat ID | Threat Vector | Attack Scenario | Impact | Mitigation / Status |
|---|---|---|---|---|
| **TV-CONF-01** | **Path Traversal via Environment Variable** (CWE-22 / CWE-15) | Attacker injects `AIOSH_COMPLIANCE_MAP_PATH=../../../../etc/shadow` or `AIOSH_COMPLIANCE_CONFIG=../../malicious.json`. | Directory escape / unauthorized file reference | **MITIGATED**: `hygiene_ok()` validates that strings contain no `..`, no control chars (`< 32` or `127`), and `len <= 1024`. Invalid paths are classified as `env_invalid` and rejected, falling back to safe defaults. |
| **TV-CONF-02** | **Memory Exhaustion via Malicious Config** (CWE-400) | Attacker drops a 500 MB JSON file as `docs/compliance_config.json` or points `--config` to a huge file to exhaust memory during `json.loads` or `serde_json`. | Verifier / Agent DoS | **MITIGATED**: `MAX_CONFIG_FILE_BYTES = 64 * 1024` (64 KiB) cap enforced **before** JSON parsing via file size check and bounded read. Exceeding files fail closed with `COMPLIANCECONF_ERR_FILE_SIZE`. |
| **TV-CONF-03** | **Suppression of Audit Logging** (CWE-284 / CWE-213) | Attacker writes `{"audit_all_mutations": false}` into the config file attempting to perform unrecorded modifications. | Audit log bypass | **MITIGATED**: Hardcoded immutability rule: `validate()` forces `merged["audit_all_mutations"] = True` regardless of input. Rust `ComplianceConfig` also rejects `audit_all_mutations = false` during validation. |
| **TV-CONF-04** | **Resource Pre-Allocation / Integer Overflow** | Attacker configures `max_entries: 999999999` or `max_store_file_bytes: 107374182400` to trigger out-of-memory allocations. | Memory exhaustion | **MITIGATED**: Inputs are clamped strictly between `[1, 4096]` for `max_entries` and `[4096, 16 MiB]` for `max_store_file_bytes`. Non-integer or negative values revert safely to default constants. |
| **TV-CONF-05** | **Null Byte & Control Character Injection** | Attacker injects null bytes or carriage returns in path strings to trick POSIX vs Windows file APIs. | Inconsistent path resolution | **MITIGATED**: `hygiene_ok` rejects any character where `ord(ch) < 32` (including `\0`, `\r`, `\n`) or `ord(ch) == 127`. |
| **TV-CONF-06** | **Silent Fallback on Explicit Malicious Arguments** | Attacker provides `--path ../../secret.json` via CLI expecting it to be silently sanitized to the default store, obscuring failure. | Silent misconfiguration | **MITIGATED**: Level-1 explicit arguments bypass `hygiene_ok` and flow directly to `validate_path()` which halts execution with an explicit fail-closed error. |

---

## 3. Proof-of-Restraint [PoR] Standing Rule Check (Invariant I-2)

- **Read-Only Invariant**: `compliance_config.resolve()`, `load_config()`, and `from_env()` are strictly read-only and emit no mutations.
- **State-Changing Paths**: Store mutation operations (`add`, `update`, `delete`, `migrate`) are strictly gated in `server.py` and `compliance.py` through PEP permission checks and capability token redemption.
- **Conclusion**: The configuration subsystem introduces zero unauthenticated or unmetered state-changing paths. Invariant I-2 holds unconditionally.

---

## 4. Policy Bypass Status

- **Known Policy Bypasses**: None.
- **Blocking Issues**: None.
- **Remediation Required for T-02910 (Hardening)**:
  - Add explicit bounds testing for edge cases (e.g. symlink handling in config path resolution, file permissions warnings on sensitive config stores).
