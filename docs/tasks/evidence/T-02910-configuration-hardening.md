# T-02910 — Compliance Mapping / configuration: Hardening

**Task ID**: T-02910 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / configuration: Hardening)  
**Depends on**: T-02909 (Security Review — `docs/tasks/evidence/T-02909-security.md`)  
**Contract**: `docs/tasks/evidence/T-02904-spec.md`  
**Date**: 2026-10-10  
**Status**: COMPLETE — Hardened Compliance Mapping configuration loading against directory path exploits, non-UTF-8 payload parsing, resource exhaustion, and unhandled I/O failures across Python and Rust substrates.

---

## 1. Summary of Changes

| Substrate | File | Hardening Change |
|---|---|---|
| **Python / MCP** | `code/aiosh-mcp/aiosh_mcp/compliance_config.py` | Added explicit `os.path.isdir()` check returning `COMPLIANCECONF_ERR_IO`; trapped `UnicodeDecodeError` mapping to `COMPLIANCECONF_ERR_PARSE`; trapped `OSError` mapping to `COMPLIANCECONF_ERR_IO`. |
| **Rust / Core** | `code/aiosh-rust/aiosh-core/src/compliance_config.rs` | Added `if meta.is_dir()` validation returning `COMPLIANCECONF_ERR_IO: path is a directory` before file read. |
| **Python Tests** | `code/aiosh-mcp/tests/test_compliance_config.py` | Added `test_config_directory_path_fails_closed` and `test_config_non_utf8_fails_closed` unit tests (23/23 tests passing). |

---

## 2. Hardening Verifications

1. **Size Caps & Memory Bounds**:
   - `MAX_CONFIG_FILE_BYTES = 64 * 1024` enforced pre-parse on both substrates.
   - Bounded read `read(MAX_CONFIG_FILE_BYTES + 1)` prevents memory exhaustion.

2. **Standard Error Envelopes**:
   - Directory paths supplied as config files fail closed with `COMPLIANCECONF_ERR_IO`.
   - Corrupted non-UTF8 binary files fail closed with `COMPLIANCECONF_ERR_PARSE`.
   - File size violations fail closed with `COMPLIANCECONF_ERR_FILE_SIZE`.
   - Traversal attempts fail closed with `COMPLIANCECONF_ERR_PATH_TRAVERSAL` or are safely dropped to `env_invalid`.

3. **Resource Leak Checks**:
   - All file descriptors are managed via Python context managers (`with open(...) as f`) and Rust scoped ownership (`File::open(...)`), guaranteeing zero file descriptor leaks on failure paths.

4. **Proof of Restraint (Invariant I-2)**:
   - Config loading remains completely read-only and side-effect free.
   - All state-changing mutation paths require active capability tokens with pre-execution redemption.

---

## 3. Test Battery Verification

- Python unit tests (`test_compliance_config.py`): 23 passed in 2.52s.
- Rust unit tests (`cargo test -p aiosh-core --lib compliance_config`): 6 passed in 0.07s.
