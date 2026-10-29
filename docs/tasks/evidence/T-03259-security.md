# T-03259 Security Review: Model Backend Adapters Recovery & Validation

## Scope & Target
- Target: `code/aiosh-mcp/aiosh_mcp/model_backend_adapters_recovery.py`
- MCP Surface: `aios_model_validate_config`, `aios_model_recover_config`
- Standard: ADR-0035 §D-2, Proof-of-Restraint Invariant I-2, CWE-22, CWE-400

---

## Threat Matrix & Abuse Scenarios

| Scenario ID | Attack Vector | Risk | Mitigation | Status |
|-------------|---------------|------|------------|--------|
| SEC-MODRECV-01 | Path traversal & arbitrary file quarantine via `config_path` (`../../etc/hosts`) | Critical | `validate_model_store_path` strictly rejects `..`, NUL bytes (`\0`), alternate data streams (`:`), Windows reserved devices (`CON`, `PRN`, `AUX`, `NUL`), and lengths > 1024. | Mitigated |
| SEC-MODRECV-02 | Unauthorized recovery / config tampering without token | High | `recover_config_file` enforces mandatory capability token presence (PoR Invariant I-2); missing/empty token raises `MODRECV_ERR_UNAUTHORIZED` fail-closed. | Mitigated |
| SEC-MODRECV-03 | Denial of Service via oversized config files (100+ MB payload) | Medium | File size bounded at `MAX_CONFIG_FILE_BYTES = 10 MiB`. Oversized files fail validation without memory exhaustion. | Mitigated |
| SEC-MODRECV-04 | Path leakage and filesystem structure disclosure in error messages | Low | `sanitize_error_message` regex scrubs absolute filesystem paths, replacing them with `[REDACTED_PATH]`. | Mitigated |
| SEC-MODRECV-05 | Race conditions during concurrent config recovery | Medium | Writes to unique temp file `<target>.tmp.<pid>` before atomic `os.replace`, guaranteeing no partially-written state. | Mitigated |

---

## Proof-of-Restraint (PoR) Verification (Invariant I-2)
- State-changing paths: `recover_config_file` modifies filesystem state (quarantine, backup, overwrite).
- Token redemption verification: Verified that `recover_config_file` strictly requires a non-empty `capability_token`. Invoking without token triggers immediate `MODRECV_ERR_UNAUTHORIZED`.
- Read paths: `validate_config_file` is strictly read-only and consumes 0 capability tokens.

---

## Conclusion
The security review found no open vulnerabilities or policy bypasses. The recovery and validation subsystem satisfies all security and Proof-of-Restraint invariants.
