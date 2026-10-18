# Security Review & Proof-of-Restraint Evidence: MCP Server Core Configuration (T-03109)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / configuration
- **Target**: Security review, threat model, abuse scenario analysis, and PoR Invariant I-2 compliance
- **Bindings**: SPEC-MCP-SERVER-CORE-CONFIG, ADR-0035 §AF-2, PoR Invariant I-2

---

## 1. Threat Model & Abuse Scenarios

| Scenario ID | Attack Vector / Abuse Pattern | Target Substrate | Mitigation / Enforcement Mechanism | Status |
|:---|:---|:---|:---|:---|
| **AS-CFG-1** | Path Traversal in `store_path` (e.g. `../../etc/shadow`, `..\\windows\\system32`) | Python & Rust Config | Normalized component validation rejects any path element matching `..` (`MCPCFG-INV1`). | **MITIGATED** |
| **AS-CFG-2** | NUL Byte Poisoning in `store_path` (`.aios/store.json\0evil`) | Python & Rust Config | Rejects any string containing `\0` (`MCPCFG-INV1`). | **MITIGATED** |
| **AS-CFG-3** | Unbounded Memory DoS via Oversized Config File | Config Parser / Loader | File metadata checked before reading; payload strictly capped at 64 KiB (`MAX_CONFIG_FILE_BYTES`). | **MITIGATED** |
| **AS-CFG-4** | Parameter Range Escalation / Resource Exhaustion | Service & Server Config | Strict numerical invariant checking: sessions in `[1, 512]`, timeouts in `[1, 300]`, args in `[1KiB, 10MiB]`. | **MITIGATED** |
| **AS-CFG-5** | State Mutation without Capability Token | Runtime Config | State mutation paths require administrative capability token verification (`ERR_UNAUTHORIZED` / -32002). | **MITIGATED** |
| **AS-CFG-6** | Incomplete Write / File Corruption Race | Persistence (`save_to_file`) | Atomic write via PID-tagged temporary file followed by atomic rename (`os.replace`). | **MITIGATED** |

---

## 2. Proof-of-Restraint Verification (Invariant I-2)

- **Invariant Check**: In accordance with `docs/proof-of-restraint/PLAN.md` Invariant I-2, no state-changing configuration persistence or administrative override can execute without redeeming an active capability grant token.
- **Surface Audit**:
  - `aios_mcp_config_get`: Pure read-only inspection.
  - `aios_mcp_config_validate`: Pure stateless in-memory validation without I/O or state modification.
  - Disk persistence / administrative override: Restricted to authorized administrative calls carrying a valid capability token.
- **Result**: No open bypass. All paths fail closed.
