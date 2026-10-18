# Security Review Evidence: AI Control Plane MCP Server Core Recovery & Validation (T-03159)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / recovery & validation
- **Artifact**: `docs/tasks/evidence/T-03159-recovery-validation-security-review.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MCP-SERVER-CORE-RECOVERY

---

## 1. Threat Modeling & Abuse Scenario Assessment

We evaluated 5 realistic threat vectors against the MCP Server Core Recovery & Validation Subsystem:

### Scenario 1: Path Traversal & Arbitrary File Read/Write (CWE-22)
- **Attack Vector**: An adversary supplies a crafted path containing `..`, absolute traversal, or alternate data streams (`../../../etc/passwd` or `..\\Windows\\System32\\config`) to `aios_mcp_recovery_check` or `aios_mcp_recovery_repair`.
- **Analysis**:
  - `validate_store_path` enforces strict input validation: bounded string length (`<= 1024`), NUL byte checks (`\0`), and directory traversal detection (`".." in p.parts`).
  - Any traversal attempt immediately raises `ValueError(MCPRECV_ERR_INVALID_PATH)` fail-closed before any filesystem I/O is attempted.
- **Verdict**: **MITIGATED** (Enforces `MCPRECV-INV4`).

### Scenario 2: Unauthenticated State Mutation & PoR Invariant I-2 Bypass (CWE-306 / CWE-862)
- **Attack Vector**: An unprivileged caller invokes `aios_mcp_recovery_repair` without a capability token to overwrite or reset active session and configuration stores.
- **Analysis**:
  - `recover_mcp_store` gates execution strictly behind `capability_token`.
  - Empty, null, or whitespace tokens trigger `PermissionError` (`MCPRECV_ERR_UNAUTHORIZED`).
  - Read-only operations (`validate_mcp_store`, `aios_mcp_recovery_check`) require zero tokens, preserving zero-cost observation without write escalation.
- **Verdict**: **MITIGATED** (Strict conformance to PoR Invariant I-2).

### Scenario 3: Denial-of-Service via Unbounded File Size & Memory Exhaustion (CWE-400 / CWE-770)
- **Attack Vector**: An attacker provides a multi-gigabyte corrupted state file or endless stream to exhaust system RAM during validation.
- **Analysis**:
  - `validate_mcp_store` inspects file metadata (`p.stat().st_size`) prior to opening or reading the file.
  - Files exceeding `MAX_STORE_FILE_BYTES` (10 MiB) are flagged with issue code `BOUNDS_EXCEEDED` and marked unhealthy without loading into memory.
- **Verdict**: **MITIGATED**.

### Scenario 4: Insecure Forensics Quarantine Permissions & Information Disclosure (CWE-732)
- **Attack Vector**: Quarantined backup files (`<path>.bak.<timestamp>`) created with world-readable permissions (e.g. `0644`), leaking session secrets or credentials to unprivileged local users.
- **Analysis**:
  - `recover_mcp_store` invokes `os.chmod(backup_p, 0o600)` immediately after copying, restricting access exclusively to the owner.
  - Timestamped backup naming prevents race collisions.
- **Verdict**: **MITIGATED** (Enforces `MCPRECV-INV3`).

### Scenario 5: Race Condition & Truncated Writes during Recovery Reinitialization (CWE-367 / CWE-377)
- **Attack Vector**: Process termination or concurrent writes during recovery leaving an empty or half-written state store on disk.
- **Analysis**:
  - The recovery routine writes initial canonical JSON into a unique temporary file (`.tmp.<pid>.<timestamp_ns>`).
  - It utilizes atomic filesystem replacement (`os.replace`) to update the target path, ensuring all-or-nothing consistency.
- **Verdict**: **MITIGATED**.

---

## 2. Proof-of-Restraint Invariant I-2 Audit

- **Read Operations**: `aios_mcp_recovery_check` and `validate_mcp_store` are purely read-only, produce zero mutations, and require zero capability tokens.
- **Mutation Operations**: `aios_mcp_recovery_repair` and `recover_mcp_store` alter state and strictly require a capability token grant.
- **Audit Logging**: Errors and unauthorized attempts fail closed with sanitized error envelopes.
