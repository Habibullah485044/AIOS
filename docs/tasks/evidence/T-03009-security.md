# Security Review: Incident Response Runbooks Configuration (T-03009)

## Executive Summary
- **Target**: Incident Response Runbooks Configuration Substrate (`aiosh-core::runbook_config` and `aiosh_mcp.runbook_config`).
- **Phase**: Phase 2 — Security Kernel & PEP Fabric.
- **Reviewer**: Antigravity Security Agent.
- **Verdict**: PASS (Zero critical or high findings; fail-closed defaults enforced across both substrates).

---

## Scope & Architectural Alignment
The Incident Response Runbooks configuration subsystem provides 4-level precedence resolution (Argument Overrides → Environment Variables → Configuration File → Built-in Defaults) for runbook catalogs, timeouts, concurrency limits, and operator confirmation flags.

Per AIOS Security Policy and PEP Invariants:
1. **Zero Dynamic Runtime Mutation via MCP**: Configuration is immutable at runtime over the RPC/MCP interface; `aios_runbook(action="config")` is strictly read-only.
2. **PEP Dispatch & Audit Invariant**: All `runbook.config` queries are routed through the authoritative dispatch gate and recorded in the SQLite audit ring (`audit_ring`).
3. **Fail-Closed Resolution**: Corrupted configuration files, non-UTF-8 payloads, and oversized files fail closed with standardized error envelopes (`RUNBOOKCONF_ERR_*`).

---

## Threat Modeling & Abuse Scenarios

### AS-CONFIG-01: Path Traversal in Configuration or Catalog Paths (CWE-22)
- **Vector**: Malicious actor provides `../../etc/shadow`, `..\\..\\Windows\\System32`, or similar traversal sequences in `--config`, `AIOSH_RUNBOOK_CONFIG`, or `catalog_path`.
- **Defense-in-Depth**:
  - `validate_config_path` in both Rust (`runbook_config.rs`) and Python (`runbook_config.py`) performs strict containment checking for `..` tokens.
  - Path length clamped to `MAX_CONFIG_PATH_LEN` (1024 bytes).
  - Traversal attempts return fail-closed error `RUNBOOKCONF_ERR_PATH_TRAVERSAL`.

### AS-CONFIG-02: Pre-Allocation & Resource Exhaustion via Oversized Configs (CWE-400)
- **Vector**: Attacker links config path to multi-gigabyte file, named pipe, or `/dev/urandom` to cause OOM or freeze parser.
- **Defense-in-Depth**:
  - Size check enforced strictly before reading and parsing (`MAX_CONFIG_FILE_BYTES` = 64 KiB).
  - Stream readers strictly bounded to 65,537 bytes.
  - Files exceeding 64 KiB fail closed with `RUNBOOKCONF_ERR_FILE_SIZE`.

### AS-CONFIG-03: Memory Exhaustion via Extreme Session Limits (CWE-770)
- **Vector**: Malicious config specifies `max_active_sessions: 1000000000` to allocate millions of session state objects.
- **Defense-in-Depth**:
  - `max_active_sessions` clamped between `MIN_MAX_ACTIVE_SESSIONS` (1) and `MAX_MAX_ACTIVE_SESSIONS` (10,000).
  - Memory consumption is deterministically bounded to less than 15 MiB even at maximum saturation.

### AS-CONFIG-04: Automated Execution Bypass of High-Risk Remediation Actions
- **Vector**: Configuration overrides set `require_operator_confirmation: false` to force unattended execution of destructive mitigation steps (e.g. process SIGKILL, network interface isolation).
- **Defense-in-Depth**:
  - Invariant: The execution service state machine (`RunbookExecutionSession::advance_step`) explicitly checks `(step_def.requires_confirmation || step_def.is_high_risk()) && !self.operator_confirmed`.
  - High-risk operations classified as destructive cannot bypass human-in-the-loop approval, maintaining fail-safe containment.

### AS-CONFIG-05: Control Character & Null Byte Injection (CWE-15 / CWE-20)
- **Vector**: Injection of `\0`, `\r`, `\n`, or terminal escape codes into path variables.
- **Defense-in-Depth**:
  - `hygiene_ok` validates every path character against ASCII control characters (`ord < 32 || ord == 127`), returning `false` and triggering fallback or error envelope.

---

## Proof-of-Restraint Verification (PoR Invariant I-2)
- **Invariant I-2 Check**: "Consequential/state-changing operations cannot execute without redeeming a capability token."
- **Analysis**:
  - `action="config"` is strictly read-only and emits an informational audit record.
  - Consequential actions (`start`, `step`, `confirm`, `abort`) remain under PEP write-gate protection requiring active grants or approved operator interaction tokens.
  - No policy bypass or unauthenticated state modification was detected.
