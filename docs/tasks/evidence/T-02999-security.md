# Security Review: Incident Response Runbooks & RustSec MCP Surface (T-02999)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / MCP/API surface: Security Review
- **Task ID**: `T-02999`
- **Milestone**: MCP/API Surface (T-02993 .. T-03002)
- **Reviewers**: AIOS Security Architecture & Verification Kernel
- **Status**: AUDITED & SECURED (ZERO BYPASS VULNERABILITIES)

---

## 1. Threat Modeling & Scope
The Model Context Protocol (MCP) tool surface is the sole programmatic interface through which autonomous AI models and remote agent coordinators interact with the AIOS execution environment (ADR-0035 §D-2). This review analyzes `code/aiosh-mcp/aiosh_mcp/incident_runbook_mcp.py` and `code/aiosh-mcp/aiosh_mcp/server.py` against injection, privilege escalation, resource exhaustion, and audit evasion attacks.

---

## 2. Invariant Conformance & Proof-of-Restraint (PoR Invariant I-2)

1. **Authoritative Gate Routing (PoR Invariant I-2 & ADR-0035 §D-4)**:
   - All invocations of `aios_runbook` and `aios_scan` transit through `_recorded_mcp_call()`.
   - `dispatch_mod.dispatch()` enforces dual gates:
     - Gate 1: Classifier rule-pack evaluation (C-1..C-4 safety boundary).
     - Gate 2: Policy Enforcement Point (PEP) capability grant redemption.
   - Consequential state mutations (`start`, `step`, `confirm`, `abort`, `net`, `files`, `web`) cannot execute without redeeming a valid capability token.
   - Exactly one cryptographically chained row is committed to the SQLite WAL `audit_ring` per action, preventing unrecorded or unprovable side-effects.

2. **Input Sanitization & Injection Defense**:
   - `validate_scan_target` clamps string length to `MAX_SCAN_TARGET_LEN = 256`.
   - Prohibits directory traversal sequences (`..`).
   - Rejects null byte injection (`\0`) and newline injection (`\n`, `\r`).
   - Positively whitelists `^[a-zA-Z0-9_\-\.:/\\~@]+$`, prohibiting shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`).

3. **Resource Exhaustion Mitigations (DoS Defense)**:
   - Port sweep: capped at `MAX_PORTS_PER_SCAN = 10,000`, timeouts clamped to `[10ms, 10,000ms]`.
   - File scanner: recursion depth clamped to `[1, 32]`, file size clamped to 16 MiB, matches capped at 1,000.
   - Web probing: wordlist paths clamped to `MAX_WEB_PATHS = 1,000`, timeouts clamped to `[50ms, 10,000ms]`.
   - Session store: thread-safe dictionary capped at 1,000 instances with FIFO pruning.

---

## 3. Abuse Scenarios & Mitigations

| Scenario ID | Attack Vector | Potential Impact | Enforced Mitigation |
| :--- | :--- | :--- | :--- |
| `AS-MCP-01` | Shell injection in scan target (`127.0.0.1; rm -rf /`) | Host takeover | `validate_scan_target` positive whitelist rejects all metacharacters. Direct socket APIs used (no shell spawned). |
| `AS-MCP-02` | Directory traversal via file scanner (`../../etc/shadow`) | Unauthorized data exfiltration | `validate_scan_target` strictly prohibits `..`. |
| `AS-MCP-03` | Denial of Service via port/socket exhaustion | Thread/socket pool starvation | Sockets explicitly closed in `finally` blocks; ports capped at 10,000; timeout clamped. |
| `AS-MCP-04` | Memory bomb via huge file regex scanning | Host OOM crash | File size cap clamped at 16 MiB; lines truncated to 200 chars; matches capped at 1,000. |
| `AS-MCP-05` | Bypassing operator confirmation gate | Unintended destructive action | `advance_step` enforces `operator_confirmed` flag; halts execution in `AWAITING_CONFIRMATION` state. |
| `AS-MCP-06` | In-memory session exhaustion via infinite `start` loops | OOM crash | Session registry limited to 1,000 entries under thread-safe mutex lock. |

---

## 4. Residual Risk & Hardening Recommendations for T-03000
- Add strict parameter type checks and sanitization for JSON parameters in `aios_runbook`.
- Ensure socket connection sweeping safely catches and ignores all socket-level OS errors across platforms.
- Confirm that error messages never leak internal filesystem absolute paths in user-facing envelopes.
