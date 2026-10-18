# Security Review: AI Control Plane MCP Server Core CLI Surface (T-03089)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / CLI surface
- **Task ID**: `T-03089`
- **Specification Document**: `docs/SPEC-MCP-SERVER-CORE-CLI.md`

## 1. Threat Modeling & Abuse Scenarios

| ID | Threat Vector | CWE | Attack Surface | Mitigation & Enforcement | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AS-01** | Privilege Escalation / Capability Bypass | CWE-285 | `aiosh mcp dispatch aios.admin.*` | Privileged administrative namespace (`aios.admin.*`) strictly requires `--grant <TOKEN>`. Unauthenticated attempts fail closed with `EXIT_UNAUTHORIZED = 3` before dispatch. | MITIGATED |
| **AS-02** | Denial of Service via Payload Flooding | CWE-400 | `aiosh mcp dispatch --args <JSON>` | Pre-parse boundary check enforces `MAX_ARGUMENTS_SIZE = 1 MiB` (`1,048,576` bytes). Payloads exceeding boundary return `EXIT_USAGE = 2` without allocating memory. | MITIGATED |
| **AS-03** | Execution Starvation via Unbounded Timeouts | CWE-400 | `aiosh mcp dispatch --timeout <S>` | Timeout values clamped to `[1s, 300s]` (`MAX_EXECUTION_TIMEOUT_SECONDS`). Prevents resource exhaustion from runaway or malicious wait states. | MITIGATED |
| **AS-04** | ANSI Escape & Trojan Source Injection | CWE-116 | CLI output rendering (`show`, `list`) | Identifiers and schemas strictly reject ASCII control characters (`\x00..\x1F`, `\x7F`) and Unicode bidirectional override codepoints (`\u202A..\u202E`, `\u2066..\u2069`). | MITIGATED |
| **AS-05** | Audit Evasion & Shadow Dispatches | CWE-778 | Unlogged CLI executions | Invariant `MCPCLI-INV5`: Every execution pathway (success, failure, usage error) commits an immutable audit row into the SQLite WAL `AuditRing` via `classify_and_emit`. | MITIGATED |

## 2. Proof-of-Restraint (PoR) Conformance Verification
- **Invariant I-2 (Redeem-Before-Act)**: Certified zero bypass paths exist for privileged tools. Invocations of administrative operations without an explicit grant token are blocked before execution begins.
- Confirmed that rejection paths emit honest audit rows (`exit_status: "failure"`) preserving the full command context in `audit.db`.

## 3. Hardening Recommendations for T-03090
1. **NUL Byte Stripping in CLI Arguments**: Explicitly scan `--args` and `--filter` parameters to reject embedded NUL bytes (`\0`) before JSON parsing.
2. **Deterministic Error Envelope Guarantee**: Ensure malformed JSON arguments return standardized `McpCoreResultEnvelope` in `--json` mode rather than plain stderr messages.
3. **Session Parameter Bounding**: Impose length limits on `--prune` duration to avoid integer overflow issues.
