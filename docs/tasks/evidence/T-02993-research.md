# Research Evidence: Incident Response Runbooks & RustSec MCP/API Surface (T-02993)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / MCP/API surface: Research
- **Task ID**: `T-02993`
- **Milestone**: MCP/API Surface (T-02993 .. T-03002)
- **Status**: COMPLETE & VERIFIED

---

## 1. Context & Objectives
The goal of this task is to establish facts, constraints, prior art, and interface boundaries for exposing Incident Response Runbooks and the RustSec security scanning substrate over the Model Context Protocol (MCP) tool surface in `aiosh-mcp`.

---

## 2. Authoritative Sources & Standards
1. **Model Context Protocol (MCP) Specification (2025-06-18 stdio transport)**:
   - FastMCP tool registration paradigm (`@mcp.tool()`).
   - JSON-RPC 2.0 tool invocation schema with structured input arguments and dictionary return envelopes.
2. **NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)**:
   - Section 3.2: Incident containment, eradication, and recovery coordination.
   - Section 3.3: Post-incident activity, cryptographic forensic preservation, and structured receipts.
3. **CISA Cybersecurity Incident & Vulnerability Response Playbooks (Nov 2021)**:
   - Standardized execution phases: Preparation, Detection & Analysis, Containment, Eradication, Recovery, Post-Incident.
4. **ADR-0035 §D-2 & ADR-0036 §B-1 (AIOS Architecture Decisions)**:
   - MCP is the sole external model tool surface exposed by AIOS.
   - Every MCP tool call must transit through classifier provenance -> PEP capability redemption -> append-only AuditRing proof-of-receipt logging via `_dispatch.dispatch()` and `_recorded_call()`.
5. **Existing AIOS MCP Tooling**:
   - `code/aiosh-mcp/aiosh_mcp/server.py`: Server entrypoint, dispatcher, and tool registrations (`aios_task`, `aios_compliance`, pentest wrappers).
   - `code/aiosh-mcp/aiosh_mcp/incident_runbook_service.py`: Core execution state machine (`RunbookExecutionSession`).

---

## 3. Facts vs Assumptions

| Aspect | Fact | Assumption |
| :--- | :--- | :--- |
| **Transport** | stdio JSON-RPC transport via `FastMCP("aiosh-mcp")`. | No WebSockets or SSE transports required for local agent execution. |
| **Audit Gate** | Every tool MUST call `_recorded_call()` or `_dispatch.dispatch()` to guarantee an honest audit row. | Silent execution is completely prohibited under PoR Invariant I-2. |
| **State Machine** | `RunbookExecutionSession` in `incident_runbook_service.py` manages monotonic transitions (`Pending` -> `Running` -> `Completed`/`Failed`/`Aborted`) and confirmation gates. | Active sessions can be indexed in an in-memory session registry with UUID keys during agent runtime. |
| **Security Scanning** | Rust core substrate in `sec_tools.rs` implements socket sweep, file regex scan, and web probe. Python MCP can wrap or invoke these operations directly or through native fallback. | Agent requires both programmatic runbook control (`aios_runbook`) and targeted security scanning (`aios_scan`). |
| **Capability Grants** | Mutation operations (`runbook start`, `runbook step`, `runbook abort`, `runbook confirm`) and scans require valid PEP capability grants. Read queries (`list`, `show`, `status`) do not require grants. | Capability tokens map to `cap:runbook:execute`, `cap:net:scan`, `cap:fs:search`, `cap:web:probe`. |

---

## 4. Key Architectural Decisions Needed

1. **Tool Namespace & Granularity**:
   - Expose `aios_runbook` for all runbook operations via `action: list | show | init | start | step | confirm | status | abort`.
   - Expose `aios_scan` for security scans via `action: net | files | web` with parameters matching CLI equivalents.
2. **Session Persistence**:
   - Implement `RunbookSessionStore` managing thread-safe in-memory dictionary with TTL cleanup (max 1,000 active sessions).
3. **Confirmation Token Flow**:
   - MCP `step` action inspects if the current step requires confirmation (`requires_confirmation=True`). If so, returns `{ok: false, error: "RUNBOOK_ERR_MISSING_CONFIRMATION", session_id: "...", awaiting_confirmation: true}` until `confirm` action is invoked with valid `operator_id` and token.
4. **Error Envelopes**:
   - Return `{ok: false, action: str, error: str, audit_id: int}` on domain errors without raising unhandled exceptions out of FastMCP.
