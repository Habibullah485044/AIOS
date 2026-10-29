# T-03273 Research: Agent Loop Hardening Core Service

## Scope & Objective
Establish architectural requirements, facts, constraints, and prior art for the **Core Service of Agent Loop Hardening** (`AgentLoopService`), bridging the passive data model (`agent_loop_data_model.py`) with active execution, policy enforcement points (PEP), and audit logging.

---

## 1. Facts vs. Assumptions

### Facts Established from Codebase
1. **Data Model Groundwork (`T-03265`..`T-03272`)**: `code/aiosh-mcp/aiosh_mcp/agent_loop_data_model.py` provides certified FSM state definitions (`LoopState`), configuration constraints (`LoopConfig`), telemetry records (`LoopStepRecord`), snapshots (`LoopSnapshot`), and string bounds.
2. **MCP Protocol Boundary (ADR-0035 §D-2)**: MCP is the sole external tool-call surface for external models. All mutating tools require PoR capability token validation (Invariant I-2).
3. **Audit Ring Integration (ADR-0035 §F-2)**: All consequential actions must write exactly one audit row into the append-only audit ring before or immediately upon completion.
4. **PEP & Dispatch Gate**: `code/aiosh-mcp/aiosh_mcp/_dispatch.py` provides policy classification and capability token redemption gates.

### Assumptions Validated
1. **Synchronous vs Asynchronous Step Orchestration**: In Python/MCP, turn execution can be synchronously stepped or scheduled as an async task, returning structured snapshots at each boundary.
2. **Separation of Policy from Execution**: Policy evaluation (`EVALUATE_POLICY`) must occur strictly *before* tool dispatch (`EXECUTE_TOOL`). If policy denies the action, the service must record a refused step record (`outcome="refused"`) rather than throwing an unhandled exception.

---

## 2. Authoritative Standards & References

- **ADR-0035 §D-1, §D-2, §D-4**: Model Context Protocol tool contracts, capability tokens, zero-token read operations.
- **ADR-0037**: Proof-of-Restraint (Layer 1 one-shot capability redemption and Layer 2 audit trail verification).
- **RFC 9457**: Problem Details for HTTP APIs (standard error code structure).
- **NIST SP 800-207**: Zero Trust Architecture — Policy Enforcement Point (PEP) verification before every privileged resource access.

---

## 3. Core Service Invariants

| Invariant | Name | Rule |
| :--- | :--- | :--- |
| **`LOOPSERV-INV1`** | Monotonic FSM Advancement | State updates strictly follow `VALID_TRANSITIONS`; terminal states are absorbing. |
| **`LOOPSERV-INV2`** | Audit Atomicity | Every turn step produces exactly one audit record with sanitized args. |
| **`LOOPSERV-INV3`** | Pre-Execution Policy Gate | Tools are never dispatched without passing through policy evaluation; policy refusals record explicit refusal steps. |
| **`LOOPSERV-INV4`** | Execution Watchdogs | Step timeout (`timeout_ms_per_step`) and total timeout (`total_timeout_ms`) enforce bounded execution. |
| **`LOOPSERV-INV5`** | Proof-of-Restraint Gating | Mutating operations (`start_loop`, `step_loop`, `abort_loop`) require valid capability token redemption. |

---

## 4. Key Architectural Decisions Needed

1. **Service Storage Backend**: In-memory registry with optional filesystem persistence to `.aios/loops/<loop_id>.json`.
2. **Watchdog Strategy**: Wall-clock timestamp comparison at turn boundaries supplemented with timeout bounds on tool execution.
3. **Tool Execution Dispatch**: Integrate with MCP tool manager and `_recorded_call` dispatch pipeline.
