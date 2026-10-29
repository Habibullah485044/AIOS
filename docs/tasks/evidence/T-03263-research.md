# T-03263 Research: AI Control Plane Agent Loop Hardening Data Model

## 1. Executive Summary & Context
- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Agent Loop Hardening / data model
- **Task ID**: T-03263
- **Primary Goal**: Establish facts, constraints, and prior art for the hardened data model governing autonomous agent execution loops in AIOS.

---

## 2. Codebase Baseline & Existing Implementations

### 2.1 Fact: Existing Agent Execution Loops
- **`code/aiosh-cli/src/agent.ts`**:
  - Implements the Sprint 2 TypeScript execution loop: `observe -> think (Ollama plan) -> classify -> call MCP tool -> observe -> repeat`.
  - Defines `AgentToolCall`, `AgentPlan`, `AgentLoopOptions`, `AgentToolResult`, `AgentStep`, and `AgentLoopResult`.
  - Interfaces are TypeScript-only and unvalidated on Python/MCP server side.
- **`code/aiosh-mcp/aiosh_mcp/agent_bridge.py`**:
  - Acts as an stdio bridge between TypeScript CLI and Python FastMCP tools.
  - Passes raw JSON dicts without loop state tracking, step budgets, or crash-resilient state machine descriptors.
- **`code/aiosh-rust/aiosh-core/src/agent.rs`**:
  - Core Rust agent definitions with basic task scheduling.

### 2.2 Facts vs Assumptions

| Item | Fact | Assumption | Resolution |
| :--- | :--- | :--- | :--- |
| **State Machine Structure** | Existing TS loop implicitly switches states in procedural while loop. | Agent loops need explicit state machine tracking (`INIT`, `OBSERVE`, `PLAN`, `EVALUATE_POLICY`, `EXECUTE_TOOL`, `RECORD_STEP`, `COMPLETED`, `FAILED`, `ABORTED`). | Provide formal `LoopState` enum with validated transition table. |
| **Resource Caps** | TS loop only caps `max_steps`. | Unbounded token usage, infinite failure retries, or execution hangs can exhaust resources. | Enforce hard caps: `max_iterations <= 100`, `timeout_ms_per_step`, `max_total_tokens`, and `consecutive_failure_limit <= 5`. |
| **Cross-Substrate Parity** | Python MCP server is the single point of truth for policy and audit. | The hardened data model must live in Python FastMCP (`code/aiosh-mcp`) and serialize cleanly across CLI/Rust bridges. | Implement `agent_loop_data_model.py` with full ADR-0035 `to_dict` / `from_dict` JSON roundtrip fidelity. |

---

## 3. Authoritative Citations & Prior Art
1. **ADR-0035 §D-1, §D-2, §D-4**: Agent loop architecture, MCP tool boundaries, classifier-before-dispatch policy.
2. **ADR-0037 / Proof of Restraint**: Token conservation and auditability across all loop iterations.
3. **NIST SP 800-53 (AC-2, SC-7)**: Automated state transition limits, bounded execution loops, and fail-safe defaults.
4. **Finite State Machine (FSM) Theory**: Deterministic state transitions, terminal state absorption, and transition validity proofs.

---

## 4. Key Architectural Decisions Needed

1. **Decision D1: State Representation (`LoopState`)**:
   - `INIT`: Loop instantiated, configuration validated.
   - `OBSERVE`: Ingesting environment context and previous step results.
   - `PLAN`: Requesting LLM reasoning / tool calls.
   - `EVALUATE_POLICY`: PEP gating / constitution checks.
   - `EXECUTE_TOOL`: Invoking MCP tool dispatch.
   - `RECORD_STEP`: Emitting audit row and updating step counters.
   - `COMPLETED`: Clean completion (goal achieved / end turn).
   - `FAILED`: Terminal failure (error threshold exceeded / unrecoverable).
   - `ABORTED`: Canceled via manual operator intervention or circuit-breaker.
2. **Decision D2: Data Models**:
   - `LoopConfig`: Immutable settings with bounds validation.
   - `LoopStepRecord`: Individual iteration metrics and tool outcomes.
   - `LoopSnapshot`: Point-in-time state machine snapshot for telemetry and persistence.
3. **Decision D3: Invariants (`LOOPDATA-INV1..INV5`)**:
   - `LOOPDATA-INV1`: Monotonic step indexing (`step_index == previous + 1`).
   - `LOOPDATA-INV2`: Token non-negativity and conservation.
   - `LOOPDATA-INV3`: Circuit-breaker enforcement on consecutive failures.
   - `LOOPDATA-INV4`: Clean serialization parity and secret redaction.
   - `LOOPDATA-INV5`: Deterministic valid state transitions.

---

## 5. Unknowns & Next Steps
- None blocking. Ready to advance to specification task `T-03264`.
