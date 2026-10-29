# Specification: Agent Loop Hardening Core Service (T-03274)

**Document ID**: SPEC-AGENT-LOOP-CORE-SERVICE  
**Lifecycle Target**: T-03273..T-03282 (Phase 3 — AI Control Plane (Pillar C Spine) / Agent Loop Hardening / core service)  
**Contract Reference**: ADR-0035 §D-1/§D-2, ADR-0037, Proof-of-Restraint Invariant I-2  
**Status**: APPROVED  

---

## 1. Overview & Architectural Role

The **Agent Loop Core Service** (`AgentLoopService`) in `code/aiosh-mcp/aiosh_mcp/agent_loop_service.py` is the execution engine governing autonomous agent reasoning turns in AIOS.

It drives the FSM state machine established in `agent_loop_data_model.py`, manages execution budgets, evaluates security policies (PEP) prior to tool invocation, handles timeouts, and enforces audit row emission on all consequential actions.

---

## 2. Invariants & Certified Contracts

| Invariant | Name | Rule | Description |
|:---|:---|:---|:---|
| **`LOOPSERV-INV1`** | Deterministic State Sequencing | Valid FSM Steps | Turn execution strictly advances through allowed FSM state transitions; terminal states are non-reentrant. |
| **`LOOPSERV-INV2`** | Audit Atomicity | Consequential Logging | Every turn step, initialization, or termination writes exactly one audit record with redacted secrets. |
| **`LOOPSERV-INV3`** | Pre-Execution PEP Gating | No Bypasses | Policy evaluation strictly precedes tool invocation. Policy refusals produce `outcome="refused"` and bypass execution. |
| **`LOOPSERV-INV4`** | Execution Watchdogs | Bounded Execution | Per-step timeout (`timeout_ms_per_step`) and cumulative timeout (`total_timeout_ms`) automatically trip into `FAILED`/`ABORTED`. |
| **`LOOPSERV-INV5`** | Proof-of-Restraint Gating | Capability Redemption | `start_loop`, `advance_turn`, and `abort_loop` strictly require capability token redemption. |

---

## 3. Error Taxonomy

Standard error identifiers returned across MCP and API surfaces:
- `LOOPSERV_ERR_NOT_FOUND`: Loop ID not found in registry.
- `LOOPSERV_ERR_ALREADY_EXISTS`: Loop ID already initialized.
- `LOOPSERV_ERR_TERMINATED`: Operation attempted on terminated loop.
- `LOOPSERV_ERR_UNAUTHORIZED`: Capability token missing or empty for state mutation.
- `LOOPSERV_ERR_POLICY_REFUSED`: Tool invocation denied by policy engine.
- `LOOPSERV_ERR_TIMEOUT`: Step or total execution timeout exceeded.
- `LOOPSERV_ERR_CIRCUIT_BREAKER`: Failure limit or token ceiling breached.

---

## 4. Interfaces & Method Contracts

```python
class AgentLoopService:
    def start_loop(self, config: LoopConfig, capability_token: str) -> LoopSnapshot:
        """Initializes a new loop in INIT state. Validates bounds and writes audit log."""
        ...

    def advance_turn(
        self,
        loop_id: str,
        action_intent: str,
        tool_name: Optional[str] = None,
        tool_args: Optional[Dict[str, Any]] = None,
        tokens_consumed: int = 0,
        policy_allowed: bool = True,
        capability_token: str = "",
    ) -> LoopStepRecord:
        """Advances agent loop through FSM: EVALUATE_POLICY -> EXECUTE_TOOL -> RECORD_STEP.
        Enforces LOOPSERV-INV1..LOOPSERV-INV5.
        """
        ...

    def abort_loop(self, loop_id: str, reason: str, capability_token: str = "") -> LoopSnapshot:
        """Transitions active loop directly to ABORTED state."""
        ...

    def get_snapshot(self, loop_id: str) -> LoopSnapshot:
        """Returns current loop snapshot. Pure read-only (0 capability tokens)."""
        ...

    def list_active_loops(self) -> List[LoopSnapshot]:
        """Lists active non-terminated loops in memory."""
        ...
```

---

## 5. Persistence & Audit Effects

1. **In-Memory & Storage Parity**: Loop states are indexed by `loop_id`. Snapshots are serialized via `to_dict()` and preserved.
2. **Audit Emission**: Every mutating call invokes `aiosh_mcp.audit_client` to record:
   - Event type: `aios.agent_loop.start`, `aios.agent_loop.step`, `aios.agent_loop.abort`.
   - Payload: Masked arguments, step index, token usage, duration, outcome, and grant ID.
