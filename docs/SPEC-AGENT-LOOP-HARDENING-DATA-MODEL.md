# Specification: AI Control Plane Agent Loop Hardening Data Model

**Document ID**: SPEC-AGENT-LOOP-HARDENING-DATA-MODEL  
**Lifecycle Target**: T-03263..T-03272 (Phase 3 — AI Control Plane (Pillar C Spine) / Agent Loop Hardening / data model)  
**Contract Reference**: ADR-0035 §D-1/§D-2/§D-4, ADR-0037, PoR Invariant I-2  
**Status**: APPROVED / ACTIVE  

---

## 1. Overview & Architectural Role

The **Agent Loop Hardening Data Model** provides authoritative, typed state machine descriptors, execution budget constraints, step telemetry records, and serialization schemas for autonomous agent execution loops in AIOS.

It governs the lifecycle of agent reasoning loops across TypeScript, Python, and Rust substrates, guaranteeing deterministic finite state transitions, bounded execution ceilings, and circuit-breaker isolation against cascading tool failures.

---

## 2. Invariants & Certified Contracts

| Invariant | Target | Rule | Description |
| :--- | :--- | :--- | :--- |
| **`LOOPDATA-INV1`** | Step Monotonicity | Sequential Indices | Step indices are contiguous non-negative integers increasing strictly by 1 (`step_index == previous + 1`). |
| **`LOOPDATA-INV2`** | Resource Conservation | Non-negative Tokens | `total_tokens_used == sum(s.tokens_consumed for s in steps)` and all token counts are `>= 0`. |
| **`LOOPDATA-INV3`** | Fault Isolation | Circuit-Breaker Bound | If `consecutive_failures >= consecutive_failure_limit`, the loop transitions immediately to `FAILED` with circuit-breaker reason. |
| **`LOOPDATA-INV4`** | Substrate Parity | Clean Serialization & Masking | Dataclasses support bidirectional `to_dict()` and `from_dict()` roundtrips with automatic secret redaction (`sk-...`, `Bearer ...`). |
| **`LOOPDATA-INV5`** | FSM Determinism | Valid State Transitions | Transitions must conform strictly to the validated finite state machine transition table; terminal states (`COMPLETED`, `FAILED`, `ABORTED`) are absorbing. |

---

## 3. Finite State Machine (FSM) Transition Table

| Current State | Allowed Next States | Description |
|:---|:---|:---|
| `INIT` | `OBSERVE`, `ABORTED` | Config validated; preparing first observation. |
| `OBSERVE` | `PLAN`, `COMPLETED`, `ABORTED` | Context loaded; transition to LLM planning or complete if goal satisfied. |
| `PLAN` | `EVALUATE_POLICY`, `COMPLETED`, `FAILED`, `ABORTED` | Plan generated; proceed to policy evaluation or end turn. |
| `EVALUATE_POLICY` | `EXECUTE_TOOL`, `RECORD_STEP`, `FAILED`, `ABORTED` | Classifier/PEP gate; if refused, records step directly; if allowed, dispatches. |
| `EXECUTE_TOOL` | `RECORD_STEP`, `FAILED`, `ABORTED` | Tool execution complete; records output. |
| `RECORD_STEP` | `OBSERVE`, `COMPLETED`, `FAILED`, `ABORTED` | Step committed to audit log; loop back or terminate. |
| `COMPLETED` | *(None — Terminal)* | Goal successfully achieved. |
| `FAILED` | *(None — Terminal)* | Terminal unrecoverable error or circuit breaker trip. |
| `ABORTED` | *(None — Terminal)* | Operator abort or intentional cancellation. |

---

## 4. Data Models & Interface Contracts

### 4.1 `LoopState` (Enum)
```python
class LoopState(str, Enum):
    INIT = "INIT"
    OBSERVE = "OBSERVE"
    PLAN = "PLAN"
    EVALUATE_POLICY = "EVALUATE_POLICY"
    EXECUTE_TOOL = "EXECUTE_TOOL"
    RECORD_STEP = "RECORD_STEP"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"
```

### 4.2 `LoopConfig` (Frozen Dataclass)
```python
@dataclass(frozen=True)
class LoopConfig:
    loop_id: str
    max_iterations: int = 25
    max_total_tokens: int = 32768
    timeout_ms_per_step: float = 30000.0
    total_timeout_ms: float = 300000.0
    consecutive_failure_limit: int = 3

    def validate_bounds(self) -> None: ...
    def to_dict(self) -> Dict[str, Any]: ...
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LoopConfig": ...
```

### 4.3 `LoopStepRecord` (Dataclass)
```python
@dataclass
class LoopStepRecord:
    step_index: int
    state_at_start: LoopState
    state_at_end: LoopState
    tool_name: Optional[str]
    tool_args_summary: str
    outcome: str    # "ok" | "refused" | "error"
    tokens_consumed: int
    duration_ms: float
    error_message: Optional[str] = None
    recorded_at_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]: ...
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LoopStepRecord": ...
```

### 4.4 `LoopSnapshot` (Dataclass)
```python
@dataclass
class LoopSnapshot:
    loop_id: str
    current_state: LoopState
    current_iteration: int
    total_tokens_used: int
    total_tool_calls: int
    consecutive_failures: int
    is_terminated: bool
    terminal_reason: Optional[str] = None
    steps: List[LoopStepRecord] = field(default_factory=list)
    created_at_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def validate_invariants(self) -> None: ...
    def transition_to(self, new_state: LoopState, terminal_reason: Optional[str] = None) -> None: ...
    def record_step(self, step: LoopStepRecord, config: Optional[LoopConfig] = None) -> None: ...
    def to_dict(self) -> Dict[str, Any]: ...
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LoopSnapshot": ...
```

---

## 5. FastMCP Tools & Operator Usage

The data model tools are registered on the AIOS MCP server in `code/aiosh-mcp/aiosh_mcp/server.py`.

### 5.1 Initialize an Agent Loop (`aios_agent_loop_init`)
Mutating tool — requires a valid Proof-of-Restraint capability token (Invariant I-2).

```json
{
  "name": "aios_agent_loop_init",
  "arguments": {
    "loop_id": "loop-agent-alpha-01",
    "max_iterations": 25,
    "max_total_tokens": 32768,
    "capability_token": "por-cap-token-demo"
  }
}
```

**Response Example**:
```json
{
  "ok": true,
  "loop_id": "loop-agent-alpha-01",
  "snapshot": {
    "loop_id": "loop-agent-alpha-01",
    "current_state": "INIT",
    "current_iteration": 0,
    "total_tokens_used": 0,
    "total_tool_calls": 0,
    "consecutive_failures": 0,
    "is_terminated": false,
    "terminal_reason": null,
    "steps": [],
    "created_at_utc": "2026-10-30T00:00:00+00:00",
    "updated_at_utc": "2026-10-30T00:00:00+00:00"
  }
}
```

### 5.2 Query Loop Status (`aios_agent_loop_status`)
Read-only query — requires 0 capability tokens.

```json
{
  "name": "aios_agent_loop_status",
  "arguments": {
    "loop_id": "loop-agent-alpha-01"
  }
}
```

---

## 6. Hardening Safeguards & Memory Caps

- `MAX_SNAPSHOT_STEPS = 1000`: Bounded step records per snapshot; prevents memory leaks on long loops.
- `MAX_ARGS_SUMMARY_BYTES = 65536`: Arguments exceeding 64 KiB are truncated with `[TRUNCATED]` suffix.
- `MAX_ERROR_MSG_BYTES = 16384`: Error traces exceeding 16 KiB are truncated with `[TRUNCATED]` suffix.
- `MAX_REGISTRY_CAPACITY = 256`: Bounded in-memory loop registry with automatic LRU eviction of terminated loops (`ABORTED`, `COMPLETED`, `FAILED`).
- Credential Redaction: `mask_secrets` sanitizes `sk-*`, `ghp_*`, and `Bearer *` authorization credentials prior to serialization.

---

## 7. Known Constraints & Limitations

1. **In-Memory Registry**: `AgentLoopRegistry` maintains snapshots in memory. Persistent cross-session snapshots require the core service persistence layer (scheduled in T-03273..T-03282).
2. **Absorbing States**: Once in `COMPLETED`, `FAILED`, or `ABORTED`, snapshots cannot be restarted; a new loop ID must be initialized.
3. **Regex Secret Redaction**: Identifies high-entropy keys (`sk-*`, `ghp_*`, `Bearer *`); custom enterprise tokens with non-standard prefixes should be explicitly sanitized before passing into step records.

---

## 8. Evidence Links

- Research: [`docs/tasks/evidence/T-03263-data-model-research.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03263-data-model-research.md)
- Specification: [`docs/tasks/evidence/T-03264-data-model-specification.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03264-data-model-specification.md)
- Scaffold: [`docs/tasks/evidence/T-03265-data-model-scaffold.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03265-data-model-scaffold.md)
- Implementation: [`docs/tasks/evidence/T-03266-data-model-implementation.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03266-data-model-implementation.md)
- Unit Tests: [`docs/tasks/evidence/T-03267-data-model-unit-test.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03267-data-model-unit-test.md)
- Integration: [`docs/tasks/evidence/T-03268-data-model-integration.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03268-data-model-integration.md)
- Security Review: [`docs/tasks/evidence/T-03269-data-model-security-review.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03269-data-model-security-review.md) & [`docs/tasks/evidence/T-03269-security.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03269-security.md)
- Hardening: [`docs/tasks/evidence/T-03270-data-model-hardening.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03270-data-model-hardening.md)
- Documentation: [`docs/tasks/evidence/T-03271-data-model-documentation.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03271-data-model-documentation.md)
