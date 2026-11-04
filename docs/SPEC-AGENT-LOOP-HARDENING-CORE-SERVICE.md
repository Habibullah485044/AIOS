# Agent Loop Hardening — Core Service

**Document ID**: SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE  
**Lifecycle Target**: T-03273..T-03282 (Phase 3 — AI Control Plane (Pillar C Spine) / Agent Loop Hardening / core service)  
**Contract Reference**: ADR-0035 §D-1/§D-2/§F-2, ADR-0037, PoR Invariant I-2  
**Status**: ACTIVE (shipped T-03276..T-03280)  
**Companion**: [SPEC-AGENT-LOOP-HARDENING-DATA-MODEL.md](SPEC-AGENT-LOOP-HARDENING-DATA-MODEL.md)

---

## 1. What it is

`AgentLoopService` (`code/aiosh-mcp/aiosh_mcp/agent_loop_service.py`) drives one agent
reasoning loop per `loop_id` through the data-model FSM:

```
INIT -> OBSERVE -> PLAN -> EVALUATE_POLICY -> EXECUTE_TOOL -> RECORD_STEP -> OBSERVE ...
                                  \-> RECORD_STEP (refused)
any non-terminal state -> ABORTED (abort, total timeout, audit failure)
RECORD_STEP -> FAILED (iteration / token / consecutive-failure breakers)
```

The service **records** turns and enforces policy before a tool would run. It does not
execute tools itself: the caller runs the tool only when `advance_turn` returns `outcome="ok"`.

## 2. Capability model (PoR I-2)

| Call | Token requirement |
|---|---|
| `start_loop` / `aios_agent_loop_start` | Redeems the token as a **single-use PEP grant**. The grant's `scope.tools` must cover `aios.agent_loop.start`. |
| `advance_turn` / `aios_agent_loop_advance` | Must present the **same grant id** that started the loop. Each `tool_name` is re-checked against that grant's `scope.tools`, expiry and revocation. |
| `abort_loop` / `aios_agent_loop_abort` | Same grant id as the start. |
| `get_snapshot` / `aios_agent_loop_snapshot` | None (read-only). |

`policy_allowed=False` from the caller refuses a step. `policy_allowed=True` is **not**
sufficient on its own: the grant must also cover the tool.

Grants are issued by the CLI (the canonical issuer):

```bash
aiosh grant create --to agent:planner --tools "aios.agent_loop.start,aios.fs.read" --ttl 900
```

The returned `grant_id` (`data.grant_id`) is the `capability_token` for every call on that loop.

## 3. MCP tools (registered in `server.py`)

| Tool | Arguments | Returns (`LoopResultEnvelope`) |
|---|---|---|
| `aios_agent_loop_start` | `loop_id`, `capability_token`, optional `max_iterations` (1..100), `max_total_tokens` (100..1e6), `timeout_ms_per_step`, `total_timeout_ms` (5000..1.8e6), `consecutive_failure_limit` (1..10) | `{"ok": true, "data": {"snapshot": {...}}}` |
| `aios_agent_loop_advance` | `loop_id`, `action_intent`, `capability_token`, optional `tool_name`, `tool_args`, `tokens_consumed`, `policy_allowed` | `{"ok": true, "data": {"step": {...}, "state": "OBSERVE", "is_terminated": false}}` |
| `aios_agent_loop_abort` | `loop_id`, `reason`, `capability_token` | `{"ok": true, "data": {"snapshot": {...}}}` |
| `aios_agent_loop_snapshot` | `loop_id` | `{"ok": true, "data": {"snapshot": {...}}}` |

On failure every tool returns `{"ok": false, "error": "...", "error_code": "<CODE>"}`. Tools never raise to the transport.

Example tool call (JSON-RPC `tools/call` params):

```json
{"name": "aios_agent_loop_advance",
 "arguments": {"loop_id": "loop-docs-demo-01", "action_intent": "read the README",
               "tool_name": "aios.fs.read", "tool_args": {"path": "README.md"},
               "tokens_consumed": 120, "capability_token": "gr_..."}}
```

## 4. Python example (copy-pasteable; verified in T-03281 evidence)

```python
import datetime as dt, json, os, tempfile
from contextlib import closing
os.environ["AIOSH_HOME"] = tempfile.mkdtemp()          # isolated audit DB for the demo
from aiosh_mcp import audit_client
from aiosh_mcp.agent_loop_data_model import LoopConfig
from aiosh_mcp.agent_loop_service import AgentLoopService

# Stand-in for `aiosh grant create` so the example is self-contained.
now = dt.datetime.now(dt.timezone.utc)
with closing(audit_client.open_db()) as conn:
    audit_client.ensure_pep_schema(conn)
    conn.execute("INSERT INTO pep_grants (grant_id, issued_at, expires_at, issued_to, constitution_rev,"
                 " scope_json, scope_hash, single_use) VALUES (?,?,?,?,?,?,?,1)",
                 ("gr_docs_demo", now.isoformat(), (now + dt.timedelta(minutes=15)).isoformat(),
                  "agent:planner", "rev-demo", json.dumps({"tools": ["aios.agent_loop.start", "aios.fs.read"]}), "h"))
    conn.commit()

svc = AgentLoopService()                                # production PEP gate on $AIOSH_HOME/audit.db
svc.start_loop(LoopConfig(loop_id="loop-docs-demo-01", max_iterations=5), capability_token="gr_docs_demo")
ok = svc.advance_turn("loop-docs-demo-01", "read README", tool_name="aios.fs.read",
                      tool_args={"path": "README.md"}, tokens_consumed=120, capability_token="gr_docs_demo")
no = svc.advance_turn("loop-docs-demo-01", "write file", tool_name="fs.write", capability_token="gr_docs_demo")
svc.abort_loop("loop-docs-demo-01", "demo finished", capability_token="gr_docs_demo")
print(ok.outcome, no.outcome, svc.get_snapshot("loop-docs-demo-01").current_state.value)
# -> ok refused ABORTED
```

## 5. Audit rows (LOOPSERV-INV2)

Each consequential event appends one hash-chained row to `audit_ring` (`$AIOSH_HOME/audit.db`):
`pep.capability.redeem`, `aios.agent_loop.start`, `aios.agent_loop.step` (outcome `ok`/`refused`),
`aios.agent_loop.abort`, `aios.agent_loop.timeout`. Arguments pass through `mask_secrets`
(`sk-…`, `ghp_…`, `Bearer …`) before they are written.

## 6. Error codes

| Code | Meaning |
|---|---|
| `LOOPSERV_ERR_UNAUTHORIZED` | Token missing, grant not redeemable (unknown/expired/revoked/replayed/out of scope), or token not bound to this loop |
| `LOOPSERV_ERR_NOT_FOUND` / `LOOPSERV_ERR_ALREADY_EXISTS` | Unknown / duplicate `loop_id` |
| `LOOPSERV_ERR_TERMINATED` | Loop is COMPLETED/FAILED/ABORTED |
| `LOOPSERV_ERR_POLICY_REFUSED` | Step refused (in `step.error_message`; the call itself succeeds) |
| `LOOPSERV_ERR_TIMEOUT` | `total_timeout_ms` exceeded; loop ABORTED |
| `LOOPSERV_ERR_INVALID_INPUT` | `action_intent` > 4096 chars, `reason` > 1024, bad `tool_name`, `tokens_consumed` outside [0, 1e6] |
| `LOOPSERV_ERR_CAPACITY` | 256 loops held and none terminated |
| `LOOPSERV_ERR_AUDIT` | Audit write failed; loop not created (start) or ABORTED (later events) |
| `LOOPSERV_ERR_GATE_UNAVAILABLE` | Grant DB unreachable; fails closed |
| `LOOPDATA_ERR_BOUNDS_EXCEEDED` | `LoopConfig` out of range or bad `loop_id` (`^[a-zA-Z0-9_-]{8,64}$`) |

## 7. Known limitations

- **In-memory state.** Loops live in the process; a server restart loses them. The audit ring is the durable record.
- **No per-step timeout.** `timeout_ms_per_step` is validated but not enforced, because the service does not run tools.
- **One grant per loop.** A single-use grant is consumed by `start_loop`. Revoking it mid-loop refuses later tool calls, but `abort_loop` still works with the bound id.
- **Two registries.** `aios_agent_loop_init`/`aios_agent_loop_status` (T-03268, data model) keep their own INIT-only registry, separate from the service. Use the `aios_agent_loop_*` service tools for running loops.
- **Caller-reported metrics.** `tokens_consumed` and `tool_args` are self-reported by the caller and only bounded, not verified.

## 8. Evidence

- T-03273 research: [T-03273-core-service-research.md](tasks/evidence/T-03273-core-service-research.md)
- T-03274 spec: [T-03274-core-service-specification.md](tasks/evidence/T-03274-core-service-specification.md)
- T-03276 implementation: [T-03276-core-service-implementation.md](tasks/evidence/T-03276-core-service-implementation.md)
- T-03277 unit tests: [T-03277-core-service-unit-test.md](tasks/evidence/T-03277-core-service-unit-test.md)
- T-03278 integration: [T-03278-core-service-integration.md](tasks/evidence/T-03278-core-service-integration.md)
- T-03279 security review: [T-03279-security.md](tasks/evidence/T-03279-security.md)
- T-03280 hardening: [T-03280-core-service-hardening.md](tasks/evidence/T-03280-core-service-hardening.md)
