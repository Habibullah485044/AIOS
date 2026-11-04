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

## 3. MCP tools (registered in `server.py`, defined in `agent_loop_mcp.py`)

All seven tools are `async`. Blocking work runs off the event loop, and each call is bounded at 15 s (T-03300).
Each tool publishes MCP `ToolAnnotations` and an `inputSchema` whose limits match the server's limits (LOOPMCP-INV3).
Annotations are hints for clients: the server still enforces every rule itself.

| Tool | Annotations | Arguments (schema limits) | `data` on success |
|---|---|---|---|
| `aios_agent_loop_start` | mutating | `loop_id` (`^[a-zA-Z0-9_-]{8,64}$`), `capability_token` (<= 256), optional `max_iterations` 1..100, `max_total_tokens` 100..1e6, `timeout_ms_per_step` 1000..120000, `total_timeout_ms` 5000..1.8e6, `consecutive_failure_limit` 1..10 | `snapshot` |
| `aios_agent_loop_advance` | mutating | `loop_id`, `action_intent` 1..4096, `capability_token`, optional `tool_name` (`^[A-Za-z0-9_.-]{1,128}$`), `tool_args` (object, <= 64 KiB, depth <= 32), `tokens_consumed` 0..1e6, `policy_allowed` | `step`, `state`, `is_terminated` |
| `aios_agent_loop_abort` | destructive, idempotent | `loop_id`, `reason` 1..1024, `capability_token` | `snapshot` |
| `aios_agent_loop_complete` | destructive | `loop_id`, `capability_token` | `snapshot` |
| `aios_agent_loop_snapshot` | read-only | `loop_id`, `steps_tail` 0..1000 (default 100) | `snapshot` (last N steps), `steps_total` |
| `aios_agent_loop_list` | read-only | `include_terminated` (default false) | `loops` (max 256 rows of id, state, iteration, tokens, terminated) |
| `aios_agent_loop_history` | read-only | `loop_id`, `limit` 1..1000 (default 100), `after_id` >= 0 | `loop_id`, `events`, `truncated`, `next_after_id` (pages are capped at about 1 MiB) |

Mutating tools need the grant: `start` redeems it, and the others require the loop-bound grant id.
Read-only tools need no token and write nothing.

How failures come back:
- **Tool-level failures** return `{"ok": false, "error": "...", "error_code": "<CODE>"}`.
- **Schema violations** come back as an MCP tool error (`isError: true`) before the tool body runs. Examples: a 3-char `loop_id`, or `limit` 0.
- **A missing token** is not a schema error. It reaches the service and returns `LOOPSERV_ERR_UNAUTHORIZED`.

Example `tools/call` params (verified against the server in T-03301):

```json
{"name": "aios_agent_loop_start",
 "arguments": {"loop_id": "loop-docs-mcp-01", "capability_token": "gr_docs_mcp", "max_iterations": 10}}
```
```json
{"name": "aios_agent_loop_advance",
 "arguments": {"loop_id": "loop-docs-mcp-01", "action_intent": "read the README",
               "tool_name": "aios.fs.read", "tool_args": {"path": "README.md"},
               "tokens_consumed": 120, "capability_token": "gr_docs_mcp"}}
```
```json
{"name": "aios_agent_loop_history", "arguments": {"loop_id": "loop-docs-mcp-01", "limit": 100, "after_id": 0}}
```
To page through history, repeat the call with `after_id` set to `next_after_id` until `truncated` is `false`.

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

## 4a. Operator CLI (`aiosh-agent-loop`, T-03283..T-03292)

Module `code/aiosh-mcp/aiosh_mcp/agent_loop_cli.py`. Run it as `python -m aiosh_mcp.agent_loop_cli`, or as
`aiosh-agent-loop` after `pip install -e code/aiosh-mcp`. Loop state is in-memory, so the CLI is a **one-shot runner**:
`run` does start, every planned turn and complete in a single process. `history` reads the durable audit ring.

| Subcommand | Token | What it does |
|---|---|---|
| `validate --plan FILE` | no | Checks a plan file (<= 1 MiB, 1..100 turns, same per-turn caps as the service) |
| `run --loop-id ID (--token-env VAR \| --token-stdin \| --token GRANT) --plan FILE [--max-iterations N] [--max-total-tokens N] [--total-timeout-ms MS] [--consecutive-failure-limit N]` | **yes** | Redeems the grant, runs every turn through the policy gate, ends COMPLETED (or FAILED or ABORTED) |
| `history --loop-id ID [--limit 1..1000]` | no | Lists `aios.agent_loop.*` audit rows for that loop, read-only |

Every subcommand accepts `--json`. In JSON mode the CLI prints exactly one object, and its `exit_code` equals the process exit code.

Plan file:
```json
{"turns": [
  {"action_intent": "read README", "tool_name": "aios.fs.read", "tool_args": {"path": "README.md"}, "tokens_consumed": 120},
  {"action_intent": "write file", "tool_name": "fs.write"}
]}
```

Copy-pasteable session (bash). Prefer `--token-env`: `--token` is visible in `ps` output and shell history.
```bash
GRANT=$(aiosh grant create --to agent:planner --tools "aios.agent_loop.start,aios.fs.read" --ttl 900 | jq -r .data.grant_id)
export AIOS_LOOP_GRANT="$GRANT"
python -m aiosh_mcp.agent_loop_cli validate --plan plan.json
python -m aiosh_mcp.agent_loop_cli run --loop-id loop-ops-demo-01 --token-env AIOS_LOOP_GRANT --plan plan.json
python -m aiosh_mcp.agent_loop_cli history --loop-id loop-ops-demo-01
```
Output with the plan above (grant covers `aios.fs.read` only):
```
plan OK: 2 turn(s)
[0] ok      aios.fs.read
[1] refused fs.write  LOOPSERV_ERR_POLICY_REFUSED: Policy evaluation refused tool invocation: tool 'fs.write' not in grant scope.tools
loop loop-ops-demo-01: COMPLETED (2 turn(s), 1 refused, 0 skipped)
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | success (refused steps are still success) |
| 1 | runtime failure (audit, gate, capacity, corrupt DB) |
| 2 | usage error or bad plan/config (rejected **before** the grant is spent) |
| 3 | unauthorized |
| 4 | timeout |
| 130 | interrupted (the loop is aborted and audited first) |

CLI limitations:
- No interactive per-turn mode: a loop cannot be continued by a later invocation.
- `history` needs no token. Protect `$AIOSH_HOME/audit.db` with file permissions.
- `--token` is still accepted for compatibility.
- The plan's `tokens_consumed` values are declared by the operator, not measured.

## 5. Audit rows (LOOPSERV-INV2)

Each consequential event appends one hash-chained row to `audit_ring` (`$AIOSH_HOME/audit.db`):
`pep.capability.redeem`, `aios.agent_loop.start`, `aios.agent_loop.step` (outcome `ok`/`refused`),
`aios.agent_loop.abort`, `aios.agent_loop.timeout`, `aios.agent_loop.complete`. Arguments pass through `mask_secrets`
(`sk-…`, `ghp_…`, `Bearer …`) before they are written.

## 6. Error codes

| Code | Meaning |
|---|---|
| `LOOPSERV_ERR_UNAUTHORIZED` | Token missing, grant not redeemable (unknown/expired/revoked/replayed/out of scope), or token not bound to this loop |
| `LOOPSERV_ERR_NOT_FOUND` / `LOOPSERV_ERR_ALREADY_EXISTS` | Unknown / duplicate `loop_id` |
| `LOOPSERV_ERR_TERMINATED` | Loop is COMPLETED/FAILED/ABORTED |
| `LOOPSERV_ERR_POLICY_REFUSED` | Step refused (in `step.error_message`; the call itself succeeds) |
| `LOOPSERV_ERR_TIMEOUT` | `total_timeout_ms` exceeded; loop ABORTED |
| `LOOPSERV_ERR_INVALID_INPUT` | `action_intent` > 4096 chars, `reason` > 1024, bad `tool_name`, `tokens_consumed` outside [0, 1e6], `tool_args` > 64 KiB or nested deeper than 32 (rejected, never truncated: T-03299) |
| `LOOPSERV_ERR_CAPACITY` | 256 loops held and none terminated |
| `LOOPSERV_ERR_AUDIT` | Audit write failed; loop not created (start) or ABORTED (later events) |
| `LOOPSERV_ERR_GATE_UNAVAILABLE` | Grant DB unreachable; fails closed |
| `LOOPDATA_ERR_BOUNDS_EXCEEDED` | `LoopConfig` out of range or bad `loop_id` (`^[a-zA-Z0-9_-]{8,64}$`) |
| `LOOPMCP_ERR_TIMEOUT` | MCP call exceeded 15 s. For mutating tools the outcome is **unknown**, so check `snapshot`/`history` before retrying |
| `LOOPMCP_ERR_AUDIT_READ` | `history`: the audit DB exists but is corrupt or unreadable |

## 7. Known limitations

- **In-memory state.** Loops live in the process; a server restart loses them. The audit ring is the durable record.
- **No per-step timeout.** `timeout_ms_per_step` is validated but not enforced, because the service does not run tools.
- **One grant per loop.** A single-use grant is consumed by `start_loop`. Revoking it mid-loop refuses later tool calls, but `abort_loop` still works with the bound id.
- **Two registries.** `aios_agent_loop_init` (T-03268, data model) still creates INIT-only loops in its own registry, which the service cannot drive. `aios_agent_loop_status` can read both registries (T-03296). Use `aios_agent_loop_start` for running loops.
- **Tokens travel as tool arguments.** MCP has no secret-argument channel, so `capability_token` can appear in client transcripts. The exposure is bounded because the grant is single-use and bound to one loop. Responses never echo it. A schema error for a token over 256 chars does echo a truncated copy back to the same caller.
- **Timeouts report uncertainty.** A mutating call that hits the 15 s bound may still finish in its worker thread. The envelope says the outcome is unknown.
- **Server-local view.** `list` only shows loops held by this server process.
- **Caller-reported metrics.** `tokens_consumed` and `tool_args` are self-reported by the caller and only bounded, not verified.

## 8. Evidence

- T-03273 research: [T-03273-core-service-research.md](tasks/evidence/T-03273-core-service-research.md)
- T-03274 spec: [T-03274-core-service-specification.md](tasks/evidence/T-03274-core-service-specification.md)
- T-03276 implementation: [T-03276-core-service-implementation.md](tasks/evidence/T-03276-core-service-implementation.md)
- T-03277 unit tests: [T-03277-core-service-unit-test.md](tasks/evidence/T-03277-core-service-unit-test.md)
- T-03278 integration: [T-03278-core-service-integration.md](tasks/evidence/T-03278-core-service-integration.md)
- T-03279 security review: [T-03279-security.md](tasks/evidence/T-03279-security.md)
- T-03280 hardening: [T-03280-core-service-hardening.md](tasks/evidence/T-03280-core-service-hardening.md)
- T-03293..T-03300 MCP/API: [research](tasks/evidence/T-03293-research.md), [spec](tasks/evidence/T-03294-spec.md), [scaffold](tasks/evidence/T-03295-mcp-api-surface-scaffold.md), [implementation](tasks/evidence/T-03296-mcp-api-surface-implementation.md), [unit](tasks/evidence/T-03297-mcp-api-surface-unit-test.md), [integration](tasks/evidence/T-03298-mcp-api-surface-integration.md), [security](tasks/evidence/T-03299-security.md), [hardening](tasks/evidence/T-03300-mcp-api-surface-hardening.md)
- T-03283..T-03290 CLI: [research](tasks/evidence/T-03283-research.md), [spec](tasks/evidence/T-03284-spec.md), [implementation](tasks/evidence/T-03286-cli-surface-implementation.md), [unit](tasks/evidence/T-03287-cli-surface-unit-test.md), [integration](tasks/evidence/T-03288-cli-surface-integration.md), [security](tasks/evidence/T-03289-security.md), [hardening](tasks/evidence/T-03290-cli-surface-hardening.md)
