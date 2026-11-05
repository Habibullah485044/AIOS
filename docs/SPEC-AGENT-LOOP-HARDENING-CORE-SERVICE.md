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

## 2b. Per-step security policy (T-03323..T-03332)

Every `advance_turn` is evaluated in a fixed order. The first refusal wins, and a refused step is still recorded, with one audit row:

1. **P1 caller verdict:** `policy_allowed=false` refuses. The caller can only narrow what is allowed.
2. **P2 constitution:** the same C-1..C-4 classifier as dispatch Gate #1 (`classifier.classify`, rule pack `sprint-2-rule-pack-v1`).
   A `refused` verdict refuses with `LOOPPOL_ERR_CONSTITUTION`. For example, every `fs.write` (R-03) and prompt-injection text in args (R-11) is refused.
   Input is normalised first (NFKC, casefold, invisible characters removed, nested keys and strings flattened), and the classifier runs once per target.
3. **P3 grant scope:** `scope.tools` (lowercase names only; globs end at a `.` boundary), revocation and expiry, then **every** target value.
   Targets are the strings under target-like keys: `target(s)`, `path(s)`, `host(s)`, `url(s)`, `file(s)`, `dest`, `src`, `dir`, `cwd` and others; lists count.
   These are checked against `scope.networks` (for `pentest`/`network` tools) or `scope.paths`. **A scoped grant with no checkable target is refused.**
4. **P4 irreversible budget:** `pentest*`, `fs.write*`, `process*`, `shell*`, `system.reboot`/`shutdown`, and anything the classifier flags C-3,
   count against the grant's `scope.max_irreversible`. The budget is counted **per grant, from the audit ring**, and the check plus the write are
   one transaction, so loops, processes and restarts cannot overspend it.

Each step row records the real `c_flags`, `policy_revision` and `classify_*` columns, `irreversible`, `irreversible_used`, and
`tool_args_sha256` (a SHA-256 of the canonical, *unmasked* args, so evidence can be matched to what actually ran). MCP, CLI and history show
`policy: {verdict, rule_ids, irreversible[, irreversible_used]}`.

Example: a TS-issued budget of 1, enforced by a Python loop:
```bash
GRANT=$(aiosh grant create --to agent:scanner --tools "aios.agent_loop.start,pentest.*,fs.*"           --networks 10.0.0.0/24 --max-irreversible 1 --ttl 900 | jq -r .data.grant_id)
AIOS_LOOP_GRANT=$GRANT python -m aiosh_mcp.agent_loop_cli run --loop-id loop-pol-docs-01           --token-env AIOS_LOOP_GRANT --plan plan.json
```
Here `plan.json` holds `pentest.nmap` 10.0.0.5, `pentest.nmap` 10.0.0.6, `pentest.nmap` 8.8.8.8, and `fs.write /tmp/report.txt`. Output:
```
[0] ok      pentest.nmap  [R-01,R-07]
[1] refused pentest.nmap  [R-01,R-07]  LOOPSERV_ERR_POLICY_REFUSED: Policy evaluation refused tool invocation: LOOPPOL_ERR_IRREVERSIBLE_BUDGET: used 1 of 1
[2] refused pentest.nmap  [R-01,R-07]  LOOPSERV_ERR_POLICY_REFUSED: Policy evaluation refused tool invocation: target '8.8.8.8' blocked by grant scope.networks
[3] refused fs.write  [R-03,R-07]  LOOPSERV_ERR_POLICY_REFUSED: Policy evaluation refused tool invocation: LOOPPOL_ERR_CONSTITUTION: c2=0.95 (R-03) (rules R-03,R-07; policy sprint-2-rule-pack-v1)
loop loop-pol-docs-01: COMPLETED (4 turn(s), 3 refused, 0 skipped)
```

Policy limitations:
- The service records turns; **the caller executes tools**. The policy judges the declared `(tool, args)`, and the args digest makes any
  divergence detectable afterwards, but this layer cannot prevent it.
- The fixes for normalisation, target extraction and flattened injection scanning apply to the agent-loop path only. `_dispatch` still calls the raw classifier.
- Known rule-pack gaps that need a cross-substrate rule-pack change: `process.run` with `bin:"/bin/rm"` is matched only exactly, and SQL keyword matching is case-sensitive.
  P4 still counts `process.*` as irreversible.
- `--max-irreversible` is enforced only for agent loops, not for direct dispatch, the TS CLI or Rust paths.

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

## 4b. Configuration (`agent_loop_config.py`, T-03303..T-03312)

Every tunable can be configured. **No security control can be.** The server resolves config once per process
(`process_config()`), and the service, gate and MCP tools all use that one result.

Precedence, strongest first:
1. explicit arguments
2. per-field env `AIOSH_AGENT_LOOP_<FIELD>`
3. a JSON file: `--config FILE`, else `AIOSH_AGENT_LOOP_CONFIG`, else `./docs/agent_loop_config.json`
4. built-in defaults

Every value is then clamped to its bounds.

| Key | Default | Bounds | Env |
|---|---|---|---|
| `default_max_iterations` | 25 | 1..100 | `AIOSH_AGENT_LOOP_MAX_ITERATIONS` |
| `default_max_total_tokens` | 32768 | 100..1e6 | `AIOSH_AGENT_LOOP_MAX_TOTAL_TOKENS` |
| `default_timeout_ms_per_step` | 30000 | 1000..120000 | `AIOSH_AGENT_LOOP_TIMEOUT_MS_PER_STEP` |
| `default_total_timeout_ms` | 300000 | 5000..1.8e6 | `AIOSH_AGENT_LOOP_TOTAL_TIMEOUT_MS` |
| `default_consecutive_failure_limit` | 3 | 1..10 | `AIOSH_AGENT_LOOP_CONSECUTIVE_FAILURE_LIMIT` |
| `registry_capacity` | 256 | 1..256 | `AIOSH_AGENT_LOOP_REGISTRY_CAPACITY` |
| `mcp_call_timeout_s` | 15 | 1..60 | `AIOSH_AGENT_LOOP_MCP_CALL_TIMEOUT_S` |
| `history_page_bytes` | 1048576 | 65536..4194304 | `AIOSH_AGENT_LOOP_HISTORY_PAGE_BYTES` |
| `snapshot_steps_tail` | 100 | 0..1000 | `AIOSH_AGENT_LOOP_SNAPSHOT_STEPS_TAIL` |
| `db_busy_timeout_ms` | 5000 | 100..30000, and at most half of `mcp_call_timeout_s` | `AIOSH_AGENT_LOOP_DB_BUSY_TIMEOUT_MS` |

**Locked (rejected if present):** `max_args_bytes`, `max_args_depth`, `max_action_intent_chars`, `max_reason_chars`,
`max_tokens_per_turn`, `tool_name_pattern`, `max_token_chars`, `require_grant`, `audit_mutations`.

A file containing any unknown or locked key is **ignored as a whole**. So are oversize (> 64 KiB), non-JSON or
non-numeric files, special files (devices, FIFOs, UNC paths), and files with non-finite numbers. Invalid env values are
ignored per field. The server always starts: it falls back to defaults, writes one `aios.agent_loop.config` audit row with
outcome `degraded`, and reports what it rejected.

Example `docs/agent_loop_config.json`:
```json
{"default_max_iterations": 10, "registry_capacity": 32, "mcp_call_timeout_s": 20}
```
Inspect what is in effect, from the shell or over MCP (`aios_agent_loop_config`, read-only):
```bash
AIOSH_AGENT_LOOP_SNAPSHOT_STEPS_TAIL=many python -m aiosh_mcp.agent_loop_cli config --config docs/agent_loop_config.json --strict
```
Expected: three keys show `(file)`, `snapshot_steps_tail` stays `100 (default)`, there is one `warning:` line, and the exit code is **2** because of `--strict`.
JSON output (`--json`) has `config`, `source` (where each value came from), `rejected` (key -> `env_invalid` / `argument_invalid`),
`errors` (masked, at most 300 characters each) and `degraded`.

Config limitations:
- Config is read once at process start; there is no hot reload.
- The default file path is relative to the server's working directory.
- Callers can still override `LoopConfig` budgets per loop, within the same bounds.

## 5. Audit rows (LOOPSERV-INV2)

Each consequential event appends one hash-chained row to `audit_ring` (`$AIOSH_HOME/audit.db`):
`pep.capability.redeem`, `aios.agent_loop.start`, `aios.agent_loop.step` (outcome `ok`/`refused`),
`aios.agent_loop.abort`, `aios.agent_loop.timeout`, `aios.agent_loop.complete`, `aios.agent_loop.init`, and `aios.agent_loop.config` (outcome `degraded`, only when config input was rejected). Every loop row carries a random `run_id`, and a loop id can be started only once per ring. Arguments pass through `mask_secrets`
(`sk-…`, `ghp_…`, `Bearer …`) before they are written.

## 5b. Observability (T-03333..T-03342)

**Metrics.** MCP `aios_agent_loop_metrics(window=10000)` and CLI `metrics [--window N] [--json]` are read-only and need no token.
Both aggregate the newest `window` agent-loop rows (1..100000) **written by the agent-loop gate** (`actor_id = agent:mcp@aiosh-mcp/agent-loop`). They report:
- event counts
- ok, refused and irreversible step counts
- measured step latency (p50/p95/max)
- refusals grouped by structured reason: `constitution`, `irreversible_budget`, `scope`, `caller`, `target`, `gate_unavailable`, `other`
- the top 20 grants by irreversible use, identified only by a 12-hex SHA-256 prefix (grant ids are bearer tokens and are never emitted)
- the number of degraded-config rows

MCP also returns `live`: this server's active and terminated loops, capacity, and counters (`steps_ok`, `steps_refused`, `audit_failures`, `gate_unavailable`, `budget_refusals`).

**Health.** Health is computed over the fixed default window, so a caller can't hide signals by choosing a small one:
- `failing`: any audit-write failure, or the ring is unreadable or the query timed out
- `degraded`: config degraded, gate unavailable, or a degraded-config row
- `ok`: otherwise

**Cost bounds.** Rows are streamed, SQLite extracts only the needed fields, args over 8 KiB are not inspected, the query stops itself after 10 s,
and metrics calls run one at a time on their own limiter.

**Logging.** The library logger `aiosh_mcp.agent_loop` adds no handlers. It emits INFO for start, step, abort and complete, and WARNING for
audit_failure, gate_unavailable, timeout and budget_race. Each line carries only an event, a loop id, a run id, an outcome and a reason **code**,
as `extra={"agent_loop": {...}}`, with control characters escaped. It never contains grant ids, args or targets.
Enable it from the host:
```python
import logging; logging.basicConfig(level=logging.INFO)   # or attach your own handler to "aiosh_mcp.agent_loop"
```

**Durations.** `duration_ms` on steps and rows is measured inside the service lock, from turn start to recording.

Example, after the plan from §4a ran (2 reads, 1 refused write):
```bash
python -m aiosh_mcp.agent_loop_cli metrics
```
```
health: ok
window: 5 row(s) (ids 3..7)
events: start=1, step=3, complete=1
steps: ok=2 refused=1 irreversible_ok=0 duration_ms p50=6.451 p95=14.029 max=14.029
refusals: constitution=1
```

Observability limitations:
- The CLI has no live counters (it is one-shot), so its health reflects the ring only.
- A local writer that forges the gate's own `actor_id` is still counted. Detecting that needs chain-verified aggregation.
- Grant hashes are unsalted. Production ids (64 random bits) are not practically reversible, but low-entropy test ids are.

## 5c. Generated reference and doc drift checks (T-03343..T-03352)

This document is checked against the code. In addition, the code serves a reference **generated from itself**, so agents never depend on prose that may be stale.

- MCP `aios_agent_loop_doc(section?)` (read-only, no token) and CLI `python -m aiosh_mcp.agent_loop_cli doc [--section tools|errors|config|cli|policy] [--json]`.
- It contains:
  - all `aios_agent_loop_*` tools, with their published input schemas and annotations (identical to `tools/list`)
  - every `*_ERR_*` code, with its module and meaning
  - config fields with defaults, bounds and env **names**, plus the locked keys
  - CLI subcommands and flags
  - the P1..P4 step-policy order
- It is built once per process (about 0.6 ms per warm call). It never includes env values, paths or grant ids. A section that fails to build
  is reported under `_unavailable` instead of failing the whole reference.

Example:
```bash
python -m aiosh_mcp.agent_loop_cli doc --section config
```
```
== config ==

default_max_iterations               25         [1..100]  AIOSH_AGENT_LOOP_MAX_ITERATIONS

default_max_total_tokens             32768      [100..1000000]  AIOSH_AGENT_LOOP_MAX_TOTAL_TOKENS

default_timeout_ms_per_step          30000.0    [1000.0..120000.0]  AIOSH_AGENT_LOOP_TIMEOUT_MS_PER_STEP
...
```

**Drift check (CI).** `tests/test_agent_loop_doc_drift.py` fails the build when:
- a code, tool, config key or env name, locked key, or CLI subcommand is missing from this document
- this document names an error code that no longer exists
- a `python` example here stops running, or a `json` example no longer validates (tool calls against the live schemas, plans, configs)

Every `*_ERR_*` constant must also have a meaning in `agent_loop_doc.ERROR_MEANINGS`; that is checked in both directions.

## 5d. Recovery & validation (T-03353..T-03362)

Loop state is in-memory. A process that dies mid-loop leaves an **orphaned run**: a `start` row and steps, but no terminal row.
- `aios_agent_loop_validate(grace_s=900)` / `python -m aiosh_mcp.agent_loop_cli validate-ring [--grace S] [--json]` (read-only).
  It reports orphaned runs and structural problems, and checks the chain. The CLI exits 1 when anything is wrong.
- `aios_agent_loop_recover(capability_token, grace_s=900)` / `python -m aiosh_mcp.agent_loop_cli recover --token-env VAR [--grace S]`.
  It redeems a grant scoped to `aios.agent_loop.recover`, then closes each orphan with exactly one `aios.agent_loop.recovered` row.
  It is idempotent and never touches runs the server still holds.
- Breaker terminations write an `aios.agent_loop.failed` row, so they are not mistaken for orphans. `metrics` reports `orphaned_runs`, and health is `degraded` while any exist.

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
| `LOOPPOL_ERR_CONSTITUTION` / `LOOPPOL_ERR_IRREVERSIBLE_BUDGET` / `LOOPPOL_ERR_TARGET` | Step refused by P2 / P4 / a non-string target value (appears in `step.error_message`; the call itself succeeds) |
| `LOOPREC_ERR_READ` | Recovery / ring validation: the audit DB is unreadable |
| `LOOPOBS_ERR_READ` | Metrics: the audit DB is unreadable, or the metrics query exceeded its 10 s budget |
| `LOOPMCP_ERR_TIMEOUT` | MCP call exceeded 15 s. For mutating tools the outcome is **unknown**, so check `snapshot`/`history` before retrying |
| `LOOPMCP_ERR_AUDIT_READ` | `history`: the audit DB exists but is corrupt or unreadable |


Additional codes. Each is defined in code and has a one-line meaning in `agent_loop_doc.ERROR_MEANINGS`. The full catalog is generated by `aios_agent_loop_doc(section="errors")` / `agent_loop_cli doc --section errors`:

| Code | Meaning |
|---|---|
| `AGENTLOOPCONF_ERR_BOUNDS` | config value clamped to its bounds (reported, applied clamped) |
| `AGENTLOOPCONF_ERR_ENV` | env value or env config path rejected; lower level kept |
| `AGENTLOOPCONF_ERR_FILE_SIZE` | config file larger than 64 KiB; ignored |
| `AGENTLOOPCONF_ERR_IO` | config file unreadable, missing, special file or UNC/device path; ignored |
| `AGENTLOOPCONF_ERR_LOCKED` | config tried to set a locked security control; whole file ignored |
| `AGENTLOOPCONF_ERR_PARSE` | config file not a JSON object of finite numbers; ignored |
| `AGENTLOOPCONF_ERR_UNKNOWN_KEY` | config key not a known tunable; whole file ignored |
| `LOOPCLI_ERR_AUDIT_READ` | CLI history/metrics: audit DB unreadable (exit 1) |
| `LOOPCLI_ERR_INTERRUPTED` | CLI run interrupted; started loop aborted and audited (exit 130) |
| `LOOPCLI_ERR_PLAN` | CLI plan file invalid (exit 2) |
| `LOOPCLI_ERR_USAGE` | CLI usage error (exit 2) |
| `LOOPDATA_ERR_INVALID_STATE` | data-model registry: loop already exists / invalid state for the operation |
| `LOOPDATA_ERR_INVALID_TRANSITION` | FSM transition not allowed by the transition table |
| `LOOPDATA_ERR_INVARIANT_VIOLATION` | snapshot invariant broken (step indices, token conservation) |
| `LOOPDATA_ERR_NOT_FOUND` | data-model status: unknown loop id |
| `LOOPDATA_ERR_UNAUTHORIZED` | data-model init: missing or unredeemable capability token |
| `LOOPSERV_ERR_CIRCUIT_BREAKER` | loop terminated by a breaker (consecutive failures, token budget, iteration ceiling); prefix of terminal_reason |

## 7. Known limitations

- **In-memory state.** Loops live in the process; a server restart loses them. The audit ring is the durable record.
- **No per-step timeout.** `timeout_ms_per_step` is validated but not enforced, because the service does not run tools.
- **One grant per loop.** A single-use grant is consumed by `start_loop`. Revoking it mid-loop refuses later tool calls, but `abort_loop` still works with the bound id.
- **Two registries.** `aios_agent_loop_init` (T-03268, data model) still creates INIT-only loops in its own registry, which the service cannot drive. `aios_agent_loop_status` can read both registries (T-03296). Use `aios_agent_loop_start` for running loops.
- **Tokens travel as tool arguments.** MCP has no secret-argument channel, so `capability_token` can appear in client transcripts. The exposure is bounded because the grant is single-use and bound to one loop. Responses never echo it. A schema error for a token over 256 chars does echo a truncated copy back to the same caller.
- **Timeouts report uncertainty.** A mutating call that hits the 15 s bound may still finish in its worker thread. The envelope says the outcome is unknown.
- **Server-local view.** `list` only shows loops held by this server process.
- **Caller-reported metrics.** `tokens_consumed` and `tool_args` are self-reported by the caller and only bounded, not verified.

## 9. Testing (automated battery, T-03313..T-03322)

The whole battery runs in CI as suite #34 `agent_loop_battery` (`tools/ci_suites.py`). Run it locally from the repo root:
```bash
python -m pytest -q -p no:cacheprovider -k "agent_loop or audit_chain_concurrency or grant_scope or secret_masking" code/aiosh-mcp/tests
```
It takes about 75 s on a laptop.

| Part | File | What it proves |
|---|---|---|
| Scenario tests | `tests/test_agent_loop_{data_model,core_service,cli,mcp,config}_*.py` | Hand-picked valid, invalid, boundary and abuse cases per surface |
| Model-based fuzz | `tests/test_agent_loop_fuzz.py`, `tests/agent_loop_model.py` | For each seed, random op sequences (start/advance/abort/complete/revoke/snapshot/foreign_start) run against the real service and gate. After **every** op it checks: the outcome or error code matches a spec-derived model (M1); the exact audit rows appended (M2); snapshot invariants (M3); terminal states are absorbing (M4); one start row and one `run_id` per loop (M5). At the end the chain verifies |
| Model unit tests | `tests/test_agent_loop_model_unit.py` | Pins every rule the model encodes, so model drift fails directly |
| Multi-process stress | `tests/test_agent_loop_stress.py` | 4 processes x 5 loops x 6 turns on one ring: exact row counts, unique ids, no chain fork |
| Cross-substrate | `tests/test_agent_loop_cross_substrate.py` | A TS `aiosh grant create` grant is redeemed by the Python service on a shared, verifying chain. Skips with a reason if `node` or `dist/` is missing |
| Isolation guard | `tests/test_agent_loop_battery_isolation.py` | Tests never write to the real `$AIOSH_HOME` or leave files in the package; production code never imports the allow-all test gate |

Fuzz knobs: `AIOSH_LOOP_FUZZ_SEEDS` (comma list, default `1,2,3,4,5`), `AIOSH_LOOP_FUZZ_OPS` (default 200), and
`AIOSH_LOOP_FUZZ_MAX_S` (default 120; exceeding it is a reported failure). A failure prints `seed=N op#K` and the last 20 ops.
Replay it exactly:
```bash
cd code/aiosh-mcp && AIOSH_LOOP_FUZZ_SEEDS=4 AIOSH_LOOP_FUZZ_OPS=1000 python -m pytest -q tests/test_agent_loop_fuzz.py -k matches_reference
```

Testing limitations:
- The fuzz model covers the service API. The CLI and MCP layers are exercised by scenario and stdio tests, not by the fuzzer.
- Time-based paths (total timeout) are covered by scenario tests only.
- The stress test uses one host and one SQLite file. Network filesystems are untested.
- About 136 other aiosh-mcp tests need the Rust `aiosh-mcp.exe` built (`cargo build`) and fail with `WinError 2` without it. They are outside this battery.

## 8. Evidence

- T-03273 research: [T-03273-core-service-research.md](tasks/evidence/T-03273-core-service-research.md)
- T-03274 spec: [T-03274-core-service-specification.md](tasks/evidence/T-03274-core-service-specification.md)
- T-03276 implementation: [T-03276-core-service-implementation.md](tasks/evidence/T-03276-core-service-implementation.md)
- T-03277 unit tests: [T-03277-core-service-unit-test.md](tasks/evidence/T-03277-core-service-unit-test.md)
- T-03278 integration: [T-03278-core-service-integration.md](tasks/evidence/T-03278-core-service-integration.md)
- T-03279 security review: [T-03279-security.md](tasks/evidence/T-03279-security.md)
- T-03280 hardening: [T-03280-core-service-hardening.md](tasks/evidence/T-03280-core-service-hardening.md)
- T-03293..T-03300 MCP/API: [research](tasks/evidence/T-03293-research.md), [spec](tasks/evidence/T-03294-spec.md), [scaffold](tasks/evidence/T-03295-mcp-api-surface-scaffold.md), [implementation](tasks/evidence/T-03296-mcp-api-surface-implementation.md), [unit](tasks/evidence/T-03297-mcp-api-surface-unit-test.md), [integration](tasks/evidence/T-03298-mcp-api-surface-integration.md), [security](tasks/evidence/T-03299-security.md), [hardening](tasks/evidence/T-03300-mcp-api-surface-hardening.md)
- T-03343..T-03350 documentation: [research](tasks/evidence/T-03343-research.md), [spec](tasks/evidence/T-03344-spec.md), [implementation](tasks/evidence/T-03346-documentation-implementation.md), [drift test](tasks/evidence/T-03347-documentation-unit-test.md), [integration](tasks/evidence/T-03348-documentation-integration.md), [security](tasks/evidence/T-03349-security.md), [hardening](tasks/evidence/T-03350-documentation-hardening.md)
- T-03333..T-03340 observability: [research](tasks/evidence/T-03333-research.md), [spec](tasks/evidence/T-03334-spec.md), [implementation](tasks/evidence/T-03336-observability-implementation.md), [unit](tasks/evidence/T-03337-observability-unit-test.md), [integration](tasks/evidence/T-03338-observability-integration.md), [security](tasks/evidence/T-03339-security.md), [hardening](tasks/evidence/T-03340-observability-hardening.md)
- T-03323..T-03330 security policy: [research](tasks/evidence/T-03323-research.md), [spec](tasks/evidence/T-03324-spec.md), [implementation](tasks/evidence/T-03326-security-policy-implementation.md), [unit](tasks/evidence/T-03327-security-policy-unit-test.md), [integration](tasks/evidence/T-03328-security-policy-integration.md), [security](tasks/evidence/T-03329-security.md), [hardening](tasks/evidence/T-03330-security-policy-hardening.md)
- T-03313..T-03320 automated tests: [research](tasks/evidence/T-03313-research.md), [spec](tasks/evidence/T-03314-spec.md), [implementation](tasks/evidence/T-03316-automated-tests-implementation.md), [unit](tasks/evidence/T-03317-automated-tests-unit-test.md), [integration](tasks/evidence/T-03318-automated-tests-integration.md), [security](tasks/evidence/T-03319-security.md), [hardening](tasks/evidence/T-03320-automated-tests-hardening.md)
- T-03303..T-03310 configuration: [research](tasks/evidence/T-03303-research.md), [spec](tasks/evidence/T-03304-spec.md), [implementation](tasks/evidence/T-03306-configuration-implementation.md), [unit](tasks/evidence/T-03307-configuration-unit-test.md), [integration](tasks/evidence/T-03308-configuration-integration.md), [security](tasks/evidence/T-03309-security.md), [hardening](tasks/evidence/T-03310-configuration-hardening.md)
- T-03283..T-03290 CLI: [research](tasks/evidence/T-03283-research.md), [spec](tasks/evidence/T-03284-spec.md), [implementation](tasks/evidence/T-03286-cli-surface-implementation.md), [unit](tasks/evidence/T-03287-cli-surface-unit-test.md), [integration](tasks/evidence/T-03288-cli-surface-integration.md), [security](tasks/evidence/T-03289-security.md), [hardening](tasks/evidence/T-03290-cli-surface-hardening.md)
