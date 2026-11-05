# T-03379 Security Review: Tool Registry & Taxonomy — core service

- Date: 2026-11-06
- Scope: `aiosh_mcp/tool_registry_service.py` and its production hooks, `_dispatch._registry_require_grant` and
  `agent_loop_policy._registry_irreversible`.
- Method: an **independent read-only reviewer subagent** was given the code and spec only. I reproduced findings #1, #2 and #7
  myself before fixing them (1 000 identical calls gave 1 000 stderr lines; `AIOSH_TOOL_REGISTRY_MODE=strct` → `require_grant False`;
  `sys.stderr=None` → the event was printed to **stdout**). Every fix has a regression test, run against the pre-fix code.
- Reviewer's headline: **no loosening found.** Both hooks OR with the legacy result.

## Findings
| # | Sev | Finding | Status |
|---|---|---|---|
| 1 | **Medium** | **Shadow mode could stall tool calls.** `report()` wrote a flushed stderr line on *every* disagreeing call. Recurring names include `aios.task`, `aios.audit.*`, the offline pentest tools, and nearly every agent-loop tool. With an undrained stderr pipe (common for MCP hosts), calls blocked after about 21 writes; in the agent loop that happens while the service lock is held. This breaks TOOLSVC-INV2. | **Fixed:** each distinct (surface, masked tool, disagreements) is logged **once**, with at most `MAX_REPORT_LINES = 32` lines per process. Suppressed lines are counted in `report_stats()`. Probe: a child whose stderr is never read now completes **> 1 000** calls in 3 s; the old code hung. |
| 2 | **Medium** | **Strict mode could silently turn off.** An unrecognised env value (`strct`, `enforce`, fullwidth `ｓｔｒｉｃｔ`) raised `ToolServiceError`. The hooks caught it and fell back to legacy-only, with one generic log line in dispatch and none in the agent loop. Any other exception also dropped strict. | **Fixed:** `intended_mode()` NFKC-normalises the value. Unset or empty means shadow; **any other unrecognised value means strict (fail closed)**, with one warning naming the value. If the registry raises while strict was asked for, dispatch **requires a grant** and the agent loop **counts the step irreversible**. Both log once. |
| 3 | Medium (design) | **Strict covers less than INV5 says.** Nothing enforces `scope_kinds`, and about 45 MCP tools never pass through `dispatch()` (agent loop, model backend, MCP core), so strict cannot tighten them. | **Documented, not fixed in this task.** Strict tightens exactly two things: the grant requirement in `dispatch()` and irreversibility in the agent loop. The scope check is reported, not enforced. The agent-loop tools already require redeemed tokens through their own gate. This is recorded as a limitation for the docs task and a follow-up for a later epic (routing those surfaces through the service). |
| 4 | Low | The process singleton keeps its first mode, and a failed build was retried on **every** call. | Mode fixed at first use is intended, like the process config (T-03310), and is now documented in `service()`. **Fixed:** a failed build is remembered and re-raised, not retried. |
| 5 | Low | `report()` masked `tool` but not `canonical`, which for an unregistered well-formed name *is* the raw name (for example a Slack token). | **Fixed:** `canonical` is masked and bounded too. (A bare 40-hex string is not matched by `mask_secrets` at all; that is a shared pattern limitation, noted as an existing follow-up.) |
| 6 | Low | Unregistered-name samples were plain `sha256(name)[:12]`, which can be reversed by dictionary and linked across processes. `disagreements` was not sorted, as the spec said. | **Fixed:** HMAC with a per-process random key, and sorted disagreements. `unregistered` counts unregistered *decisions*, as documented in T-03376. |
| 7 | Low | With `sys.stderr` missing, `print(file=None)` wrote the event to **stdout**, which is the MCP JSON-RPC channel. The dispatch fallback had the same problem. | **Fixed:** `_stderr_line()` never writes to stdout (it skips if stderr is `None` or is stdout) and never raises. Both hooks use it. |
| 8 | Info | Strict will refuse `aios.task`, `aios.audit.segments` and `aios.audit.seen` without a grant, and spend the irreversible budget on unregistered agent-loop tools. | Intended (INV5). Coverage comes before anyone should enable strict; documented. |
| 9 | Info | Cost is about 70 µs per unregistered decision and about 100 µs per hook. | Bounded, accepted. |

Fine (reviewer): case and whitespace variants of the mode parse; JSON with `ensure_ascii` blocks newline injection; no audit rows or DB
access; counters are locked; the singleton is built safely; strict only ORs; grant validity stays in `grant_check` / `grant_redeem`.

## Regression tests (`code/aiosh-mcp/tests/test_tool_registry_service_security.py`, 13)
Result on pre-fix code: **11 of 13 fail.** The 2 that pass pin behaviour that was already right: `"STRICT "` parses as strict, and an
empty value means shadow. The undrained-pipe test previously **hung** on the old code; it now fails cleanly there after 30 s
("child blocked on a full stderr pipe") and passes on the new code.
```
$ python -m pytest tests/ -k tool_registry -q
184 passed, 1437 deselected, 1 warning in 20.78s
```
Existing tests updated: a bogus env value now means strict (was: raise), and tests that assert log lines reset the process-wide
report state.

## PoR standing rule
The service adds no audit rows (I-3), never loosens a grant decision (I-2), and now fails closed when strict was requested. **No bypass.**
