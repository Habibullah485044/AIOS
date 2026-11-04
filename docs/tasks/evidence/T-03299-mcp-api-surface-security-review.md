# T-03299 Security Review: Agent Loop Hardening — MCP/API surface

- Date: 2026-11-05
- Scope: `aiosh_mcp/agent_loop_mcp.py` (7 tools), the service paths they call, `read_loop_history`, and the `aios_agent_loop_status` fallback.

## Findings
| # | Severity | Finding | Status |
|---|---|---|---|
| M2 | **Medium** (audit evasion, CWE-778) | `tool_args` of any size was accepted, then **silently truncated** to 64 KiB in the step record and the audit row. A caller could put benign args first and the real payload after the cut, so the audit trail would not show what ran. Probe: a 5 MB arg was accepted with `ok=true`. | **Fixed** in the service (covers MCP + CLI): args larger than 64 KiB (`str` or JSON form) -> `LOOPSERV_ERR_INVALID_INPUT`, nothing recorded |
| M3 | Low (DoS) | Hostile nesting (5000 levels) was accepted. | **Fixed**: an iterative depth check rejects depth > 32 without recursion |
| M1 | Info | A pydantic schema error for an over-long `capability_token` echoes a truncated copy of the value **back to the same caller**. It is not written to server logs (probe: logging captured at DEBUG). | Accepted: the caller already holds that value. Service-level errors never echo tokens (tested). |
| M4 | — | Forged token, or another loop's grant, on advance/abort/complete | Not vulnerable (T-03279 binding); re-tested over MCP |
| M5 | — | `policy_allowed=true` for an out-of-scope tool | Not vulnerable: refused by the grant scope re-check |
| M6 | — | `readOnlyHint` tools could be auto-approved by clients | Verified truthful: snapshot/list/history leave both state and the audit ring unchanged |
| M7 | — | Secrets in args surfacing via snapshot/history | Not vulnerable: masked |
| M8 | — | Injection-shaped `loop_id` | Rejected by the schema pattern; the history SQL is parameterised and read-only anyway |
| M9 | Accepted | `list`/`history`/`snapshot` need no token | By design (spec). The stdio server is single-client, and `audit.db` file permissions are the boundary. |

## Abuse scenarios -> tests (`tests/test_agent_loop_mcp_security.py`, 9 cases)
M2 oversized-args rejection plus "args under the cap are audited in full" (no `[TRUNCATED]`), M3 nesting, M4 forged/cross-loop on 3 tools,
M5 self-approval, M6 read-only truthfulness, M1 no token in envelopes, M7 masking, M8 injection-shaped id.

**Fails when broken:** removing the new `_validate_tool_args` call makes `test_m2_oversized_args_rejected_not_truncated`
and `test_m3_hostile_nesting_rejected` fail (2 failed, 7 passed). After restoring, 9 pass.

## PEP gating and audit (PoR I-2 standing rule)
State-changing tools: `start` redeems a grant; `advance`/`abort`/`complete` need the loop-bound grant. Each writes exactly one audit row.
The new M2 rejection happens **before** any state change or audit write. Read-only tools write nothing. **No known policy bypass remains open.**

## Verification
```
189 passed, 909 deselected in 19.31s
```
