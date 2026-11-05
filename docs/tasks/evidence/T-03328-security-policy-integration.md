# T-03328 Evidence: Agent Loop Hardening — security policy Integration

- Date: 2026-11-05

## Wired into the production surfaces
| Surface | Change |
|---|---|
| `LoopStepRecord` | optional `policy` = `{verdict, rule_ids, irreversible[, irreversible_used]}`; `to_dict`/`from_dict` round-trip it, and the key is omitted when unset, so older snapshots parse unchanged |
| MCP `aios_agent_loop_advance` / `snapshot` | the step dict now carries `policy` |
| `read_loop_history` (MCP `aios_agent_loop_history` + CLI `history`) | events add `verdict` and `rule_ids` from the classifier columns (T-03326); `None`/`[]` for non-step events and pre-T-03326 rows |
| CLI `run` (human output) | refused and flagged steps show their rule ids, e.g. `[0] refused fs.write  [R-03,R-07]  LOOPSERV_ERR_POLICY_REFUSED: ... LOOPPOL_ERR_CONSTITUTION ...` |

## Cross-substrate
`test_ts_max_irreversible_is_enforced_by_python_loop`: `aiosh grant create --tools aios.agent_loop.start,pentest.* --networks 10.0.0.0/24 --max-irreversible 1` (**TS issuer**)
leads to a Python loop where the first `pentest.nmap` is ok and the second is refused (`LOOPPOL_ERR_IRREVERSIBLE_BUDGET: used 1 of 1`), on one verifying chain.
**This is the first place in the repo where `--max-irreversible` has any effect** (T-03323 F4).

## Integration smoke
`tests/test_agent_loop_policy_integration.py`: TS budget; a real `python -m aiosh_mcp.server` stdio session (policy on the advance response,
R-03 on the refused `fs.write`, history verdicts `["ok","refused"]`, identical to the CLI reader); CLI rule ids.
```
3 passed in 5.99s
389 passed, 1 skipped, 908 deselected, 1 warning in 99.99s (0:01:39)   (CI battery scope)
```
