# T-03288 Evidence: Agent Loop Hardening — CLI surface Integration

- Date: 2026-11-05

## Production call paths / registration points
| Surface | Change |
|---|---|
| Console script | `code/aiosh-mcp/pyproject.toml` `[project.scripts] aiosh-agent-loop = "aiosh_mcp.agent_loop_cli:main"`. Run `pip install -e code/aiosh-mcp` to create the launcher (the existing editable install was **not** re-installed by this task). |
| Module runner | `python -m aiosh_mcp.agent_loop_cli` (unchanged; exercised as a real subprocess) |
| CI registry | `tools/ci_suites.py` suite #33 `agent_loop_integration` (tail append, existing indices stable); `tools/test_ci_suites.py` frozen order and count updated (32 -> 33) |
| MCP | Already registered in T-03278. Parity with it is checked below. |

## Cross-substrate parity (shared SQLite audit ring)
`test_cli_and_mcp_parity_on_shared_ring` runs the same 3-turn plan once through the CLI and once through the MCP tools,
both against **one** audit DB. It asserts:
- identical step shapes `(step_index, tool_name, outcome, tokens_consumed)`, i.e. `ok`, `refused`, `ok`
- identical audit event sequences per loop (`start`, `step` x3, `complete`)
- the shared hash chain verifies (`audit_client.verify` -> `ok`)

## Integration smoke
`code/aiosh-mcp/tests/test_agent_loop_cli_integration.py`:
```
3 passed in 3.76s
```
Registered CI suite command, run from the repo root exactly as `tools/ci_run.py` would run it:
```
12 passed in 4.66s
```
CI tooling self-tests: `test_ci_config` OK, `test_ci_run` PASS, `test_ci_service` PASS (X1..X7), `test_ci_suites` PASS (W1..W7).
