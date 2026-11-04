# T-03287 Evidence: Agent Loop Hardening — CLI surface Unit Test

- Date: 2026-11-05
- Test file: `code/aiosh-mcp/tests/test_agent_loop_cli_unit.py` (32 cases, standalone)

| Area | Cases |
|---|---|
| Valid / boundary | plans of exactly 1 and 100 turns accepted; `--max-iterations 1` with 3 turns -> FAILED, `turns_skipped=2`, no complete row |
| Invalid plans (exit 2, `LOOPCLI_ERR_PLAN`) | bad JSON, non-object, 0 turns, 101 turns, extra top-level key, empty intent, unknown turn key, injected tool name, non-object args, bool/negative tokens, non-bool policy; >1 MiB file; missing file |
| Usage (exit 2) | no subcommand, unknown subcommand, missing required flags, NUL byte, `--limit` 0 / 1001 / non-int |
| Grant safety | invalid `loop_id` and invalid plan both exit 2 with **zero audit rows**, so the grant stays redeemable |
| Primary failures | replayed grant -> exit 3; audit failure -> exit 1 `LOOPSERV_ERR_AUDIT` |
| History | missing DB -> empty and **no file created** (read-only); `--limit` respected; events filtered to one `loop_id` |
| Output contract | `--json` exit-code parity on failure; secrets masked in JSON and human output |

## Fails when broken
Mutation: in `_cmd_run`, `load_plan` was moved after `start_loop`, which violates LOOPCLI-INV3.
```
FAILED tests/test_agent_loop_cli_unit.py::test_invalid_plan_does_not_spend_grant
1 failed, 31 passed
```
After restoring with `git checkout`:
```
32 passed in 1.17s
```
