# T-03290 Evidence: Agent Loop Hardening — CLI surface Hardening

- Date: 2026-11-05
- Files: `code/aiosh-mcp/aiosh_mcp/agent_loop_cli.py`, `code/aiosh-mcp/tests/test_agent_loop_cli_hardening.py` (8 cases)

## Failure modes -> explicit, auditable outcomes
| Failure | Before | After |
|---|---|---|
| Ctrl-C mid-`run` | Loop left open in the audit ring forever (start/steps, no terminal row) | Loop **aborted and audited** (`aios.agent_loop.abort`, detail `cli run interrupted: KeyboardInterrupt`), exit **130** `LOOPCLI_ERR_INTERRUPTED` |
| Unexpected crash mid-`run` | Same as above, exit 1 | Same honest abort row; exit 1 `LOOPCLI_ERR_INTERNAL` |
| `history` on a DB without `audit_ring` | `OperationalError` caught by the catch-all | Empty event list, exit 0 |
| `history` on a corrupt file | Unclassified internal error | exit 1 `LOOPCLI_ERR_AUDIT_READ` |
| Locked audit DB on read | Implicit default wait | Explicit `timeout=5.0 s` bounded wait (`HISTORY_DB_TIMEOUT_S`) |
| stdout closed (`... \| head`) | `BrokenPipeError` traceback | Exit code preserved, no traceback (stdout redirected to devnull) |

Fail-open never occurs. Every path either refuses or writes an honest terminal audit row (ADR-0035 §F-2).

## Resource cleanup
- The `history` connection is closed in `finally` on every path, opened read-only (`mode=ro`).
  `test_history_does_not_modify_db` asserts the DB bytes are identical afterwards.
- The CLI creates no temp files and spawns no child processes. Gate DB handles are covered by T-03280's leak test.

## Real pipe check
```
$ python -m aiosh_mcp.agent_loop_cli validate --plan plan.json | head -c 0
pipe exit=120   (no traceback on stderr)
```

## Tests
```
8 passed in 1.20s
148 passed, 909 deselected in 8.60s   (all agent-loop suites)
```
