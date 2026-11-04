# T-03290 Evidence: Agent Loop Hardening — CLI surface Hardening

- Date: 2026-11-05
- Files: `code/aiosh-mcp/aiosh_mcp/agent_loop_cli.py`, `code/aiosh-mcp/tests/test_agent_loop_cli_hardening.py` (10 cases after the follow-up fix)

## Failure modes -> explicit, auditable outcomes
| Failure | Before | After |
|---|---|---|
| Ctrl-C mid-`run` | Loop left open in the audit ring forever (start/steps, no terminal row) | Loop **aborted and audited** (`aios.agent_loop.abort`, detail `cli run interrupted: KeyboardInterrupt`), exit **130** `LOOPCLI_ERR_INTERRUPTED` |
| Unexpected crash mid-`run` | Same as above, exit 1 | Same honest abort row; exit 1 `LOOPCLI_ERR_INTERNAL` |
| `history` on a DB without `audit_ring` | `OperationalError` caught by the catch-all | Empty event list, exit 0 |
| `history` on a corrupt file | Unclassified internal error | exit 1 `LOOPCLI_ERR_AUDIT_READ` |
| Locked audit DB on read | Implicit default wait | Explicit `timeout=5.0 s` bounded wait (`HISTORY_DB_TIMEOUT_S`) |
| stdout closed (`... \| head`) | Traceback (`BrokenPipeError` on POSIX, `OSError` EINVAL on Windows) | Exit code preserved, no traceback (stdout redirected to devnull); fixed in the follow-up PR |

Fail-open never occurs. Every path either refuses or writes an honest terminal audit row (ADR-0035 §F-2).

## Resource cleanup
- The `history` connection is closed in `finally` on every path, opened read-only (`mode=ro`).
  `test_history_does_not_modify_db` asserts the DB bytes are identical afterwards.
- The CLI creates no temp files and spawns no child processes. Gate DB handles are covered by T-03280's leak test.

## Real pipe check — correction (follow-up fix PR)
The first version of this evidence, merged in PR #400, claimed "no traceback" without having verified it.
The real check **failed** on Windows. A closed pipe raises `OSError: [Errno 22] Invalid argument`, not
`BrokenPipeError`, so the handler missed it (traceback, exit 120).

The follow-up fix catches `OSError` on the final write and flush. It also adds two tests: a simulated
`EINVAL` and a real subprocess whose stdout reader closes immediately (asserts no `Traceback` and exit 0).
```
$ python -m aiosh_mcp.agent_loop_cli validate --plan plan.json | head -c 0
pipe exit=0      (no traceback on stderr)
```

## Tests
```
8 passed in 1.20s
148 passed, 909 deselected in 8.60s   (all agent-loop suites)
```
