# T-03310 Evidence: Agent Loop Hardening — configuration Hardening

- Date: 2026-11-05
- Files: `aiosh_mcp/agent_loop_config.py` (`process_config`, `reset_process_config`, `audit_degraded`), service, gate, MCP, CLI;
  `tests/test_agent_loop_config_hardening.py` (5 cases)

## Gaps closed
| Gap | Fix |
|---|---|
| Each consumer called `resolve()` on its own, at different times. The config tool could report values the service or gate were not using, and an env change mid-process split the view. | **One resolution per process** (`process_config()`). Service capacity, gate busy timeout (now fixed at construction, no longer lazy) and the MCP tools all read it. |
| Falling back to defaults on a bad config is a **fail-open** that left no trace in the audit ring (ADR-0035 §F-2). | `audit_degraded()` writes one `aios.agent_loop.config` row with outcome `degraded` (rejected keys, file status, masked errors, at most 20). The MCP config tool reports `degraded: true`. |
| The audit write itself could fail at import. | Never raises. The failure is appended to `errors` and visible in the config tool, which is the honest report. |
| `agent_loop_cli config` exited 0 even with rejected inputs, so a bad deployment config was invisible to CI. | `config --strict` exits 2 (`AGENTLOOPCONF_ERR_STRICT`) when anything was rejected or adjusted. |

Bounds, size caps and special-file handling were done in T-03309. Config resolution starts no processes, holds no
connections (the audit write uses `closing()`) and creates no temp files.

## Test isolation fix
The degraded-config row is written to `$AIOSH_HOME/audit.db`. The T-03308 integration fixture now sets `AIOSH_HOME` to a temp dir and resets
the process config. Checked: the developer ring (`~/.aios/audit.db`) has **0** `aios.agent_loop.config` rows after the runs.

## Tests
```
5 passed in 2.48s
299 passed, 1 skipped, 929 deselected, 1 warning in 39.57s
```
Covered: consumers agree with the config tool, and a later env change does not split them; a degraded config gives exactly one row
across two registrations; a clean config writes no row; an unwritable ring is reported, not raised; `--strict` gives exit 2 / 0.
