# T-03311 Evidence: Agent Loop Hardening — configuration Documentation

- Date: 2026-11-05
- `docs/SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE.md`, new **§4b Configuration**: precedence ladder; the 10 tunables with defaults, bounds and env names
  (including the busy-wait coupling); the 9 locked controls; what makes a file be ignored; fail-open-to-defaults plus the degraded
  audit row; an example `docs/agent_loop_config.json`; a copy-pasteable `config --strict` check and its expected output; the JSON fields; limitations.
- §5 now lists the `init` and `config` rows, `run_id` and single-use loop ids. §8 links the 7 configuration evidence files (all links resolve).

## Example verified, and the doc gap it exposed
The documented command was run in a scratch dir holding the documented example file:
```
$ AIOSH_AGENT_LOOP_SNAPSHOT_STEPS_TAIL=many python -m aiosh_mcp.agent_loop_cli config --config docs/agent_loop_config.json --strict
default_max_iterations               10           (file)
default_max_total_tokens             32768        (default)
default_timeout_ms_per_step          30000.0      (default)
default_total_timeout_ms             300000.0     (default)
default_consecutive_failure_limit    3            (default)
registry_capacity                    32           (file)
mcp_call_timeout_s                   20.0         (file)
history_page_bytes                   1048576      (default)
snapshot_steps_tail                  100          (default)
db_busy_timeout_ms                   5000         (default)
config file: file
warning: AGENTLOOPCONF_ERR_ENV: AIOSH_AGENT_LOOP_SNAPSHOT_STEPS_TAIL is not a finite number
error [AGENTLOOPCONF_ERR_STRICT] (exit 2): 1 configuration input(s) rejected or adjusted
exit=2
```
The first run showed only the error line: on a `--strict` failure the CLI hid the table, which is exactly what an operator needs.
`render` now always prints the table, then the strict error. The output above matches the doc's "Expected" sentence.

## Limitations stated
No hot reload (config is read once per process); the default file path is relative to the server CWD; per-loop budgets can still be overridden within bounds.
