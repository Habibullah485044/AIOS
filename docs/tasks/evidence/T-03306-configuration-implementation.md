# T-03306 Evidence: Agent Loop Hardening — configuration Implementation

- Date: 2026-11-05
- Implemented `code/aiosh-mcp/aiosh_mcp/agent_loop_config.py` per T-03304. It provides `default_config`, `hygiene_ok` (CWE-15), `validate`,
  `resolve` (argument -> per-field env -> file -> default, then clamp; returns `{config, source, errors}` and never raises), and
  `loop_config_for` (resolved defaults plus explicit per-call values).
- Reused the `compliance_config.py` house pattern: the same precedence ladder, hygiene predicate, 64 KiB bounded file read and source labels.
  Stdlib only, **no new dependencies**.
- Locked controls (grant redemption, audit writes, args cap and depth, input caps) are rejected as `AGENTLOOPCONF_ERR_LOCKED`,
  never applied (AGENTLOOPCONF-INV2).
- Read-only: no file writes, no audit rows. **No consumer is wired yet.** Service capacity, gate busy timeout and MCP bounds still use
  their constants until T-03308 (Integration), so runtime behaviour is unchanged by this task.

## Test-first
`tests/test_agent_loop_config_impl.py` was written first: **6 failed** (stubs raised `NotImplementedError`). After:
```
9 passed in 2.14s
202 passed, 909 deselected in 22.94s   (all agent-loop suites, no regression)
```
Covered: pure defaults; all four precedence levels in one resolution; env path hygiene (`../../etc/...` -> `env_invalid`);
reported clamping; `loop_config_for` (explicit wins, None keeps the default, result passes `validate_bounds`); `validate` rejecting
unknown and locked keys. The scaffold's stub-must-raise test was removed because it no longer applies.

## Fail-closed smoke (spec §4)
```
oversize  file=config_invalid  defaults_kept=True err=AGENTLOOPCONF_ERR_FILE_SIZE
badjson   file=config_invalid  defaults_kept=True err=AGENTLOOPCONF_ERR_PARSE
array     file=config_invalid  defaults_kept=True err=AGENTLOOPCONF_ERR_PARSE
locked    file=config_invalid  defaults_kept=True err=AGENTLOOPCONF_ERR_LOCKED
unknown   file=config_invalid  defaults_kept=True err=AGENTLOOPCONF_ERR_UNKNOWN_KEY
nonnum    file=config_invalid  defaults_kept=True err=AGENTLOOPCONF_ERR_PARSE
missing   file=config_invalid  defaults_kept=True err=AGENTLOOPCONF_ERR_IO
env bad   source= env_invalid value= 25
```
