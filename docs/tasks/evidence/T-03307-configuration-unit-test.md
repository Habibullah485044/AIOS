# T-03307 Evidence: Agent Loop Hardening — configuration Unit Test

- Date: 2026-11-05
- Test file: `code/aiosh-mcp/tests/test_agent_loop_config_unit.py` (40 cases, standalone; env cleared and CWD isolated per test)

| Area | Cases |
|---|---|
| Boundaries | every one of the 10 fields: both edges accepted with no error; one step past each edge clamped and reported (`AGENTLOOPCONF_ERR_BOUNDS`) |
| Valid input | numeric strings from env (`" 2.5 "`, `"12"`); default file `docs/agent_loop_config.json` picked up when present |
| Invalid file (fail closed) | oversize, bad JSON, array, deep nesting, bad UTF-8, non-numeric, bool, null, unknown key, locked key, locked key next to a valid key: **whole file ignored**, defaults kept, error code reported |
| Other failures | missing file -> `IO`; bad env value -> `env_invalid` and the lower level kept; locked, unknown or non-numeric overrides reported and not applied |
| Hygiene predicate | 12 inputs incl. empty, `..`, NUL/LF/DEL, 1024 vs 1025 chars, `None`, int: total, never raises |
| Invariants | every resolved key has a `source` in `CONFIG_SOURCES` (INV3); `loop_config_for` rejects unknown fields |

## Defect found and fixed
A non-numeric string override or file value produced Python's bare `could not convert string to float: 'x'`, which did not name the field.
`_number` now reports `<key>: 'x' is not a number`.

## Fails when broken
Mutation: the locked-key check was disabled (`if False and key in LOCKED_KEYS`):
```
FAILED ...test_defective_file_is_ignored_entirely[locked-key]
FAILED ...test_defective_file_is_ignored_entirely[locked-plus-valid]
FAILED ...test_bad_overrides_reported_not_applied
3 failed, 37 passed
```
After restoring it:
```
40 passed in 0.65s
242 passed, 909 deselected in 26.45s   (all agent-loop suites)
```
