# T-03346 Evidence: Agent Loop Hardening — documentation Implementation

- Date: 2026-11-05
- `agent_loop_doc.reference(section=None)` builds the reference **from code at call time** (LOOPDOC-INV2):
  | Section | Source |
  |---|---|
  | `tools` | a FastMCP instance with the agent-loop tools registered (`settings={}`, so no config or audit side effects). Gives name, first docstring line, annotations and `input_schema`. |
  | `errors` | every `*_ERR_*` constant in the 8 agent-loop modules (first definer wins), plus `ERROR_MEANINGS` |
  | `config` | `FIELDS` (default/min/max/type/env), `LOCKED_KEYS`, file env, default path, file cap |
  | `cli` | subcommands and flags from `agent_loop_cli._build_parser()` |
  | `policy` | the P1..P4 order, classifier revision, irreversible name set, target arg keys |
  The current output has 9 tools, 34 errors, 10 config fields and 5 CLI subcommands.
- **`LOOPSERV_ERR_CIRCUIT_BREAKER` is now real** (T-03343 F3). When a breaker (consecutive failures, token budget, iteration ceiling) ends a loop
  during `advance_turn`, `terminal_reason` is prefixed with the code. The wording after the prefix is unchanged, so existing substring checks still pass.
  Aborts and timeouts are not tagged.
- MCP/CLI exposure and the drift test come in T-03348 (integration) and T-03347 (unit), per the spec.

## Test-first
`tests/test_agent_loop_doc_impl.py` (5) on the scaffold code: **5 failed**. After:
```
5 passed in 3.07s
426 passed, 1 skipped, 950 deselected, 1 warning in 85.93s (0:01:25)   (agent-loop suites)
```
Covered: every section is derived from code; tool schemas are **identical to the live server's** `tools/list`; single and unknown sections;
the reference contains no environment **values** (a sentinel `AIOSH_HOME` is absent; env names and defaults are present); the breaker prefix appears on FAILED and not on an abort.
