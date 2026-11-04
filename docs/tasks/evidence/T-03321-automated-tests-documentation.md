# T-03321 Evidence: Agent Loop Hardening — automated tests Documentation

- Date: 2026-11-05
- `docs/SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE.md`, new **§9 Testing**: how to run the battery locally (the exact CI suite #34 command);
  a table of the six parts (scenario tests, model-based fuzz M1..M5, model unit tests, multi-process stress, cross-substrate, isolation guard)
  and what each proves; the fuzz env knobs; how to replay a failing seed; limitations. §8 links the 7 automated-test evidence files (all resolve).

## Examples verified
- Battery command: run as CI suite #34 in T-03318 (347 passed, 1 skipped, about 72 s); the doc says about 75 s.
- Replay command, run verbatim:
```
$ cd code/aiosh-mcp && AIOSH_LOOP_FUZZ_SEEDS=4 AIOSH_LOOP_FUZZ_OPS=1000 python -m pytest -q tests/test_agent_loop_fuzz.py -k matches_reference
1 passed, 2 deselected in 24.24s
```
  That is a clean 1000-op run, 5x the CI default.

## Limitations stated
The fuzzer covers the service API, not the CLI/MCP layers. Time-based paths are covered by scenarios only. Stress runs on a single host with
local SQLite. 136 non-battery tests need the Rust binary.
