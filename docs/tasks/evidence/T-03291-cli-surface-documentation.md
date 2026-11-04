# T-03291 Evidence: Agent Loop Hardening — CLI surface Documentation

- Date: 2026-11-05
- Updated `docs/SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE.md`. New **§4a Operator CLI** covers: subcommands, token sources (recommends
  `--token-env`), plan schema, a copy-pasteable bash session, expected output, exit codes 0/1/2/3/4/130, and CLI limitations.
  §5 adds the `aios.agent_loop.complete` row; §8 links the 7 CLI evidence files.
- Updated `code/aiosh-mcp/README.md` (Agent Loop Tools section): it now names the CLI and the console script.

## Example verified end-to-end, cross-substrate
The documented session was run against a fresh `AIOSH_HOME`. The grant was issued by the **real TS CLI**
(`node code/aiosh-cli/dist/cli.js grant create --to agent:planner --tools "aios.agent_loop.start,aios.fs.read" --ttl 900`)
and redeemed by the Python CLI. `jq` is not installed on this host, so `grant_id` was extracted with a Python one-liner;
the JSON path `.data.grant_id` is the same.
```
plan OK: 2 turn(s)
[0] ok      aios.fs.read
[1] refused fs.write  LOOPSERV_ERR_POLICY_REFUSED: Policy evaluation refused tool invocation: tool 'fs.write' not in grant scope.tools
loop loop-ops-demo-01: COMPLETED (2 turn(s), 1 refused, 0 skipped)
exit=0
     3 2026-11-04T20:50:27.276154Z aios.agent_loop.start    ok
     4 2026-11-04T20:50:27.295545Z aios.agent_loop.step     ok
     5 2026-11-04T20:50:27.314450Z aios.agent_loop.step     refused
     6 2026-11-04T20:50:27.326785Z aios.agent_loop.complete ok
4 event(s) for loop-ops-demo-01
```
The `validate` and `run` lines match the "Output" block in §4a exactly.

## Limitations stated in the doc
No interactive per-turn mode; `history` is token-less (file permissions are the boundary); `--token` is kept for compatibility;
plan `tokens_consumed` values are declared, not measured.
