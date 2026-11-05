# T-03341 Evidence: Agent Loop Hardening — observability Documentation

- Date: 2026-11-05
- `docs/SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE.md`, new **§5b Observability**: what the metrics contain; trusted-writer filtering;
  health semantics over the fixed window; cost bounds; logger behaviour and how a host enables it; measured durations; a copy-pasteable
  `metrics` command with verbatim output; limitations. §6 adds `LOOPOBS_ERR_READ`; §8 links the 7 observability evidence files (all resolve).

## Example verified
A fresh `AIOSH_HOME`, a TS-issued grant, and the §4a-style plan run through `agent_loop_cli run`, then:
```
$ python -m aiosh_mcp.agent_loop_cli metrics
health: ok
window: 5 row(s) (ids 3..7)
events: start=1, step=3, complete=1
steps: ok=2 refused=1 irreversible_ok=0 duration_ms p50=6.451 p95=14.029 max=14.029
refusals: constitution=1
```
`--json` ring keys: `degraded_config_rows, events, irreversible_by_grant, irreversible_grants_total, refusals, steps, window` (as documented).

## Limitations stated
The CLI has no live counters; a writer forging the gate's actor_id is still counted; grant hashes are unsalted (fine for production 64-bit ids).
