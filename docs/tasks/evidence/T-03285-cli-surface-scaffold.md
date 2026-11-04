# T-03285 Evidence: Agent Loop Hardening — CLI surface Scaffold

- Date: 2026-11-05
- New module: `code/aiosh-mcp/aiosh_mcp/agent_loop_cli.py`. It defines exit codes 0..4; limits (`MAX_PLAN_BYTES` 1 MiB,
  `MAX_PLAN_TURNS` 100, history limit 1..1000); `PlanTurn`, `CliResult` and `PlanError`;
  `load_plan`, `dispatch_cli`, `render` and `main`; and a `python -m` entry guard.
- Service extension (spec D2): `AgentLoopService.complete_loop(loop_id, capability_token)`, stubbed.
- Every body raises `NotImplementedError("T-03286: ...")`.

## Build / import
```
$ python -c "import aiosh_mcp.agent_loop_cli, aiosh_mcp.server; print('import ok')"
import ok
```

## Call sites / test stubs
`code/aiosh-mcp/tests/test_agent_loop_cli_scaffold.py` (9 cases) imports every new interface. It asserts the exit-code
taxonomy and the `PlanTurn` defaults, and checks that all 5 CLI stubs and `complete_loop` fail loudly.
```
95 passed, 909 deselected in 4.98s
```
