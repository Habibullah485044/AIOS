# T-03335 Evidence: Agent Loop Hardening — observability Scaffold

- Date: 2026-11-05
- New `code/aiosh-mcp/aiosh_mcp/agent_loop_observability.py`:
  - library logger `aiosh_mcp.agent_loop` (no handlers)
  - `LOOPOBS_ERR_READ`, window bounds, `REFUSAL_REASONS` and `HEALTH_STATES`
  - stubs `classify_refusal`, `ring_metrics`, `health` and `log_event`
- New stub `AgentLoopService.stats()`.
- All stubs raise `NotImplementedError("T-03336: ...")`. Nothing is wired in yet.

```
$ python -c "import aiosh_mcp.agent_loop_observability, aiosh_mcp.server; print('import ok')"
import ok
6 passed in 0.33s   (tests/test_agent_loop_observability_scaffold.py)
```
