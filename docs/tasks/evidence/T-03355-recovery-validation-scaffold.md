# T-03355 Evidence: Agent Loop Hardening — recovery & validation Scaffold

- Date: 2026-11-05
- New `code/aiosh-mcp/aiosh_mcp/agent_loop_recovery.py`: `RECOVER_TOOL`, `TERMINAL_EVENTS` (incl. the new `failed` and `recovered`), the grace default,
  the listing cap, `PROBLEM_KINDS`, and stubs `validate_ring` and `recover_orphans` (`NotImplementedError("T-03356: ...")`). Not wired in yet.
- New error codes come in T-03356 together with their `ERROR_MEANINGS`; the two-way doc test (T-03345) would reject a code with no meaning.

```
$ python -c "import aiosh_mcp.agent_loop_recovery, aiosh_mcp.server; print('import ok')"
import ok
3 passed in 0.34s
```
