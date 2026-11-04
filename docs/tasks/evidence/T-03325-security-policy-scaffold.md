# T-03325 Evidence: Agent Loop Hardening — security policy Scaffold

- Date: 2026-11-05
- New `code/aiosh-mcp/aiosh_mcp/agent_loop_policy.py`: error codes `LOOPPOL_ERR_CONSTITUTION` and `LOOPPOL_ERR_IRREVERSIBLE_BUDGET`, the irreversible
  name set (mirrors `audit_client.grant_check`), the `StepPolicy` dataclass, and stubs `is_irreversible` and `evaluate_step` (`NotImplementedError("T-03326: ...")`).
- Not wired into the service yet, so behaviour is unchanged.

```
$ python -c "import aiosh_mcp.agent_loop_policy, aiosh_mcp.server; print('import ok')"
import ok
3 passed in 0.34s   (tests/test_agent_loop_policy_scaffold.py)
```
