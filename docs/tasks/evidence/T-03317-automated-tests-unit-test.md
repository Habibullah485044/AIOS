# T-03317 Evidence: Agent Loop Hardening — automated tests Unit Test

- Date: 2026-11-05
- Test file: `code/aiosh-mcp/tests/test_agent_loop_model_unit.py` (18 cases, standalone, pure-Python, no DB). It pins every rule the fuzzer's
  reference model encodes, so model drift from the spec (AUTOTEST-INV2) is caught directly rather than as confusing fuzz failures.

| Area | Cases |
|---|---|
| start | redeemed / revoked / no-start-scope / unknown grant -> UNAUTHORIZED with no rows; malformed id -> BOUNDS; reused id refused locally **and** from a foreign service |
| advance | input validation precedes lookup (no-tool args, oversize args); 6 step-outcome rules incl. the glob segment boundary (`github.delete_repo` vs `git`/`aios.fs.*`) and revocation mid-loop; wrong grant |
| boundary | the `max_iterations=3` ceiling terminates after exactly 3 steps, then TERMINATED |
| abort / complete | abort is idempotent (second abort writes no row); complete after termination; complete needs a live grant, abort does not |
| model hygiene | failed ops leave the model state unchanged; `generate_ops` never mutates the caller's model |

## Fails when broken
Mutation: the model's step rule was loosened to `startswith("aios.fs")` / `"git"`, reproducing the #421 prefix bug inside the model:
```
FAILED tests/test_agent_loop_model_unit.py::test_step_outcome_rules[github.delete_repo-True-False-refused]
1 failed, 17 passed
```
After restoring:
```
18 passed in 0.31s
```
