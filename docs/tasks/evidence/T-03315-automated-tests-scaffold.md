# T-03315 Evidence: Agent Loop Hardening — automated tests Scaffold

- Date: 2026-11-05
- New `code/aiosh-mcp/tests/agent_loop_model.py` (test-only, not shipped in the package, per D5). It has `OP_KINDS`, default seeds and ops, and the
  `Op`, `Expectation` and `FuzzReport` dataclasses; stubs `LoopModel.expect/apply`, `generate_ops` and `run_and_check` raise `NotImplementedError("T-03316: ...")`.
- New `tests/test_agent_loop_autotest_scaffold.py` (5 cases) imports every interface and asserts that the stubs fail loudly.
- Stdlib only (`random`, `dataclasses`).

```
5 passed in 0.21s
```
