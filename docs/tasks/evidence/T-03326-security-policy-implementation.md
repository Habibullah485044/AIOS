# T-03326 Evidence: Agent Loop Hardening — security policy Implementation

- Date: 2026-11-05
- `aiosh_mcp/agent_loop_policy.py`:
  - `evaluate_step` runs the **Constitution classifier** (dispatch Gate #1, `classifier.classify`); it fails closed if the classifier errors
  - `is_irreversible` uses the name set of `audit_client.grant_check` or the classifier's C-3 flag
  - `audit_fields` maps the result onto the audit columns, **reusing** `_dispatch._classify_to_c_flags/_classify_evidence`
- Service `advance_turn`: the pipeline is now **P1 caller -> P2 constitution -> P3 grant scope -> P4 `max_irreversible` budget** (T-03324 §1).
  ok irreversible steps are counted per loop, and refusals never consume budget.
- Gate: `audit(..., classification=)` writes the real `c_flags`, `policy_revision` and `classify_*` columns on every step row (ok and refused).
  `irreversible_budget(grant_id)` reads `scope.max_irreversible`.
- Closes T-03323 F2 (steps skipped the classifier), F3 (hard-coded c_flags) and F4 for agent loops (`--max-irreversible` was enforced nowhere).
  F4 remains open for dispatch, TS and Rust and is listed as a follow-up.
- Observation, not changed here: the rule pack classifies `fs.delete` with `path:"/"` as `ok`. That is a classifier rule gap that belongs to its own task.

## Tests
`tests/test_agent_loop_policy_impl.py` (6). Against the pre-implementation code: **5 failed, 1 passed**. The passing one is "no budget = unlimited", true before as well.
```
6 passed in 1.22s
```
Covered: `fs.write` refused with `LOOPPOL_ERR_CONSTITUTION` and an R-03 row; prompt-injection args (R-11) refused; ok/reasoning rows carry
`policy_revision` and real flags; a budget of 2 allows 2 then refuses ("used 2 of 2"); budget 0 refuses the first step; a scope refusal does not consume budget.

## Behaviour changes (intentional, parity with dispatch)
`fs.write` steps are now always refused by the constitution (rule R-03), as in dispatch. Two scope tests that used `fs.write` now use `fs.read` /
`aios.net.fetch` (which the classifier allows) so they still exercise P3. One assertion was added: `fs.write` is refused.
```
360 passed, 1 skipped, 908 deselected, 1 warning in 93.71s (0:01:33)
```
