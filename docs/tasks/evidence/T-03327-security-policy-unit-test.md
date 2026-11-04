# T-03327 Evidence: Agent Loop Hardening — security policy Unit Test

- Date: 2026-11-05
- Test file: `code/aiosh-mcp/tests/test_agent_loop_policy_unit.py` (26 cases, standalone)

| Area | Cases |
|---|---|
| `is_irreversible` | 10: each name rule (`pentest.`, the `fs.write` prefix incl. `fs.write_bulk`, reboot/shutdown); not-irreversible tools; the C-3 flag alone; None and empty tool |
| `evaluate_step` | reasoning step (only C-4, no refusal, not irreversible); classifier exception -> **fail closed** (refused + counted irreversible) |
| **LOOPPOL-INV1 / dispatch parity** | 6 `(tool, target, args)` triples (read, write, reboot, pentest, prompt injection, gui). The policy's `c_flags`/evidence equal `_dispatch`'s, and a real loop step (grant allowing that tool) is refused **iff** dispatch Gate #1 refuses |
| Budget boundaries | budget 1 (second refused), non-irreversible and reasoning steps not counted, budget 2 with interleaving, budget 0, no budget = unlimited |
| Failure modes | a caller refusal does not consume budget; a budget read failure fails closed (`GATE_UNAVAILABLE`); gate parsing (3 -> 3, unset -> None, -4 -> 0, bool -> None, unknown grant -> None) |

## Fails when broken
Mutation: `evaluate_step` never refuses on the classifier verdict:
```
3 failed, 23 passed in 1.08s
```
After restoring:
```
26 passed in 1.14s
```
