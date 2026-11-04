# T-03316 Evidence: Agent Loop Hardening — automated tests Implementation

- Date: 2026-11-05
- `code/aiosh-mcp/tests/agent_loop_model.py` implements the spec-derived **reference model** (`LoopModel.expect/apply`), a state-biased
  op generator (`next_op`, `generate_ops`) and `run_and_check(seed, n_ops, db_path)`, which checks **M1..M5** after every op
  against the real `AgentLoopService` + `PepCapabilityGate` on a temp ring.
- `tests/test_agent_loop_fuzz.py`: one test per seed (`AIOSH_LOOP_FUZZ_SEEDS`, default 1..5; `AIOSH_LOOP_FUZZ_OPS`, default 200) plus a reproducibility test.
- Stdlib only. The model encodes the documented check order (input caps -> lookup -> binding -> terminated -> grant liveness), not the code (AUTOTEST-INV2).

## Results
```
6 passed in 24.51s
```
Outcome coverage over the 5 default seeds (1000 ops): every error code the service can return for these ops, plus ok, across all op kinds.
Examples: advance->TERMINATED 172, advance->INVALID_INPUT 80, start->UNAUTHORIZED 43, start->ALREADY_EXISTS 25,
start->BOUNDS 14, complete->UNAUTHORIZED (revoked) 6; step outcomes refused 89 / ok 49.

## The fuzzer catches real bugs (mutation check, 3 security fixes re-broken one at a time)
| Re-introduced bug | Result |
|---|---|
| Grant tool-scope check disabled (#421 / T-03279 F3) | 5 failed: `seed=1 op#24: advance ...: expected outcome refused, got ok` |
| `complete` ignores revocation (#420 finding #5) | 3 failed: `seed=1 op#140: complete ...: expected LOOPSERV_ERR_UNAUTHORIZED, got None` |
| Ring-wide reused-id pre-check removed (#420 finding #2) | First version: **not caught**. A single service refuses reused ids from memory before the ring check. Added `foreign_start` (a second service on the same ring, like another process or a restarted server). Now 5 failed: `seed=1 op#8: foreign_start ...: expected rows (), got ('pep.capability.redeem',)`, i.e. the grant was burned |

## Test-first note
The scaffold test (T-03315) asserted that the stubs raise. It failed against this implementation as expected and was trimmed. One leftover: while the stub
tests still existed they called the real `run_and_check(..., "unused.db")` and created a stray DB in the package folder. The DB was removed and the call is gone.
