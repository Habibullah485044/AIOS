# T-03292 Verification Output: Agent Loop Hardening — CLI surface

- Date: 2026-11-05
- Subsystem: Phase 3 — AI Control Plane (Pillar C Spine) / Agent Loop Hardening / CLI surface (T-03283..T-03292)
- Status: ALL RELEVANT SUITES PASSED

## CLI suites
```
tests\test_agent_loop_cli_scaffold.py ..                                 [  3%]
tests\test_agent_loop_cli_impl.py .....                                  [ 11%]
tests\test_agent_loop_cli_unit.py ................................       [ 61%]
tests\test_agent_loop_cli_integration.py ...                             [ 66%]
tests\test_agent_loop_cli_security.py ...........                        [ 84%]
tests\test_agent_loop_cli_hardening.py ..........                        [100%]

============================= 63 passed in 7.55s ==============================
```

## All agent-loop suites (data model + core service + CLI)
```
150 passed, 909 deselected in 9.24s
```

## Registered CI suite `agent_loop_integration` (command from `tools/ci_suites.py`, run from repo root) + registry self-test
```
12 passed in 5.95s
PASS: ci_suites unit tests (W1..W7)
```

## Proof-of-Restraint
```
PoR pytest suites: 19 passed, 4 warnings in 8.41s
C1: PASS
C2: PASS
C3: PASS
C4: PASS
C5: PASS
C6: PASS
CONFORMANT: C1..C6 PASS
demo_por.py: verdict   : PROVABLY_RESTRAINED 
```
After the post-anchor tamper the demo rejects the proof (`HEAD_HASH_MISMATCH`), as designed.

## Cross-substrate check (from T-03291)
A grant issued by the TS CLI (`node code/aiosh-cli/dist/cli.js grant create`) was redeemed by `python -m aiosh_mcp.agent_loop_cli run`
on the same `audit.db`. The loop COMPLETED and `history` read back 4 events.

## Full aiosh-mcp baseline
Unchanged from T-03282: every non-agent-loop failure is the unbuilt Rust binary (`FileNotFoundError: [WinError 2]`)
or the known order-dependent runbook flake. `test_release_*smoke` is still excluded (it writes multi-GB backup zips into the CWD).
