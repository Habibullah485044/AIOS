# T-03302 Verification Output: Agent Loop Hardening — MCP/API surface

- Date: 2026-11-05
- Subsystem: Phase 3 — AI Control Plane (Pillar C Spine) / Agent Loop Hardening / MCP/API surface (T-03293..T-03302)
- Status: ALL RELEVANT SUITES PASSED

## MCP/API suites
```
tests\test_agent_loop_mcp_scaffold.py ..                                 [  4%]
tests\test_agent_loop_mcp_impl.py ...                                    [ 11%]
tests\test_agent_loop_mcp_unit.py .......................                [ 65%]
tests\test_agent_loop_mcp_integration.py ..                              [ 69%]
tests\test_agent_loop_mcp_security.py .........                          [ 90%]
tests\test_agent_loop_mcp_hardening.py ....                              [100%]

============================= 43 passed in 14.59s =============================
```

## All agent-loop suites (data model + core service + CLI + MCP, incl. stdio wire tests)
```
193 passed, 909 deselected in 25.49s
```

## Registered CI suite `agent_loop_integration` + CI registry + evidence checker
```
14 passed in 12.91s
PASS: ci_suites unit tests (W1..W7)
PASS: evidence integrity criteria (E1..E4)
```

## Proof-of-Restraint
```
PoR pytest suites: 19 passed, 4 warnings in 8.46s
C1: PASS
C2: PASS
C3: PASS
C4: PASS
C5: PASS
C6: PASS
CONFORMANT: C1..C6 PASS
demo_por.py: verdict   : PROVABLY_RESTRAINED
```
After the post-anchor tamper the demo prints `VERIFY_FAILED: HEAD_HASH_MISMATCH` (expected rejection).

## Wire-level checks (T-03298, T-03301)
Over a real `python -m aiosh_mcp.server` stdio session:
- the 7 tools publish their annotations and schema limits
- a full loop runs and its MCP history equals the CLI history on the shared ring
- the three documented `tools/call` examples succeed as written

## Full aiosh-mcp baseline
Unchanged: every non-agent-loop failure is the unbuilt Rust binary (`FileNotFoundError: [WinError 2]`) or the known
order-dependent runbook flake. `test_release_*smoke` stays excluded (it writes multi-GB backup zips into the CWD).
