# T-03322 Verification Output: Agent Loop Hardening — automated tests

- Date: 2026-11-05
- Subsystem: Phase 3 — AI Control Plane (Pillar C Spine) / Agent Loop Hardening / automated tests (T-03313..T-03322)
- Status: ALL RELEVANT SUITES PASSED

## CI suite #34 `agent_loop_battery` (exact registered command, repo root)
```
352 passed, 1 skipped, 908 deselected, 1 warning in 93.34s (0:01:33)
```

## Extended fuzz sweep (beyond CI): seeds 6..25 x 300 ops = 6000 model-checked operations
```
20 passed, 2 deselected in 155.60s (0:02:35)
```
Together with CI's seeds 1..5 x 200 and the 1000-op replay of seed 4 (T-03321), that is about 8000 model-checked operations with **0** divergences.

## Registry / evidence
```
PASS: ci_suites unit tests (W1..W7)
PASS: evidence integrity criteria (E1..E4)
```

## Proof-of-Restraint
```
C1: PASS
C2: PASS
C3: PASS
C4: PASS
C5: PASS
C6: PASS
CONFORMANT: C1..C6 PASS
demo_por.py: verdict   : PROVABLY_RESTRAINED
```
After the post-anchor tamper the proof is rejected (`HEAD_HASH_MISMATCH`), as designed.

## What the battery has demonstrably caught (mutation evidence)
Each check was run against a deliberately re-broken fix:
- disabled tool-scope check
- complete ignoring revocation
- cross-process loop-id reuse
- removed chain-append lock (fuzz and stress)
- loosened model glob rule (model unit tests)
- leaky default-path test (isolation guard)
See T-03316, T-03317, T-03319 and T-03320.
