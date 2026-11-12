# T-03422 Verification Output: Tool Registry & Taxonomy — automated tests

- Date: 2026-11-13
- Subsystem: Phase 3 — AI Control Plane (Pillar C Spine) / Tool Registry & Taxonomy / automated tests (T-03413..T-03422)
- Status: ALL RELEVANT SUITES PASSED

| Suite | Result |
|---|---|
| CI suite #35 `tool_registry` | 619 passed, 1 skipped, 1437 deselected, 1 warning in 88.73s (0:01:28) |
| CI suite #34 `agent_loop_battery`. It consumes catalog irreversibility in strict mode, which T-03419 changed for backup/release. | 557 passed, 1 skipped, 1499 deselected, 1 warning in 364.75s (0:06:04) |
| `tools/test_ci_suites.py` | PASS: ci_suites unit tests (W1..W7) |
| `tools/check_evidence.py` | PASS (E1..E4), at T-03419 |

## Full aiosh-mcp suite, every failure classified
```
138 failed, 1913 passed, 6 skipped, 5 warnings in 733.83s (0:12:13)
failures=138 missing-Rust-binary=136 known-baseline=1 other=1
 other: tests/test_agent_loop_doc_security.py::test_repeated_calls_are_cheap  (wall clock: 21.7 ms/call > 10 ms)
```
- The 136 failures are the Rust debug binary, which is not built on this host (`FileNotFoundError` / `aiosh-mcp.exe must exist`). The known one is
  `test_runbook_config_integration::test_integration_dynamic_session_capping_via_env`.
- `test_repeated_calls_are_cheap` belongs to the agent-loop doc epic, and this epic did not touch it. It passed 3/3 when rerun alone and inside
  suite #34. Another session's `cargo test` was loading the CPU during the full run. **Follow-up note:** it has the same load
  sensitivity T-03420 fixed for the registry (wall clock instead of CPU time).

## Proof-of-Restraint
```
CONFORMANT: C1..C6 PASS
demo_por.py (exit 0): verdict   : PROVABLY_RESTRAINED
PASS: unused grant proved PROVABLY_RESTRAINED; post-anchor tamper (delete + re-chain) REJECTED.
```
- **Environment note:** the installed `aiosh-mcp` is an editable install whose project location is `C:\Users\OBSESSION\Desktop\AIOS_MERGED`,
  and that folder no longer exists. From the repo root `aiosh_mcp` therefore cannot be imported, and the conformance runner first reported
  C1..C6 FAIL (`ModuleNotFoundError`). Both PoR runs above used `PYTHONPATH=F:/AIOS_MERGED/code/aiosh-mcp`. The Python install was not changed.
  Fix: `pip install -e code/aiosh-mcp` from this checkout.
- `docs/proof-of-restraint/LOG.md` has a T-03422 entry. The T-03419 catalog change makes backup/release count against `max_irreversible` in strict mode (I-2).

## Epic summary (T-03413..T-03422, PRs #532..#541)
- Shipped:
  - `tests/tool_registry_model.py`: oracles and generators written from the doc;
  - properties P1–P6 over seeds × cases;
  - a seed lock on the security fields of all 73 entries;
  - a Rust `is_irreversible` drift check that refuses unmodelled constructs;
  - capped knobs and a per-property watchdog;
  - operator doc §6f with a doc drift test.
- The independent review (T-03419):
  - S1: backup/release made irreversible, closing a strict-mode budget gap;
  - S2: rule 7 widened to the Rust PEP list and the bare `shell`/`process`;
  - it also made P1 non-vacuous and stopped empty knobs from silently skipping.
- State: `progress.md` entry added; the ledger pointer advances to T-03423.

## Security audit (standing rule for every shipped task)
- This task changes only docs and state files.
- Verified end to end: no suite shows a new failure from this epic. Conformance proves every consequential tool is still refused
  without a grant (C1), and the restraint proofs hold (C3, C4).
- **No bypass open.**
