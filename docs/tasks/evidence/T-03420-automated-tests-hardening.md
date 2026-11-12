# T-03420 Evidence: Tool Registry & Taxonomy — automated tests Hardening

- Date: 2026-11-13
- Scope: the property suite and its helpers (`tests/tool_registry_model.py`, `test_tool_registry_properties.py`,
  `test_tool_registry_rust_drift.py`, `tests/conftest.py`), plus one load-sensitive bound found by the T-03419 full run.
  These are test files only. No production module changes.

## Gaps found (probe on the T-03419 code) and fixed
| # | Failure mode | Before (probe) | After |
|---|---|---|---|
| H1 | Case count unbounded | `AIOSH_TOOLREG_FUZZ_N=10000000` accepted (one typo = a multi-day CI run) | cap `MAX_CASES=20000`; the error names the variable and the cap |
| H2 | Seed count unbounded | 5000 seeds accepted | cap `MAX_SEEDS=64` |
| H3 | Bad knob error is anonymous | `"1,x"` → `invalid literal for int() with base 10: 'x'`; no hint which variable | `AIOSH_TOOLREG_FUZZ_SEEDS must be comma-separated integers, got '1,x'` (same for `_N`, `_TIMEOUT_S`) |
| H4 | No timeout | a hung property stalls CI until the job-level timeout, with no location | `watchdog()` per property (`AIOSH_TOOLREG_FUZZ_TIMEOUT_S`, default 120 s, bounded (0, 3600]). **Soft stage:** interrupt the main thread → `TimeoutError` reported by pytest as a normal failure, traceback included, and the run continues. **Hard stage:** if the hang is in C code, `faulthandler` dumps all stacks and exits with status 1 after a 30 s grace. Wired through a `pytest_runtest_call` call wrapper in `conftest.py` (a fixture never sees the test body's exception) and opted in with `pytestmark = toolreg_watchdog` |
| H5 | Drift parser fails obscurely or not at all | no definition → `IndexError`; no early `return false;` → `ValueError: not enough values to unpack`; **two definitions → parsed silently (only the first was read)**; missing file → raw `FileNotFoundError` | every shape is an `AssertionError` with its reason: missing file, over 1 MiB, definition count ≠ 1, no closing brace, early-return count ≠ 1. `rust_rule(path)` is testable on synthetic files |
| H6 | Wall-clock complexity bound fails under load | `test_largest_possible_catalog_stays_bounded` read 2.86 s > 2.0 s during the T-03419 full run (another job was hashing 8643 files); passed 3/3 alone | measured with `time.process_time()` (this process's CPU time), so host load cannot fail an O(1) check |

## Instruction checklist
| Instruction | Result |
|---|---|
| Timeouts, size caps, bounded retries where processes/files are involved | H1, H2, H4 (timeouts), H5 (1 MiB cap on `pep.rs`). Every child process in the new tests has `timeout=`. No retries: a flaky retry would hide a real failure, so none were added. |
| Errors in the standard envelope, never silent | Knob errors are `ValueError` naming the variable (H3). Hangs become `TimeoutError` failures (H4). Parser shapes become `AssertionError` with a reason (H5). |
| Resource cleanup | Tests write only under `tmp_path` (pytest removes it). `test_config_reads_release_the_file`: 50 reads (valid and invalid), each followed by `unlink`. On Windows an open handle makes `unlink` fail, and on Linux the `/proc/self/fd` count is compared. The watchdog thread is joined and the faulthandler timer cancelled in `finally` (`test_watchdog_is_cancelled_when_the_block_ends`). |
| Fail-open must write an honest audit row (ADR-0035 §A F-2) | Not applicable: the suite has no fail-open path. Every hardening path fails closed (error, failure or exit 1). No MCP tool call was added or changed. |

## Tests: `code/aiosh-mcp/tests/test_tool_registry_tests_hardening.py` (26)
- knobs: non-numeric values name the variable (4), seed and case caps at the boundary (2), timeout bounds incl. `nan`/`inf` (5), default (1)
- watchdog, in child processes: Python-level hang → `TimeoutError` pointing at `spin` (under 20 s); a sleep the interrupt cannot reach is killed
  by the hard stage; cancelled after a fast block; other errors pass through unchanged; the property module carries the marker
- **end to end through pytest:** a marked spinning test is reported `1 failed, 1 passed`, exit 1 (not 2 = interrupted), `TimeoutError` in output
- drift parser: 5 bad shapes refused with their reason, the minimal good shape accepted, missing and oversize files refused
- cleanup: config reads release the file (above)

```
$ python -m pytest tests/ -k tool_registry -q
618 passed, 1 skipped, 1437 deselected, 1 warning in 122.19s (0:02:02)      # 592 before + 26 new
```
Full aiosh-mcp suite (`conftest.py` is shared, so every test passes through the new call wrapper):
- All 2056 tests ran. The session ended before pytest printed its summary, so the result comes from the progress line:
  **137 `F`, 0 `E`, 6 `s`**. The T-03419 baseline was 138: 136 missing-Rust-binary, 1 known runbook, and 1 load-timed bound.
  The load-timed bound passes now (H6).
- The last four files rerun on their own (`test_tool_registry_service_*`, `test_tool_registry_tests_hardening`,
  `test_toolchain_mcp_smoke`): 3 failed, all `FileNotFoundError` (Rust binary not built); 66 passed.

## Mutation check (each applied in place, then restored)
| Mutation | Result |
|---|---|
| A: case cap removed | 1 failed |
| B: duplicate `is_irreversible` definitions tolerated (`found >= 1`) | 1 failed |
| D: watchdog soft stage never interrupts | 2 failed (Python-level hang, and the pytest end-to-end test via the hard stage) |

## Security audit (standing rule for every shipped task)
- **Attack surface:** test code only. Nothing is importable from `aiosh_mcp` and nothing runs in the server.
- **Process spawning:** `subprocess.run` with an argument list (no shell), `sys.executable`, fixed code strings, and a `timeout` each.
- **Plugin loading:** the end-to-end test loads `conftest` by name, with the tests directory **first** on `PYTHONPATH`, so another
  `conftest` module elsewhere on the path cannot win.
- **`faulthandler.dump_traceback_later(exit=True)`** is armed only inside `watchdog()` and always cancelled in `finally`. A process
  that ends a block normally keeps running (tested).
- **No security check weakened:** H6 changes the clock source of a performance bound, not a policy assertion. The caps only
  narrow what the knobs accept.
- **PEP / audit / PoR (I-2):** no state-changing path added or changed, so no capability-token check applies. **No bypass.**
