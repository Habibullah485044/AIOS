# T-02889 — Continuous Restraint Conformance: Hardening

**Task ID**: T-02889  
**Component**: Proof of Restraint — Continuous Restraint Conformance Suite (CRCS)  
**Architecture Reference**: ADR-0037 (I-5), `docs/proof-of-restraint/PLAN.md` §4, ADR-0035 §F-2  
**Contract**: [T-02888-security.md](T-02888-security.md) findings TV-CRC-01/04/05/07, [T-02883-spec.md](T-02883-spec.md)  
**Date**: 2026-10-08  

---

## 1. Scope

Closes the four hardening findings from the T-02888 security review, plus the task-level acceptance criteria (bounded external processes, honest error reporting, resource cleanup, honest fail-open disclosure).

## 2. Findings Closed

### TV-CRC-01 — PATH-based interpreter hijack
- `code/aiosh-mcp/tests/test_por_conformance.py`: new `_resolve_interpreter(name, override_var)` — explicit override env (`AIOSH_NODE`) trusted verbatim (operator intent); otherwise PATH-only lookup, resolved binary must be a real file and (POSIX) must not live in a world-writable directory; unresolvable interpreters **raise** (`FileNotFoundError`), never silently reroute. Both `node` call sites (`_run_cli_verify`, `_ts_canonical_json`) now use it.
- `tools/ci_run.py`: new `_validate_interpreter(path, name)` — resolved `bash` must exist and (POSIX) not come from a world-writable directory; `bash` unresolvable via PATH now raises an honest `RuntimeError` (previously fell back to bare `bash`, re-enabling the System32 WSL shadow). `$AIOSH_BASH` remains an explicit operator trust override.

### TV-CRC-05 — fail-open masking via skips
- `tools/test_por_conformance_suites.py`: `_skipped_count()` parses pytest's summary; `_criterion_verdict()` is fail-closed on any pytest failure and, under `AIOSH_CONFORMANCE_STRICT=1`, on any skip. `run_criterion` prints each `SKIPPED` line and an explicit `~ n skipped node(s)` note — a criterion can no longer be silently green while its parity checks never executed. Header prints the active mode.

### TV-CRC-04 — sandbox escape / env-var leakage
- `test_por_conformance.py::_make_env(mp=None)` accepts a pytest `monkeypatch`; the `conform_env` fixture passes one, so `AIOSH_HOME` mutation is per-test and concurrency-safe (auto-restored at teardown). The bare fallback (used by the T-02886 meta tests) keeps restoring the environment in `cleanup()`.

### TV-CRC-07 — resource exhaustion / temp leakage (+ real connection leak found)
- **Actual leak fixed**: `_make_env` used `with sqlite3.connect(...)`, whose context manager **commits but never closes** — on Windows the locked `audit.db` made `shutil.rmtree` fail silently and every sandbox leaked into `%TEMP%`. Proven empirically (sandbox tree survived `cleanup()` with `audit.db` still present), then replaced with explicit `try/finally conn.close()`. Sandboxes now remove cleanly.
- Temp-root hygiene: `_TEMP_ROOTS` registry + `atexit` cleanup so even a hard-aborted run cannot leak `por-conform-*` trees; `cleanup()` releases the tracking slot.

## 3. Acceptance Criteria

| Criterion | Status | Evidence |
|---|---|---|
| Timeouts on external processes | DONE | `run_criterion` bounded at `CRITERION_TIMEOUT_S = 900` (timeout ⇒ honest FAIL); `_run_cli_verify` child bounded at 120s (`pytest.fail` on hang — never a silent skip); `_ts_canonical_json` at 60s with `TimeoutExpired` re-raised as failure, not "unavailable substrate" |
| Size caps | DONE (pre-existing) | log reads bounded via `_print_failure_tail` (`max_file_bytes`); proof payloads bounded by T-02879 verifier caps; subprocess output captured then tail-trimmed |
| Bounded retries | DONE | the harness contains no retry loops — every external process runs exactly once under a timeout; failures are reported, never retried into flakiness |
| Errors in standard envelope, never silent | DONE | timeout/OSError paths print `! FAIL: ...` and return False (fail-closed); skips always printed; strict mode converts skips to FAIL |
| Resource cleanup | DONE | SQLite connections explicitly closed (`try/finally`), sandboxes removed + tracked for `atexit`, child processes bounded by timeout |
| Fail-open honest disclosure (ADR-0035 §F-2) | DONE | the CRCS's fail-open surface is skip-masked criteria; disclosure is the always-printed skip report + strict mode; runtime fail-open audit rows remain the runtime's contract (ADR-0035) and are exercised by C2 parity |

## 4. Verification

```
python3 -m pytest code/aiosh-mcp/tests/test_por_conformance_meta.py code/aiosh-mcp/tests/test_por_conformance.py  -> 24 passed (10 M-*, 14 C-*, incl. 4 new H1..H4)
python3 tools/test_por_conformance_suites.py                                  -> CONFORMANT: C1..C6 PASS (exit 0)
AIOSH_CONFORMANCE_STRICT=1 python3 tools/test_por_conformance_suites.py       -> CONFORMANT: C1..C6 PASS (exit 0, zero skips)
python3 -m pytest code/aiosh-mcp/tests/ -k por                               -> 77 passed, 1 skipped (pre-existing)
ci_run._effective_command(['bash', ...]) -> validated Git Bash (C:\Program Files\Git\usr\bin\bash.EXE)
```

New hardening unit tests (in `test_por_conformance_meta.py`):
- **H1** skip parsing + strict fail-closed verdict matrix
- **H2** interpreter override trust / PATH resolution / loud failure
- **H3** sandbox uses monkeypatch, never global env
- **H4** temp-root registration/release and tree removal (regression test for the closed connection leak)
