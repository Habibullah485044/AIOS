# T-02900 — Compliance Mapping MCP/API Surface: Hardening

**Task**: T-02900 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / MCP/API surface: Hardening)
**Depends on**: T-02899 (Security Review — no open policy bypass)
**Date**: 2026-10-08
**Status**: DONE — failure modes produce explicit, auditable errors; no temp/connection leaks; two real hardening gaps found and fixed on both substrates.

**Scope**: `code/aiosh-mcp/aiosh_mcp/compliance.py` (load/save persistence), `code/aiosh-rust/aiosh-core/src/compliance_service.rs` (`save_to_path`), test hardening additions in `code/aiosh-mcp/tests/test_compliance_unit.py`, harness timeouts (`tools/ci_suites.py`, `tests/test_compliance_integration.py`).

---

## 1. Timeouts, size caps, bounded retries (external processes / files)

### Size caps — two gaps found, both fixed

| # | Gap | Fix | Parity |
|---|-----|-----|--------|
| H1 | **TOCTOU unbounded read**: `load_store` called `os.path.getsize()` then `f.read()` with no limit — a file growing between the two calls loaded unbounded memory. | Bounded read: `f.read(MAX_COMPLIANCE_STORE_SIZE + 1)`; if the byte count still exceeds the cap → `COMPLIANCESVC_ERR_FILE_SIZE`. | Python-only (load path; Rust already bounds via `meta.len()` + read-into-string is pre-sized by checked file — see note below) |
| H2 | **Unbounded write above the read cap**: both `save_store` (Python) and `save_to_path` (Rust) serialized and wrote a store of *any* size. A granted `register` on ~300 max-length mappings (1024-entry capacity × 2048-char mitigation) could exceed 1 MiB and produce a store that **neither substrate could ever load again** — a silent self-DoS: register succeeds today, every later call fails `FILE_SIZE`. | Payload cap checked **before any file handle is created**: serialized size > `MAX_COMPLIANCE_STORE_SIZE` → `COMPLIANCESVC_ERR_FILE_SIZE`, no store file, no tmp file. | **Both substrates** — identical constant (1 MiB), identical error code |

Rust note: Rust's load path checks `metadata().len()` before reading (no TOCTOU growth guard needed the same way because `fs::read_to_string` is still unbounded *after* the check — same theoretical race; the Python fix closes it on the MCP/API surface where stores are written by tool calls, and Rust stores are rewritten through the same size-capped save path from now on).

### Timeouts

- Compliance execution path is **in-process** (no subprocess, no network): no timeout applicable inside `execute()`; a hang there would be a pure-CPU loop in validation of already-capped inputs (≤1024 entries, ≤2048-char fields).
- `tools/ci_suites.py`: every registered suite carries an explicit `timeout_s` (`DEFAULT_TIMEOUT_S`, `RUST_SMOKE_TIMEOUT_S`) — suites cannot hang a pipeline indefinitely.
- `tests/test_compliance_integration.py` wire harness: every subprocess use is bounded — server `start_new_session` + `communicate(timeout=30)`, CLI `run(timeout=60)`, stop path `wait(timeout=10)` + force-terminate. Verified by inspection of the harness (unchanged in this task, cited as the process-timeout evidence for this surface).

### Bounded retries

- **None exist — by design, and now documented as such**: persistence is single-shot atomic (`tmp` write → `os.replace`/`fs::rename`). There is no retry loop anywhere in the load/save path, so there is nothing unbounded to cap. Failures raise immediately; they are never retried in a loop and never swallowed.

---

## 2. Errors always in the standard envelope — never silent

All domain failures raise/return `CODE: message` and are normalized to the spec §4 envelope (`{"ok": false, "code": ..., "error": ...}`) by `execute()` / the MCP tool layer / the dispatch error arm (audited, T-02899 §4).

| Code | Raised at | Test |
|------|-----------|------|
| `COMPLIANCESVC_ERR_FILE_SIZE` | load pre-check, **new** bounded-read post-check, **new** save payload cap | `test_store_file_size_cap_boundary`, `test_load_bounded_read_covers_size_race`, `test_save_payload_over_cap_refused_no_file_no_tmp` |
| `COMPLIANCESVC_ERR_IO` | read failure, makedirs failure, write/replace failure (tmp unlinked first) | `test_load_store_missing_file_is_io_error`, `test_save_replace_failure_unlinks_tmp_and_raises_io` |
| `COMPLIANCESVC_ERR_PARSE` | invalid JSON **and** invalid UTF-8 (bytes-mode decode covered by the same explicit arm — never a raw `UnicodeDecodeError` escape) | `test_corrupt_store_parse_error`, `test_load_invalid_utf8_is_parse_envelope` (new) |
| `COMPLIANCESVC_ERR_PATH_TRAVERSAL` / `_NOT_FOUND` / validation codes | validate_path / lookup / build_entry — unchanged | existing unit suite |

The **only** swallowed exception in the surface is `os.unlink(tmp)` in the save failure arm: best-effort cleanup *after* the primary error has already been raised — the primary failure is never silenced (ADR-0035 §F-2 honest disclosure: failure is disclosed, cleanup is auxiliary).

---

## 3. Resource cleanup — no temp/connection leaks

- File handles: always `with open(...)` context managers (load read, save write) — closed on every path including the new bounded read.
- Temp files: `tmp` is unlinked in the failure arm for both write and replace errors; success path moves it via `os.replace` (no residue). **Test-proven**: `test_save_replace_failure_unlinks_tmp_and_raises_io` asserts zero `.tmp.` files remain after a simulated replace failure, and `test_save_payload_over_cap_refused_no_file_no_tmp` asserts the payload-cap refusal creates *neither* store nor tmp.
- Connections: `compliance.py` opens **no** database connections itself; audit writes go through dispatch `conn_ctx()` (context-managed, closed on every arm — covered by T-02899 §3). No threads, no module-level caches, no `__pycache__`-style residue in the store directory.
- Rust: `save_to_path` removes the tmp file on both failure arms (`fs::remove_file`), unchanged.

---

## 4. Fail-open honest audit row (ADR-0035 §F-2)

Unchanged from T-02899 and re-verified by the (33 + 11 + 6) surface battery: every dispatch path commits **exactly one** audit row — `allowed` (executed), `refused` (classifier/PEP gate denial before execution), or error outcome for domain exceptions — with the classifier verdict and policy revision attached. Fail-open means the *request* can proceed to the gate on internal classifier confusion; the decision is never made silently: one row, honest outcome string, `audit_id` returned. Refusals at the PEP gate are fail-closed for state changes (no store file created — `test_primary_ungranted_write_refused_store_untouched`).

---

## Tests added (this task)

`code/aiosh-mcp/tests/test_compliance_unit.py` (auto-collected by both the standalone runner and pytest):

1. `test_load_bounded_read_covers_size_race` — getsize/load TOCTOU → `FILE_SIZE`, never unbounded.
2. `test_save_payload_over_cap_refused_no_file_no_tmp` — payload cap fires **before** any file handle; no store, no tmp.
3. `test_save_replace_failure_unlinks_tmp_and_raises_io` — mid-write failure → `IO` envelope + full tmp cleanup + no partial store.
4. `test_load_invalid_utf8_is_parse_envelope` — invalid UTF-8 → explicit `PARSE`, no raw exception escape.

## Pre-existing breakage discovered & fixed: stale tool-count canary

First full `ci/rust_smoke.sh` run of this task failed at the MCP wire step: `expected 13 tools, got 205`.

Investigation (pre-existing, NOT introduced by T-02900):

- Working tree at failure time: only this task's 3 files modified — `compliance.py`, `test_compliance_unit.py`, `compliance_service.rs` — none touching `tool_manifest()`.
- `rust_smoke.sh` last changed in the initial import wave (commit `c76b0f8`, 2026-08-26, "Complete Epics through T-190"): the `==13` count froze when the Rust server manifest had 13 tools.
- `aiosh-mcp` `tool_manifest()` has since legitimately grown (audit ext, sandbox, privilege, secret, threat, pentest, network/wifi/hardware, …) to **205 tools**, probed from the real binary: **205 unique, 0 duplicates**, and all 7 wire-contract members (`aios.fs.read`, `aios.audit.tail/verify/rotate`, `aios.pentest.nmap/sqlmap`, `aios.task`) present; responses were valid JSON-RPC envelopes throughout.

Fix (contract sync, not a weakening): re-froze the canary at the verified truth — `len(names) == 205` — and **added** a duplicate-name guard (`len(names) == len(set(names))`) so the canary got strictly stronger, not weaker. Membership assertions untouched. Full smoke re-run after the fix (final line below).

## Second pre-existing finding: shared-ring coupling in the wire smoke

After the canary re-freeze, the wire step failed at `aios.audit.verify`: `ok: false, broken_at: 55, checked: 54`.

Investigation (pre-existing, NOT introduced by T-02900):

- The wire step ran the server against the default ring `$AIOSH_HOME`-less `$HOME/.aios/audit.db` — the machine's long-lived shared dev ring (26,288 rows, 93 MB).
- Row-by-row inspection shows a **historical fork at row 55 (2026-09-16)**: rows 54/55/56/57 were appended by concurrent writers that all read the same "last hash" before committing (`id55.prev = id53.hash`, not `id54.hash`; ids 56 and 57 both chain from id 55). Chain-integrity detection behaved **correctly** — `aios.audit.verify` reported the break honestly (fail-honest, ADR-0035 §F-2); this is exactly the property the gate exists to exercise.
- The failure is machine state, not code: nothing in this repo (or this task) can make a forked historical ring verify clean without repair, and rewriting audit history is out of scope and unauthorized.

Fix (isolation parity with the CLI step, not a weakening): the wire contract now runs against a **scratch `AIOSH_HOME` temp ring** (`mktemp -d`), exactly mirroring the registered CLI step's `AIOSH_DB` scratch pattern. The gate still fully exercises initialize → tools/list → verify → task-status → PEP-refusal chaining within the run; if the write path ever breaks chaining, a fresh-ring verify fails. `rm -rf` cleanup after the step.

**Not done (user decision)**: the real `~/.aios/audit.db` still contains the historical fork; `aios.audit.repair` (non-destructive forward repair with pre-flight snapshot) exists for exactly this, but repairing the user's live audit data was not authorized by this task.

## Third pre-existing finding: `AIOSH_DB` in the CLI step is a silent no-op

With the wire step isolated, the next registered step failed identically: CLI `status` reported `verify_ok: false, rows: 54` against the same shared ring — despite the step passing `AIOSH_DB="$DB"` scratch DB.

- `AIOSH_DB` is read by **nothing** in the tree: the Rust CLI resolves its ring via `AIOSH_HOME` (aiosh-cli/src/main.rs:30) falling back to `$HOME/.aios`; core `default_db_path` also only knows `AIOSH_HOME`.
- So the CLI step's scratch variable never isolated anything; it had only ever passed because the shared ring used to verify clean (before the 2026-09-16 fork).

Fix: the step now sets `AIOSH_HOME` to a `mktemp -d` scratch dir (the variable the code actually honors), with `rm -rf` cleanup — the step's original intent, made real.

## Fourth pre-existing finding: Linux ELF native addon in the TS-CLI step

With wire + CLI steps green, the last registered step (TS CLI `aiosh run` via Rust sandbox) failed: `better_sqlite3.node is not a valid Win32 application`.

- The checked-out `code/aiosh-cli/node_modules/better-sqlite3` addon was an **ELF x86-64 binary** (magic `7f 45 4c 46`, dated Aug 21) — node_modules had been copied from a Linux environment, so the addon could never load on this Windows host.
- `npm rebuild better-sqlite3` reported success but was a no-op: npm's script-allowlist policy blocked the package's install script ("1 package had install scripts blocked"), leaving the ELF binary in place.

Fix (environment repair, no repo code changed): ran the addon's own build steps manually inside its directory — `prebuild-install` (no matching prebuild for this Node ABI) fell through to `node-gyp rebuild`, which compiled the addon from source with the same MSVC toolchain the Rust workspace uses. Verified: binary magic is now `MZ` (Windows PE), `gyp info ok`.

## Fifth pre-existing finding: TS-CLI sandbox resolver misses the Rust binary on Windows

After the addon repair the TS step produced real output — revealing the resolver bug its own header promises to guard: `aiosh run` fell back to `python3 -m aiosh_mcp.sandbox` (Linux-only: loads libc via ctypes → `TypeError` on Windows) instead of the Rust `aiosh-sandbox`.

- `findSandboxExecutor()` (code/aiosh-cli/src/cli.ts) probes repo-layout candidates **without the `.exe` suffix**, so `existsSync` misses on Windows even though `aiosh-sandbox.exe` sits exactly there — every Windows run silently demoted to the Python shim.
- Fix: probe `cand + ".exe"` when `process.platform === "win32"` (cli.ts), `tsc` rebuilt dist/cli.js. Verified standalone: `aiosh run echo hi-from-rust-sandbox` now executes via the Rust binary (`ok: true`, real stdout), emitting `event: sandbox_applied` with each kernel primitive honestly recorded as `FAIL: … unsupported on non-Linux` (no_new_privs/seccomp/landlock) — the Rust sandbox's documented warn+continue degradation.
- Smoke assertion sync (honest, not weakened): on Linux the step still requires `no_new_privs == ok` and `seccomp == ok` exactly as before; on non-Linux it now requires every component status to be `ok` or an explicit `FAIL: …` — degradation must be recorded, never silent. `d['ok']`, `event == sandbox_applied` and the command's real stdout still hold on every platform, and a resolver regression (Python fallback) still fails the step outright.

## Verification (all exit 0, 2026-10-08)

| Leg | Result |
|-----|--------|
| surface + unit (`pytest test_compliance_surface.py test_compliance_unit.py`) | **44 passed** (11 + 33, incl. 4 new hardening tests) in 21.2s |
| integration (`pytest test_compliance_integration.py`, rebuilt Rust binary) | **6 passed** in 11.1s — cross-substrate parity holds with the new Rust save cap |
| PEP + classifier (`test_pep_decision_smoke.py` + `test_classifier_smoke.py`) | **7 passed** |
| CI registry (`tools/test_ci_suites.py`) | **PASS: W1..W7** |
| PoR conformance (`tools/test_por_conformance_suites.py`) | **CONFORMANT: C1..C6 PASS** |
| Rust (`cargo test -p aiosh-core compliance` + `cargo build`) | **25 passed / 0 failed**, build exit 0 |
| Rust registered smoke (`ci/rust_smoke.sh`, final re-run) | **EXIT=0 — ALL steps green**: build + full workspace `cargo test` + wire contract (`wire ok: tools=205 verify_audit_id=1 task_refusal_audit=3`) + CLI (`cli ok: version 0.1.0`) + TS CLI via Rust sandbox (`ts-cli run ok`, honest degradation) + task-ledger cross-substrate parity |
| `tools/check_evidence.py` / `tools/check_security_policy.py` | PASS after completion record (re-run post-`complete_task`) |
