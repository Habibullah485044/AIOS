# T-03359 Security Review: Agent Loop Hardening — recovery & validation

- Date: 2026-11-06
- Scope: `agent_loop_recovery` (`validate_ring`, `recover_orphans`), its MCP tools (`aios_agent_loop_validate`,
  `aios_agent_loop_recover`) and CLI subcommands (`validate-ring`, `recover`), and the shared
  `audit_client.write_audit_row` / `PepCapabilityGate.audit` paths that recovery relies on.
- Method: an **independent read-only reviewer subagent** was given the code only (not my conclusions).
  I reproduced each finding before fixing it. Every fix has a regression test, and the tests were run
  against the pre-fix code (production modules stashed) to show they actually catch the bug.

## Findings
| # | Sev | Finding | Status |
|---|---|---|---|
| 1 | **High** | **Recovery could close a run that another process was still stepping.** An open run counted as orphaned once it was idle for `grace_s` and not live *in this process*. A loop running in another MCP/CLI process that simply paused between steps (or `grace_s=0`) was closed with a terminal `recovered` row. The owning process then kept writing steps after a terminal row, so the honest-close guarantee (LOOPREC-INV1) failed both ways. | **Fixed:** (a) a run is orphaned only once it is idle past grace **and** past its own `total_timeout_ms` (from its start row, capped at the 1800 s LoopConfig max) + 1 s, i.e. when no process could still legitimately step it. (b) `recover_orphans` re-checks under `BEGIN IMMEDIATE` that the run's newest row is still the one seen at validation; any newer row means it is alive and it is skipped. (c) Defence in depth: every non-claim loop audit now refuses (`RunRecovered`) if a `recovered` row exists for its `run_id`. The service maps that to `ABORTED` / `LOOPSERV_ERR_TERMINATED` and writes nothing more. |
| 2 | **High** | **`write_audit_row` dropped the caller's write lock.** It called `ensure_pep_schema` / `ensure_audit_schema`, which use `executescript()`. `executescript()` COMMITs any open transaction first. So a caller doing check-then-write under `BEGIN IMMEDIATE` (gate claim/budget checks, recovery's terminal re-check, `grant_redeem`) had its check committed and the lock released **before** the insert. That reopened the races fixed in #419/#420/T-03330. Probe: `caller_work_committed_early: True` before, `False` after. | **Fixed:** the schema helpers run only when `write_audit_row` opens its own transaction. When the caller already holds one, the schema is already ensured (`open_db` / the gate's `_open`), and the lock is held through the insert. |
| 3 | Medium | **Broad grants could authorise recovery.** `recover_orphans` used glob matching, so a grant for `aios.agent_loop.*` or `aios.*` (e.g. a loop-start grant) could close *other* loops' runs. | **Fixed:** the grant must list `aios.agent_loop.recover` **exactly** in `scope.tools`, checked before redemption. |
| 4 | Medium | **Unbounded cost of the tokenless validate call.** Every `aios_agent_loop_validate` / metrics call re-verified the whole hash chain and scanned every agent-loop row. | **Fixed:** the scan covers the newest 50 000 agent-loop rows (`window`), and the chain check is opt-in (`verify_chain=True` on MCP, `--chain` on CLI). `chain_ok` is `null` when not checked. |
| 5 | Medium | **Secret-shaped `loop_id`s.** An id like `sk-…` / `ghp_…` / `AKIA…` passed the id regex, was stored **masked** in audit rows (so different secret-shaped ids aliased each other in history/recovery), and the rejection path would echo it. | **Fixed:** `LoopConfig.validate_bounds` rejects ids matching `SECRET_PATTERN`. Found while fixing: the rejection message itself echoed the raw id. It is now masked and truncated. |
| 6 | Low | `skipped_live` from recovery reflected only orphans, and recovery inherited the 1000-entry listing cap. | **Fixed:** live runs are counted during validation and reported honestly. Recovery calls validation with `max_listed=None`, so it is not capped by the display limit. |

## Regression tests (`code/aiosh-mcp/tests/test_agent_loop_recovery_security.py`, 12)
| Test | Old code | New code |
|---|---|---|
| run within its total timeout is not orphaned (#1a) | **fails** | passes |
| row written after validation blocks recovery (#1b) | **fails** | passes |
| recovered run stops writing, `LOOPSERV_ERR_TERMINATED` (#1c) | **fails** | passes |
| `write_audit_row` keeps the caller's lock (#2) | **fails** | passes |
| glob grant cannot recover: `aios.agent_loop.*`, `aios.*` (#3) | **fails** | passes |
| glob grant cannot recover: `*` (#3) | passes (`*` never matched dotted names, #421) | passes |
| chain check opt-in, scan windowed (#4) | **fails** | passes |
| secret-shaped loop_id rejected and not echoed: `sk-`, `ghp_`, `AKIA` (#5) | **fails** ×3 | passes |
| live runs reported honestly (#6) | **fails** | passes |

Result on pre-fix code: **11 failed, 1 passed**. On the fixed code: **12 passed**.

Existing recovery tests updated for the new orphan rule. They move recovery's clock (`rec._now`) past the
1800 s maximum timeout. The stdio end-to-end test uses `total_timeout_ms=5000` and waits 6.2 s, because
the server subprocess cannot be monkeypatched. Chain assertions now pass `verify_chain=True`.

## Verification
- Agent-loop battery (`-k "agent_loop or grant_scope or secret_masking or audit_chain_concurrency"`):
  **519 passed, 1 skipped**.
- Wider audit/PEP/grant/dispatch tests: 130 passed. The 27 failures are all the known Windows baseline
  `FileNotFoundError: [WinError 2]` (unbuilt Rust `aiosh-mcp.exe`). None differ.
- `python tools/test_por_conformance_suites.py`: **CONFORMANT: C1..C6 PASS**.

## PoR standing rule
Recovery is the only state-changing path. It requires a redeemed, explicitly scoped grant (I-2), writes one
hash-chained audit row per closed run (I-3), and now cannot close a run that can still legitimately step.
**No bypass.**

## Follow-ups (not done here)
- A heartbeat row for long tool calls would let recovery use a shorter bound than the total timeout.
- Chain verification over a window (the ring head to N rows back) would give `verify_chain` bounded cost too.
