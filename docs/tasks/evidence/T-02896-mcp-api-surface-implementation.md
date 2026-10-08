# T-02896 — Compliance Mapping MCP/API Surface: Implementation

**Task**: T-02896 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / MCP/API surface: Implementation)
**Depends on**: T-02893 (Research), T-02894 (Spec), T-02895 (Scaffold)
**Date**: 2026-10-08
**Status**: DONE — targeted tests 11/11, no regression in touched-module suites (baseline-proven).

---

## 1. What was implemented

### 1.1 `code/aiosh-mcp/aiosh_mcp/compliance.py` (scaffold → full implementation)

The loud-fail stubs were replaced with a **Rust-parity port** of
`aiosh_core::compliance_service` (`code/aiosh-rust/aiosh-core/src/compliance_service.rs`)
plus the `aiosh compliance` CLI verbs (`code/aiosh-rust/aiosh-cli/src/main.rs`
L19440–L19800). No new dependencies; pure stdlib + existing helpers.

Implemented behavior (each verified against the Rust source before coding):

| Function | Rust parity source | Notes |
|---|---|---|
| `_validate_identifier` / `_validate_title` / `_validate_control` | `validate_identifier`, `validate_title`, `validate_control` | Same regexes, same length caps, same error codes (`COMPLIANCESVC_ERR_*`) |
| `_validate_target_ref` | `fn validate_target_ref` | Requires `MISSING_SUBSTRATE_REF` semantics: non-empty, no whitespace, must carry a substrate prefix |
| `_check_path` | `Path::extension() == Some("json")` + traversal guard | `.json` extension required; path-traversal rejected with `COMPLIANCESVC_ERR_PATH_TRAVERSAL` |
| `compliance_init` | `compliance init` | Errors if the store already exists (Rust parity); writes baseline store |
| `compliance_add_mapping` | `ComplianceService::add_mapping` | MAX_COMPLIANCE cap enforced; duplicate-id rejection; `status` defaults to non-compliant (CLI parity); load-or-baseline fallback |
| `compliance_assess` | `compliance assess` | Builds the assessment report: counts per status, coverage %, gap list, findings ordered deterministically |
| `compliance_check_pep` | `compliance check-pep` | PEP gate verdict for a mapping/control pair; fail-closed on missing store |

All errors surface as the existing MCP error envelope (`ok: false`,
`error.code` + `error.message`) — identical shape the Rust service returns to
the CLI, so the CLI and MCP surfaces stay behaviorally interchangeable.

### 1.2 `code/aiosh-mcp/aiosh_mcp/server.py` (tool wiring)

One tool added — function `aios_compliance`, canonical name
`aios.compliance` (`TOOL_NAME` in compliance.py, used for audit rows) —
following the exact convention of the other `aios.*` tools:

- **PEP gating**: the tool is registered as a consequential action, so an
  ungranted call is refused at `require_grant` (Gate #2) before any service
  code runs.
- **Audit envelope**: exactly one result row per call via `_recorded_call`
  (Gate #2.5 redeem-before-act adds a *redemption* row only when a grant is
  presented — that is invariant I-2, not the tool's result row).
- **Registry**: FastMCP `_tool_manager._tools` now contains `aios_compliance`.
  Total registered tools: 22 (15 `@mcp.tool()` in server.py + pentest module
  registrations).
- **`agent_bridge.py` untouched by design**: `CANONICAL_TO_MCP` is a curated
  9-tool bridge subset (`known` is filtered to its keys), and other tools such
  as `aios.task` are equally absent — adding `aios.compliance` there would
  widen the bridge surface beyond this task's scope.

### 1.3 `code/aiosh-mcp/tests/test_compliance_surface.py` (scaffold stubs → real tests)

The 5 loud-fail `B-*` stubs became real behavioral tests; the 5 `S-*`
scaffold tests were kept and still pass (11 tests total, real names):

| Test | Covers |
|---|---|
| `test_s1_constants_match_rust_parity` | Limits/constants equal to the Rust service |
| `test_s2_closed_vocabularies` | statuses / severities / frameworks are closed sets |
| `test_s3_action_vocabulary_and_gating_split` | Seven verbs; exactly three are write actions |
| `test_s4_entry_field_order_matches_rust` | `ComplianceMappingEntry` field order parity |
| `test_s5_interfaces_fail_loudly_on_garbage` | Garbage input raises instead of silently coercing |
| `test_b1_happy_path_register_list_show` | register → list → show round-trip against a temp store |
| `test_b1b_init_creates_baseline_then_refuses` | `init` writes the baseline store, then refuses if it exists (Rust parity) |
| `test_b2_failure_codes` | Rust-parity error codes: invalid id, oversize title, missing substrate ref, path traversal, non-.json store path, duplicate mapping, bounds violations |
| `test_b3_audit_and_pep_effects` | One result row per `aios.compliance` call; grant-presented calls show I-2 redemption row + result row (2), refusals show exactly 1; PEP gate effect checked |
| `test_b4_store_round_trip_byte_stable` | Persisted store reloads byte-identical |
| `test_b5_validation_parity_bounds_and_transitions` | Bounds + status-transition validation matches Rust |

**Failing-first**: the `B-*` stubs were committed red in T-02895 (5 failed
with "T-02896 IMPLEMENTATION"); they went green only after §1.1/§1.2.

---

## 2. Corrections made along the way

### 2.1 Spec §7 audit-row wording corrected (T-02894-spec.md)

The spec originally said "exactly one audit row per call". Test `b3` proved
this imprecise: when a **grant is presented**, dispatch Gate #2.5
(redeem-before-act, invariant I-2) writes the grant's *redemption* row before
the tool's own result row — 2 rows total, by design of the PoR battery.
Refusals and ungranted calls still write exactly 1. Spec §7 was amended to
state the real contract (result row: always exactly one; redemption row:
exactly one *iff* a grant was presented), matching what
`test_por_conformance.py` C4 already asserts.

### 2.2 Required-check ordering (compliance.py)

`target_ref` whitespace validation is deliberately deferred to the Rust-parity
`MISSING_SUBSTRATE_REF` check rather than being pre-rejected as generic
`PARAM_INVALID`, so the MCP surface returns the *same* error code the Rust
service returns for the same input.

---

## 3. Verification

### 3.1 Targeted tests (acceptance: "Targeted test passes")

```
python3 -m pytest code/aiosh-mcp/tests/test_compliance_surface.py -q
=> 11 passed in 4.83s
```

### 3.2 No-regression (acceptance: "No regression in existing smoke suites for touched modules")

All commands re-run on 2026-10-08 after the final edit:

| Suite | Command | Result |
|---|---|---|
| PoR conformance battery | `python3 tools/test_por_conformance_suites.py` | **CONFORMANT: C1..C6 PASS** |
| PoR pytest battery | `pytest code/aiosh-mcp/tests/ -k por -q` | **77 passed, 1 skipped, 170 deselected** |
| PEP decision + classifier smokes | `pytest test_pep_decision_smoke.py test_classifier_smoke.py -q` | **7 passed** |
| Metrics smoke (imports server.py) | `python3 tests/test_metrics_smoke.py` | **12/12 checks pass** |
| Tool registry | `len(mcp._tool_manager._tools)` | **22 tools, `aios_compliance` present** |
| Import smoke | `python3 -c "import aiosh_mcp.compliance"` | clean |

Script-style smokes that could not run to a verdict on this Windows host
(ALL pre-existing, §3.3): `test_ledger_matrix_smoke` / `test_observability_smoke`
skip with "binaries missing (run cargo build)"; `test_retention_smoke` raises
`FileNotFoundError [WinError 2]` on bare-command spawn, same class as
`test_smoke.py`.

### 3.3 Baseline proof for the two pre-existing failures

Two script-style smokes fail on this Windows host. To prove they are **not**
regressions of T-02896, both were run with my `server.py` change stashed
(`git stash push -- code/aiosh-mcp/aiosh_mcp/server.py`), i.e. at pristine
baseline:

| Smoke | With T-02896 | At baseline (change stashed) | Cause |
|---|---|---|---|
| `tests/test_task_mcp_smoke.py` | P2–P6 ✓, **P7 ✗** | P2–P6 ✓, **P7 ✗ (identical)** | Stale expectation: P7 minted a **single-use** grant, P2 consumed it through the I-2 redeem-before-act gate (predates this task), so P7's later call is refused `already redeemed` at the PEP gate instead of reaching the task service's NO-SKIP check. Pre-existing since the I-2 gate landed; the failure message and pass/fail pattern are byte-identical with and without my change. |
| `tests/test_smoke.py` | crash at `subprocess.run(["npm", ...])` → `FileNotFoundError: [WinError 2]` | **identical crash at the same line** | Windows host: bare `npm` resolves to `npm.cmd`, which `subprocess` without `shell=True` cannot execute. CI on Linux/Git Bash is unaffected. Pre-existing. |

Both remain open as host/stale-test debt owned by the smoke's own epic; they
are out of scope for T-02896 (which touched `compliance.py`, `server.py`,
`test_compliance_surface.py`, and this spec correction only).

---

## 4. Acceptance checklist

- [x] **Targeted test passes** — `test_compliance_surface.py` 11/11.
- [x] **No regression in existing smoke suites for touched modules** — PoR
      battery CONFORMANT (C1..C6), `-k por` 77 passed/1 skipped, PEP+
      classifier 7 passed, metrics smoke 12/12, registry 22 with
      `aios_compliance` present; the script smokes that cannot run on this
      host fail identically at baseline (stash-proven, §3.3).
- [x] Failing-first honored (B-* red in T-02895, green only after implementation).
- [x] No new dependencies.
- [x] Reused existing helpers (`_recorded_call`, `require_grant`, `open_db`,
      canonical JSON) — no duplicated audit/PEP logic.
- [x] No new dependencies; `agent_bridge.py` intentionally unchanged (curated
      9-tool subset, §1.2).
- [x] Audit invariants: result row exactly one per call; I-2 redemption row
      exactly one iff grant presented (spec §7 corrected to state this).
