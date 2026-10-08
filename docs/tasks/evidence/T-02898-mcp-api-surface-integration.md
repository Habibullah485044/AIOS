# T-02898 — Compliance Mapping MCP/API Surface: Integration

**Task**: T-02898 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / MCP/API surface: Integration)
**Depends on**: T-02897 (Unit Test)
**Date**: 2026-10-08
**Status**: DONE — integration suite 6/6 green end-to-end (real stdio MCP server + Rust CLI parity); discovered and fixed a real cross-substrate serialization bug; registered in CI registry; no regressions.

**Deliverable**: `code/aiosh-mcp/tests/test_compliance_integration.py` — 6 integration tests exercising the production path.

---

## 1. Instructions → evidence map (T-02898)

| Instruction | Where it is satisfied |
|---|---|
| Wire the feature into its real call path (MCP tool) | Tests spawn the **real production server** (`python -m aiosh_mcp.server` over stdio JSON-RPC), not an in-process stub: `test_mcp_stdio_advertises_compliance_tool`, `test_mcp_stdio_read_calls_end_to_end`, `test_wire_ungranted_write_refused_fail_closed`, `test_wire_granted_write_persists_store` |
| Confirm cross-substrate parity where the feature touches canonical JSON | `test_cross_substrate_init_baseline_and_loads`, `test_cross_substrate_register_show_status_assess` — Rust CLI (`aiosh compliance … --path STORE`) and Python (`aiosh_mcp.compliance.execute`) operate on **one shared canonical-JSON store**, each loading the other's bytes |
| Update the relevant registration point so the surface is discoverable | Discoverability asserted over the wire: `tools/list` on the live server must advertise `aios_compliance` with its schema (`test_mcp_stdio_advertises_compliance_tool`). CI registration: `compliance_integration` suite added to `tools/ci_suites.py` SUITES (tail append; import-time validation passes) |
| Run the closest existing smoke suite that exercises the integrated path | Full regression battery in §4 |

## 2. What the suite proves (6 tests)

| Test | Observable assertion |
|---|---|
| `test_mcp_stdio_advertises_compliance_tool` | Live server `initialize` + `tools/list` contains `aios_compliance` with `action` in its input schema |
| `test_mcp_stdio_read_calls_end_to_end` | Wire `tools/call aios_compliance action=list` returns the canonical baseline (4 mappings), `isError=false`, spec §4 envelope keys |
| `test_wire_ungranted_write_refused_fail_closed` | Ungranted `register` over the wire → refusal envelope (`ok:false`), **no store file created**, exactly one `outcome=error` audit row (fail-closed) |
| `test_wire_granted_write_persists_store` | Same call with a pre-minted scope grant → `ok:true`, store file exists and contains the new mapping |
| `test_cross_substrate_init_baseline_and_loads` | Rust-init store loads in Python and vice versa; both baselines agree field-for-field (4 mappings, canonical ids) |
| `test_cross_substrate_register_show_status_assess` | Rust `register`→Python `show`; Python `status`→Rust `show`; `assess` counts (total/compliant/percentage) identical on both substrates for the same store |

### Harness note (reproducibility)

The wire helper keeps **stdin open until every response is read** (reader thread + queue) before terminating the server. Closing stdin immediately after the last request triggered a FastMCP shutdown race in which the final `tools/call` response was lost — isolated and fixed during T-02898 (5/6 → 6/6).

## 3. Defect found and fixed (the point of an integration test)

**Cross-substrate store breakage (bidirectional).** Rust's `ComplianceFramework` enum derived `snake_case` serde names that differ from its own `as_str()`/`parse_framework()` canonical forms for two variants:

| Variant | Rust wrote (serde) | Canonical (`as_str` / Python / `parse_framework`) |
|---|---|---|
| `NistSp80053Rev5` | `nist_sp80053_rev5` | `nist_sp_800_53_rev5` |
| `Iso27001` | `iso27001` | `iso_27001_2022` |

Consequences proven before the fix:

- Python-init stores were **unreadable by the Rust CLI**: every verb failed with `unknown variant 'nist_sp_800_53_rev5'` (exit 3) — the two substrates could not share one store at all.
- Rust-init stores disagreed with Python's canonical baseline (`nist_sp80053_rev5` in `list --json`).

**Fix** (`code/aiosh-rust/aiosh-core/src/compliance_data_model.rs`): explicit `#[serde(rename = …)]` on the two variants so serialized JSON equals `as_str()`. Verified: `cargo check -p aiosh-core` clean; **18/18** compliance-domain `cargo test` cases pass; `aiosh` debug binary rebuilt; the integration suite's two parity tests then pass with each substrate loading the other's bytes.

No other enum in the file had a serde/`as_str` mismatch (checked `ComplianceStatus`, `SubstrateTargetType`).

## 4. Regression battery (all run after the final edit)

| Check | Command | Result |
|---|---|---|
| Combined compliance surface + unit + integration | `python3 -m pytest -q -p no:cacheprovider code/aiosh-mcp/tests/test_compliance_{surface,unit,integration}.py` | **46 passed**, exit 0 |
| Continuous Restraint conformance (Invariant I-5) | `python3 tools/test_por_conformance_suites.py` | **CONFORMANT: C1..C6 PASS**, exit 0 |
| PEP decision + classifier | `python3 -m pytest -q -p no:cacheprovider code/aiosh-mcp/tests/test_pep_decision_smoke.py code/aiosh-mcp/tests/test_classifier_smoke.py` | **7 passed**, exit 0 |
| CI registry integrity (W1..W7, incl. frozen order + new suite) | `python3 tools/test_ci_suites.py` | **PASS: W1..W7**, exit 0 |
| Rust compliance domain | `cargo test -p aiosh-core compliance` (backgrounded job) | **18 passed**, `TEST_EXIT=0` |

## 5. CI registration

`tools/ci_suites.py` — appended (tail append keeps every pre-existing index stable):

```python
{"name": "compliance_integration",
 "command": ["python3", "-m", "pytest", "-q", "--no-header",
             "-p", "no:cacheprovider",
             "code/aiosh-mcp/tests/test_compliance_integration.py"],
 "timeout_s": DEFAULT_TIMEOUT_S},
```

`tools/test_ci_suites.py` — `CANONICAL_ORDER` extended with `por_conformance`, `compliance_integration`; pinned count `29 → 31`. Import-time validation (duplicate names, non-positive timeout, command shape) passes; W1 confirms every suite's script exists on disk.

## 6. Acceptance (T-02898)

- ✅ **Feature reachable through its production surface** — live `tools/list` advertises `aios_compliance`; wire `tools/call` succeeds for reads, refuses ungranted writes fail-closed, persists granted writes.
- ✅ **Integration smoke passes end-to-end** — 6/6 green over the real server + Rust CLI shared-store parity; registered as the `compliance_integration` CI suite.

## 7. Limitations (honest)

- The Rust CLI legs skip cleanly when no `aiosh`/`aiosh.exe` binary is present (build with `cargo build -p aiosh-cli` first); on this machine the binary exists and the parity tests ran for real (not skipped).
- Achievement counters / GitHub-side effects are unrelated to this task; no external services are contacted by the suite.
