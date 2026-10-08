# Scaffold Evidence: Compliance Mapping / MCP-API Surface (T-02895)

- **Task ID**: T-02895
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / MCP-API surface
- **Status**: Completed
- **Document Date**: 2026-10-08
- **Contract**: [T-02894-spec.md](T-02894-spec.md) (normative)

## 1. Scaffold Implementation

### `code/aiosh-mcp/aiosh_mcp/compliance.py` (new module)
- Typed interfaces only; **every body raises `NotImplementedError("T-02896 IMPLEMENTATION: ...")`** until the implementation task.
- Constants transcribed from `compliance_data_model.rs` (binding parity, spec §6): 7 bounds (`MAX_COMPLIANCE_ID_LEN=64` … `MAX_COMPLIANCE_ENTRIES_CAPACITY=1024`), 11 error-code strings (`COMPLIANCE_ERR_*`, `COMPLIANCESVC_ERR_PATH_TRAVERSAL`) plus AIOS codes (`PARAM_INVALID`, `NOT_FOUND`, `STORE_UNAVAILABLE`, `STORE_EXISTS`).
- Closed vocabularies: `FRAMEWORKS` (6) + `FRAMEWORK_ALIASES`, `STATUSES` (4) + `STATUS_ALIASES`, `TARGET_TYPES` (5), `STATUS_TRANSITIONS` (Rust `can_transition_to` incl. its `_ => true` fallback — noted as a parity caveat).
- Tool contract: `TOOL_NAME="aios.compliance"`, `ACTIONS` (7), split into `READ_ACTIONS` (4) / `WRITE_ACTIONS` (3) per spec §8.
- Dataclasses `ComplianceMappingEntry` (all fields defaulted so declaration order == Rust struct order for byte-stable round-trip, spec §5), `ComplianceCatalogSnapshot`, `ComplianceAssessmentReport`.
- Interfaces: `validate_identifier/title/text_length`, `parse_framework/status`, `validate_path`, `load_store/save_store/init_store`, `list_mappings/get_mapping/register_mapping/update_status`, `assess_framework`, `verify_pep_coverage/uncovered_pep_gates`, and the tool-facing `execute` dispatcher.

### `code/aiosh-mcp/aiosh_mcp/server.py` (call site)
- New `@mcp.tool()` `aios_compliance(action, id, framework, status, control_id, target_type, target_ref, threat_ids, mitigation_summary, tags, reason, gate_id, grant_id)` — full typed signature per spec §2; body delegates to `compliance_mod.execute(...)` (fails loudly until T-02896).
- Module import wired: `from . import compliance as compliance_mod`.
- PEP/audit wiring (`_recorded_call`, `require_grant` per action) intentionally deferred to T-02896 per spec §7 — the scaffold contains no half-wired policy path.

### `code/aiosh-mcp/tests/test_compliance_surface.py` (test stubs)
- **S1..S5 structural tests — green now**: Rust parity constants, closed vocabularies + alias closure, action/gating split, dataclass field order == Rust order, all 17 interfaces present and raising `NotImplementedError`.
- **B1..B5 behavioral stubs — fail loudly by design**: happy path (§3 envelope), error-code table (§4), one-audit-row + gating (§7/§8), byte-stable store round-trip (§5), validation parity (§6). Each `pytest.fail("T-02896 IMPLEMENTATION: ...")`.

## 2. Build / Import Verification

```
python3 -c "import aiosh_mcp.compliance"   -> OK (aios.compliance, 7 actions)
python3 -c "import aiosh_mcp.server"       -> OK, aios_compliance registered
pytest test_compliance_surface.py --collect-only  -> 10 tests collected
pytest test_compliance_surface.py          -> 5 passed, 5 failed (B-* loud stubs by design)
```

No CI suite sweeps the tests directory (every registered suite names a specific file), so the loud B-* stubs cannot break the CI registry.

## 3. Regression Verification (post-scaffold)

- PoR battery: `pytest tests/ -k por` → **77 passed, 1 skipped** (green).
- Conformance battery: `python3 tools/test_por_conformance_suites.py` → **CONFORMANT: C1..C6 PASS**.

## 4. Incidental Fix: Fixture Grant Expiry Time-Bomb

At 2026-10-08T00:00Z the conformance suite's fixture grants (`expires_at=2026-10-07T23:59:59Z`) expired against the wall clock — `grant_check` refused redeem and **4 tests failed** (`c1_spent_grant_replay`, `c2_*` ×2, `c4_redeemed_grant_prove_refused`). Root cause verified by direct repro (`grant gr_x expired`). Fixed in `_mint_grant` default → `2199-12-31T23:59:59Z` (time-robust; synthetic proof dicts at line 545 are not wall-clock-checked and were left narrative-consistent). Battery restored to 77/1. This was a pre-existing latent bug (T-02885 fixture), not caused by the scaffold.

## 5. Acceptance

- [x] Project builds/imports with zero errors.
- [x] New interfaces exist, referenced by a call site (`server.py` → `compliance_mod.execute`) and 10 test stubs.
