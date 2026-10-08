# T-02899 — Compliance Mapping MCP/API Surface: Security Review

**Task**: T-02899 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / MCP/API surface: Security Review)
**Depends on**: T-02898 (Integration)
**Date**: 2026-10-08
**Status**: DONE — no open policy bypass; every state-changing path is PEP-gated + audited; all abuse scenarios below are blocked and test-proven.

**Scope**: `code/aiosh-mcp/aiosh_mcp/compliance.py` (domain + persistence), `server.aios_compliance` + `_recorded_call` (MCP entry), `_dispatch.dispatch` (gates), Rust parity via `aiosh compliance` CLI.

---

## 1. Input validation & untrusted-content handling

| Surface | Control | Where |
|---|---|---|
| Unknown `action` | `PARAM_INVALID` with valid-list | `execute()` L511 |
| Store path (env `AIOSH_COMPLIANCE_MAP_PATH` or default) | `validate_path()` — rejects `..`, UNC (`\\`, `//`), control chars, non-`.json`/bare `.json`, depth > 16, **symlinks** (CWE-22/CWE-59), Rust `Path::extension()` parity | `validate_path()` L208-227 |
| Framework / status enums | strict whitelist parsers (`parse_framework`, `parse_status`) → `PARAM_INVALID` on anything unknown (also blocks the serde rename injection fixed in T-02898) | L176-205 |
| Store file contents | size cap `MAX_COMPLIANCE_STORE_SIZE` (1 MiB) before read; UTF-8 + JSON parse errors → `COMPLIANCESVC_ERR_PARSE`; every entry validated as object with typed fields | `load_store()` L268-288, `_obj_to_snapshot()` L240-264 |
| Field lengths / counts | `MAX_COMPLIANCE_ID_LEN=64`, title 128, desc/notes 2048, `MAX_THREAT_IDS_COUNT=16`, `MAX_TAGS_COUNT=16`, `MAX_COMPLIANCE_ENTRIES_CAPACITY=1024` | L34-42 |
| Audit-args truncation | bounded at 8192 bytes/string, 32 items/list, Nones dropped — never persists unbounded raw input | `server.aios_compliance` `_clip()` |
| Atomic write | same-dir temp + `os.replace`; temp name includes pid+`time_ns`; on `OSError` temp is unlinked | `save_store()` L292-320 |

**Argument injection**: no shell interpolation anywhere on this surface — path goes only through `validate_path` into `open()`/`os.replace`; ids are exact-match dict lookups (`get_mapping`), never filenames or query fragments. `target_ref`/`control_id` are stored as data only.

## 2. PEP gating & audit emission (every state-changing path)

Actions split: `READ_ACTIONS = (list, show, assess, check-pep)` vs `WRITE_ACTIONS = (register, status, init)`.

- `server.aios_compliance` passes `require_grant=action in compliance_mod.WRITE_ACTIONS` into `_recorded_call` → `dispatch.dispatch()`:
  - **Gate #1 classifier** — refusal writes an audit row (`outcome=refused`, `gate=classifier`) and returns.
  - **Gate #2 PEP grant** — `grant_check`; `require_grant and grant_id is None` → refusal row (`gate=pep`).
  - **Gate #2.5 redeem-before-act (invariant I-2)** — `grant_redeem` on the grant; failure → refusal row (`gate=pep.redeem`), detail truncated to 1024 chars.
  - On pass, `_recorded_call.commit()` writes exactly **one** result row (`outcome=ok|error`) and attaches `audit_id` to the response; an exception inside `fn` also commits an `outcome=error` row (never silent).

**[PoR] Invariant I-2 check** (`docs/proof-of-restraint/PLAN.md` L110): `aios.compliance register/status/init` cannot execute without redeeming a capability token — `require_grant=True` at L854 of `server.py`, redemption enforced in `_dispatch.py` L190-241. Test-proven: `test_compliance_unit.py::test_ungranted_write_refused_at_pep_gate` (fail-closed: no store file, exactly one refusal row) and `test_compliance_integration.py::test_wire_ungranted_write_refused_fail_closed` (same over real stdio wire). Recorded here per the standing rule.

## 3. Abuse scenarios

| # | Scenario | Outcome | Proof |
|---|---|---|---|
| A1 | `AIOSH_COMPLIANCE_MAP_PATH=../../etc/x.json` (path traversal) | `COMPLIANCESVC_ERR_PATH_TRAVERSAL`, nothing read/written | `test_compliance_unit.py::test_path_traversal_rejected` |
| A2 | Store replaced by a symlink → exfil/overwrite outside repo | `PATH_TRAVERSAL` ("Symlinks are forbidden") before open | `test_compliance_unit.py::test_symlink_store_rejected` |
| A3 | Ungranted `register` (state change without capability) | PEP refusal, `ok:false`, gate `pep`, **no store file**, one refusal row | unit + wire tests (§2) |
| A4 | Replayed/expired/wrong-scope grant | `grant_redeem` fails → `gate=pep.redeem` refusal row | `test_por_redeem_gate.py` |
| A5 | Oversized store (DoS via memory) | `COMPLIANCESVC_ERR_FILE_SIZE` at 1 MiB cap, file not parsed | `test_compliance_unit.py` boundary block |
| A6 | Malformed/foreign JSON as store (parser confusion) | `COMPLIANCESVC_ERR_PARSE` envelope, no partial state | unit invalid-input block |
| A7 | Enum smuggling (`framework="nist_sp80053_rev5"` style aliases) | `PARAM_INVALID` via whitelist parsers | unit unknown-enum test; T-02898 cross-substrate fix |
| A8 | Huge `mitigation_summary` / 10k-element `threat_ids` (log/store bloat) | field caps + audit `_clip()` at 8192B/32 items | boundary tests + `_clip()` |
| A9 | Duplicate `id` overwrite to silently rewrite a control | `COMPLIANCESVC_ERR_DUPLICATE_ID`, store bytes unchanged | unit duplicate test |
| A10 | Reader races a partially-written store | temp+`os.replace` atomicity — reader sees old or new, never torn | `save_store()` L292-320 |
| A11 | Error swallowed as `ok:true` (silent failure) | every path returns spec §4 envelope; `_recorded_call` exception → `outcome=error` row | `_recorded_call` L96-111 |
| A12 | Crafted `action` string to reach the `init` fall-through | `action not in ACTIONS` rejected first (L511); `init` reachable only as exact `"init"` | unit unknown-action test |

## 4. Verdict

- **No known policy bypass remains open** (acceptance #2). The only bypass ever found on this surface — the cross-substrate serde name split — was fixed and regression-locked in T-02898.
- Blocking notes: none.

## 5. Verification run (this task)

| Check | Result |
|---|---|
| `pytest test_compliance_surface.py test_compliance_unit.py test_compliance_integration.py` | **46 passed**, exit 0 |
| `pytest test_por_redeem_gate.py` (redeem-before-act, invariant I-2) | **3 passed**, exit 0 |
| `pytest test_pep_decision_smoke.py test_classifier_smoke.py` | **7 passed**, exit 0 |
| `python3 tools/check_security_policy.py` | **PASS S1..S5** |
