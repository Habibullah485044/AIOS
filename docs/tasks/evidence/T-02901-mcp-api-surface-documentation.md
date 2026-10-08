# T-02901 — Compliance Mapping MCP/API Surface: Documentation

**Task**: T-02901 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / MCP/API surface: Documentation)
**Depends on**: T-02900 (Hardening)
**Date**: 2026-10-08
**Status**: DONE — README + service spec now document the `aios_compliance` surface with live-verified, copy-pasteable examples; constraints and limitations stated honestly; all evidence linked.

## What was updated

### 1. `code/aiosh-mcp/README.md` (primary — had ZERO compliance coverage before)

- Tool table: added the `aios_compliance` row (reads ✓ / writes ✓, PEP-gated, shared canonical store, 1 MiB cap both directions).
- New section **"Compliance Mapping Tool (`aios_compliance`)"** matching the house style of the other tool sections:
  - dispatch overview (`list|show|register|status|assess|check-pep|init`), store location (`AIOSH_COMPLIANCE_MAP_PATH`, default `$AIOSH_HOME/compliance_map.json`), cross-substrate model (Python tool ↔ Rust CLI `aiosh compliance --path`, one store byte-for-byte);
  - **4 copy-pasteable examples**: (1) JSON-RPC `tools/call` list with real response shape, (2) ungranted register → captured live PEP refusal envelope, fail-closed proof, (3) Python direct call with real assess output, (4) Rust CLI `init`/`list`/`assess` with real captured output + full subcommand/flag list;
  - **Constraints & Boundaries (honest)**: one audit row per call (ADR-0035 §F-2); 1 MiB cap on load *and* save; MCP surface is Python-only (Rust exposes CLI only); every status transition legal per Rust fallback with the `compliant` guard; `.json`/≤16-components/traversal rules; baseline-fallback-on-missing-store semantics;
  - **Evidence & specs**: links to SPEC-COMPLIANCE-CLI/SERVICE/DATA-MODEL and to T-02898 / T-02899 / T-02900 / T-02901 evidence.

### 2. `docs/SPEC-COMPLIANCE-SERVICE.md`

- `COMPLYSVC4` invariant wording corrected: the 1 MiB cap is now enforced on **load** (bounded read, TOCTOU-safe) **and** on **save** (payload refused before any file handle exists, both substrates — T-02900).
- §4 limitations extended: Python-only MCP surface / CLI-only Rust side; legal-transition semantics and the `compliant` guard.
- §5 evidence list extended with the MCP/API surface lineage (T-02894 spec → T-02898 integration → T-02899 security → T-02900 hardening → T-02901 docs).

## Live verification of every documented example (2026-10-08)

All four README examples were executed before being written down:

| Example | Captured result |
|---------|-----------------|
| CLI `init --path` | `Compliance store initialized with canonical baseline at: …/compliance_map.json` |
| CLI `list --json --path` | `{"code":0,"count":4,"mappings":[MAP-NIST-AC3-PEP, MAP-NIST-AU2-RING, MAP-SOC2-CC61-PEP, MAP-CIS-CTRL6-PEP]}` |
| CLI `assess --framework nist_sp_800_53_rev5 --json --path` | `{"assessment":{"compliance_percentage":100.0,"compliant_count":2,"gap_control_ids":[],…},"code":0}` |
| Python `compliance.execute(action="assess", framework="nist")` | `{'total_mappings': 2, 'compliant_count': 2, 'compliance_percentage': 100.0}` (parity with the CLI numbers on the same store) |
| Wire `tools/call` ungranted register (real stdio server) | `{"ok": false, "tool": "aios.compliance", "audit_id": 1, "reason": "tool 'aios.compliance' requires explicit PEP grant", "gate": "pep", "policy_revision": "sprint-2-rule-pack-v1"}` and **store file absent after refusal** (fail-closed observed) |

Note: the wire list probe and refusal probe ran against a real `python -m aiosh_mcp.server` stdio session with isolated `AIOSH_HOME`/`AIOSH_COMPLIANCE_MAP_PATH`.

## Honest limitations recorded in the docs (not omitted)

1. MCP tool surface is Python-only; Rust compliance surface is CLI-only; parity via shared store (integration-proven T-02898).
2. 1 MiB store cap binds in both directions since T-02900 — an oversized payload is refused before any write.
3. Every status transition is legal (mirrors Rust `_ => true`); only to-`compliant` requires mitigation/reason.
4. Reads never create the store; missing store = read-only canonical baseline.
5. Grants: writes need a scope grant (`aios.compliance`), redemption single-shot (invariant I-2).

## Verification

- All example commands re-run in this task's session (table above) — exit 0, outputs pasted from real runs, not hand-written.
- `tools/check_evidence.py` / `tools/check_security_policy.py`: PASS (re-run after completion record).
- Regression battery unchanged by this task (docs-only + spec wording); T-02900's full green battery stands (see [T-02900](T-02900-mcp-api-surface-hardening.md)).
