# Task Evidence: T-02885 — Continuous Restraint Conformance: Implementation

- **Task ID**: `T-02885`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / continuous restraint conformance (Component 6)
- **Date**: 2026-10-07
- **Invariants Implemented**: `I-5` (Continuous Conformance Gate), covering `I-1` .. `I-4`

## Implementation Delivered

1. **`code/aiosh-mcp/tests/test_por_conformance.py`** (14 scenario tests, all implemented):
   - **Sandbox fixture** `conform_env`: isolated `AIOSH_HOME` + temp `audit.db` (audit + PEP schemas), 5 base rows, two conformance grants minted before anchor finalization (`gr_conform_untouched`, `gr_conform_redeemed`), covering Ed25519 anchors bracketing the window, and `prove`/`verify` helper closures. Zero network.
   - **C1.1** (`test_c1_no_grant_consequential_tool_refused`): authoritative gate (`grant_check`) and full dispatch surface (`_dispatch.dispatch`, both classifier and PEP gates) refuse `pentest.nmap` with no grant; zero `outcome='ok'` rows, refused row audited.
   - **C1.2** (`test_c1_spent_grant_replay_refused`): single-use grant redeemed twice ⇒ second attempt refused at `grant_redeem`, `grant_check`, and dispatch; exactly one `pep.capability.redeem` row (F-SPENT-RETRY).
   - **C1.3** (`test_c1_consequential_tool_coverage_complete`): source-scans `pentest.py` (`_audit_tool_name(...)` calls + `pentest.*` literals) so **new tool additions are auto-discovered**; asserts known minimum registry (`pentest.nmap/nikto/sqlmap/tshark/aircrack-ng`) plus `fs.write`, `system.reboot`, `system.shutdown`, and that every entry is gate-refused without a grant.
   - **C2.1** (`test_c2_mint_redeem_row_parity`): exactly one `pep.capability.mint` per issuance and one `pep.capability.redeem` per consumption; hash chain verifies (`audit_client.verify ok`).
   - **C2.2** (`test_c2_canonical_json_parity`): canonical serialization deterministic, normative (sorted keys, no whitespace), round-trip stable, and **byte-identical to TypeScript `canonicalJson`** (live `node` invocation of `dist/audit.js`).
   - **C3.1–C3.3** (`F-UNTOUCHED`): untouched grant proves `PROVABLY_RESTRAINED`; standalone verify `valid=true` with all 7 checks; verdict idempotent across repeated prove/verify.
   - **C4.1–C4.2** (`F-REDEEMED`, catastrophic direction): redeemed grant ⇒ generator raises `GRANT_REDEEMED`; forged well-signed packages (redeemed_at recorded / hidden-but-Bloom-positive) fail CHECK_GRANT and CHECK_BLOOM_EXCLUSION respectively.
   - **C5.1–C5.2** (`F-PARITY`): live cross-substrate parity via `node dist/cli.js prove verify` — identical verdict/proof_id/checks map, and canonical JSON of the verdict object matches **byte-for-byte** across Python and TypeScript.
   - **C6.1–C6.2** (`F-ANCHOR-CADENCE`): anchors verify individually and as an ordered chain; strict window bounding `T_a1 <= T_s < T_e <= T_a2` with non-decreasing seq.

2. **`tools/test_por_conformance_suites.py`** (implemented): `run_criterion` executes each criterion's pytest node ids (fail-closed), prints per-criterion results, and reports `CONFORMANT: C1..C6 PASS` / `NON-CONFORMANT: <criteria>` with matching exit codes. Fixed a scaffold path-resolution bug (`REPO = HERE.parent`).

## Test Results
```
code/aiosh-mcp/tests/test_por_conformance.py::test_c1_no_grant_consequential_tool_refused PASSED
code/aiosh-mcp/tests/test_por_conformance.py::test_c1_spent_grant_replay_refused PASSED
code/aiosh-mcp/tests/test_por_conformance.py::test_c1_consequential_tool_coverage_complete PASSED
code/aiosh-mcp/tests/test_por_conformance.py::test_c2_mint_redeem_row_parity PASSED
code/aiosh-mcp/tests/test_por_conformance.py::test_c2_canonical_json_parity PASSED
code/aiosh-mcp/tests/test_por_conformance.py::test_c3_untouched_grant_proves_restrained PASSED
code/aiosh-mcp/tests/test_por_conformance.py::test_c3_standalone_verify_valid PASSED
code/aiosh-mcp/tests/test_por_conformance.py::test_c3_idempotent_verdict PASSED
code/aiosh-mcp/tests/test_por_conformance.py::test_c4_redeemed_grant_prove_refused PASSED
code/aiosh-mcp/tests/test_por_conformance.py::test_c4_forged_restraint_proof_rejected PASSED
code/aiosh-mcp/tests/test_por_conformance.py::test_c5_python_typescript_verdict_parity PASSED
code/aiosh-mcp/tests/test_por_conformance.py::test_c5_canonical_json_byte_parity PASSED
code/aiosh-mcp/tests/test_por_conformance.py::test_c6_anchor_chain_verifies PASSED
code/aiosh-mcp/tests/test_por_conformance.py::test_c6_window_bounding_between_anchors PASSED
============================= 14 passed in 6.01s ==============================
```

Criteria battery:
```
$ python3 tools/test_por_conformance_suites.py
C1: PASS   C2: PASS   C3: PASS   C4: PASS   C5: PASS   C6: PASS
CONFORMANT: C1..C6 PASS
```

Full PoR battery (Components 4–6, no regressions):
```
============================= 52 passed, 1 skipped in 16.15s =================
```

## Security Audit
- D4 catastrophic direction (redeemed grant verifies as restrained) is actively tested and impossible under the suite.
- The I-5 "new tool additions" clause is enforced by source-scanning discovery, not a static list.
- C5 parity runs the real TypeScript substrate; canonical byte parity is asserted, not merely semantic equality.
