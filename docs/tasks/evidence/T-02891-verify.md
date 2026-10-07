# T-02891 — Continuous Restraint Conformance: Verification & Evidence

**Task ID**: T-02891  
**Component**: Proof of Restraint — Continuous Restraint Conformance Suite (CRCS, Component 6) — **CLOSEOUT**  
**Architecture Reference**: ADR-0037 (I-5), `docs/proof-of-restraint/PLAN.md` §4  
**Date**: 2026-10-08  

---

## 1. Milestone

This task closes **Component 6 — Continuous Restraint Conformance Gate (Invariant I-5)**, the 10-task series T-02882..T-02891. With Components 5 (Standalone Proof Verifier, T-02872..T-02881) and 6 complete, Proof of Restraint now has: a zero-DB verifier (I-4) and a CI-enforced conformance gate (I-5) proving on every run that mint→anchor→prove→verify holds and new tools cannot bypass the redeem gate.

## 2. Verification Runs (fresh, 2026-10-08)

| Check | Command | Result |
|---|---|---|
| Full PoR battery (conformance + meta + verifier + integration + redemption + reduction) | `python3 -m pytest code/aiosh-mcp/tests/ -k por -q` | **77 passed, 1 skipped** (pre-existing Win32-substrate skip) |
| Conformance battery, strict mode | `AIOSH_CONFORMANCE_STRICT=1 python3 tools/test_por_conformance_suites.py` | **CONFORMANT: C1..C6 PASS** (exit 0, zero skips) |
| Conformance battery, default mode | `python3 tools/test_por_conformance_suites.py` | **CONFORMANT: C1..C6 PASS** (exit 0) |
| Criteria detail (strict run) | — | C1 PASS, C2 PASS, C3 PASS, C4 PASS, C5 PASS (2 tests, live Python↔TypeScript oracle), C6 PASS |
| CI registry validation | `tools/ci_suites.py` schema check | 30 suites, `por_conformance` at index 29 |
| Orchestrator mechanics | `python3 tools/ci_run.py` (full run) | Summary artifact schema-valid; blocked at pre-existing `rust_smoke` defects (flaky cargo tests; stale wire-contract assertion 13 vs 205 tools) before suite 30 — see T-02887 |
| TypeScript substrate | `npm run build` (aiosh-cli) | tsc clean |

## 3. Series Ledger (T-02882..T-02891)

| Task | Phase | Artifact |
|---|---|---|
| T-02882 | Research | drift classes D1..D5, I-5 grounding → `T-02882-research.md` |
| T-02883 | Specification | normative CRCS contract → `T-02883-spec.md` |
| T-02884 | Scaffold | suite + battery skeleton, fail-loud stubs → `T-02884-scaffold.md` |
| T-02885 | Implementation | C1..C6 + fixtures F-* live → `T-02885-implementation.md` |
| T-02886 | Unit Test | M1..M6 meta-tests → `T-02886-unit-test.md` |
| T-02887 | Integration | CI registry + `ci_run.py` bash resolution fix → `T-02887-integration.md` |
| T-02888 | Security Review | TV-CRC-01..07 → `T-02888-security.md` |
| T-02889 | Hardening | TV-CRC-01/04/05/07 closed; sqlite3 leak fix → `T-02889-hardening.md` |
| T-02890 | Documentation | `docs/SPEC-RESTRAINT-CONFORMANCE-GATE.md` → `T-02890-doc.md` |
| T-02891 | Verification & Evidence | this document — series closeout |

## 4. Acceptance Criteria

- [x] All relevant suites run and PASS captured here (§2).
- [x] Full baseline smoke set attempted via `ci_run.py`; remaining blockers are pre-existing `rust_smoke` defects, honestly recorded (T-02887 §Note).
- [x] Milestone recorded (§1).
- [x] Task complete; advance to next numeric task (T-02892).

## 5. Residual Risks & Follow-Up

1. `rust_smoke` flaky cargo tests + stale MCP tool-count assertion (13 vs 205) intermittently hide downstream suites under fail-fast; recommend fixing upstream.
2. World-writable interpreter checks are POSIX-only; Windows relies on explicit `AIOSH_BASH`/`AIOSH_NODE` overrides.
3. C5 requires compiled `aiosh-cli` dist + node; strict mode makes any resulting skip fatal.
