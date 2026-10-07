# Task Evidence: T-02882 — Continuous Restraint Conformance: Research

- **Task ID**: `T-02882`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / continuous restraint conformance (Component 6)
- **Date**: 2026-10-07
- **Invariants Researched**: `I-5` (Continuous Conformance Gate), covering `I-1` .. `I-4`

---

## 1. Problem Statement & Motivation

Invariant `I-5` (PLAN.md §4, ADR-0037 D-2) binds the *process*, not just the code:

> CI must execute automated conformance suites verifying that new tool additions cannot bypass the redeem gate and that restraint proofs for untouched grants consistently pass.

Components 4 (proof generator) and 5 (standalone verifier) prove restraint **at a point in time**. But Proof of Restraint is only actuarially meaningful if that guarantee **holds continuously** as the codebase evolves: every new tool wrapper, dispatch path, or substrate added tomorrow must remain unable to execute a consequential action without a committed `pep.capability.redeem` row, and grants that were never redeemed must keep yielding `PROVABLY_RESTRAINED`.

Continuous restraint conformance is therefore a **regression oracle for negative attestation**: a CI-enforced suite that turns the invariants into an executable gate.

---

## 2. Drift & Regression Model

Research identified five drift classes the conformance gate must catch:

| ID | Drift Class | Invariant Threatened | Example Failure |
|---|---|---|---|
| **D1** | **Redeem-gate bypass** | `I-2` | A new tool handler in `server.py` / `cli.ts` / Rust `main.rs` executes a consequential action without the PEP redeem commit |
| **D2** | **Mint/redeem parity drift** | `I-1` | Mint writes 0 or 2 audit rows; redeem row lacks `grant_token`; canonical JSON differs between substrates |
| **D3** | **Untouched-grant proof instability** | `I-4` | A refactor makes `generate_restraint_proof` → `verify_restraint_proof` fail for a grant that was never redeemed (false "restraint violated") |
| **D4** | **Touched-grant proof leakage** | `I-2`/`I-4` | A redeemed grant still yields `valid=true` (false "provably restrained" — the catastrophic direction) |
| **D5** | **Substrate divergence** | `I-1`/`I-4` | Python, TypeScript, and Rust implementations disagree on canonical hashing, Bloom parameters, or gate ordering |

D4 is the highest-severity class: a false negative attestation silently destroys the insurance/compliance guarantee.

---

## 3. Conformance Dimensions (C1..C6)

1. **C1 — Redeem-gate non-bypassability**: every dispatch path (Python MCP tool table, Rust MCP wire surface, CLI subcommands, direct module API) refuses consequential execution when no unspent redeem row exists.
2. **C2 — Mint/redeem audit parity**: exactly one `pep.capability.mint` row per issuance and exactly one `pep.capability.redeem` per consumption, byte-identical under canonical JSON across substrates.
3. **C3 — Untouched-grant restraint stability**: mint → (no redeem) → anchors → generate proof → standalone verify ⇒ `valid=true`, idempotently across repeated runs (deterministic `proof_id` inputs).
4. **C4 — Touched-grant invalidation**: mint → redeem → generate proof ⇒ generator refuses (`GRANT_REDEEMED`) **and** any tampered proof claiming restraint fails standalone verification.
5. **C5 — Substrate oracle parity**: identical verdicts and canonical JSON for the same scenario across Python and TypeScript (and Rust where the surface exists).
6. **C6 — Anchor/chain continuity**: anchors appended at deterministic cadences verify as a chain (`anchor verify`), and window bounding between consecutive anchors holds (`T_a <= T_s < T_e <= T_a'`).

---

## 4. Survey of Existing Assets

| Asset | Reuse Potential |
|---|---|
| `ci/run_all_smokes.sh` → `tools/ci_run.py` + `tools/ci_suites.py` (suite registry; order IS CONTRACT) | Conformance suite registers here to become a CI gate |
| `code/aiosh-mcp/tests/test_ledger_matrix_smoke.py` (M1..M6 cross-surface matrix) | Precedent for one-sandbox, multi-surface (Python MCP + Rust MCP wire + CLI) scenarios |
| `code/aiosh-cli/tests/test_restraint_mint_redeem.py` | Existing mint/redeem lifecycle fixture to extend |
| `code/aiosh-mcp/tests/test_por_restraint_*` / `test_por_verifier_*` | Component 4/5 batteries — the conformance suite composes them end-to-end |
| `aiosh_mcp.anchors.append_anchor` / `verify_checkpoint`, `cli anchor verify` | C6 chain-continuity checks |
| `tools/ci_service.py check` | Machine-readable run summary validation (`$AIOSH_CI_RESULTS`) |

Key finding: **no suite today re-executes the full mint → anchor → prove → verify loop on every CI run**, and no suite asserts the D4 catastrophic direction (redeemed grant must never verify as restrained) as a standing gate. That is the gap Component 6 fills.

---

## 5. Substrate Architectural Blueprint

- **Conformance harness**: `code/aiosh-mcp/tests/test_por_conformance.py` (scenario runner) + `tools/test_por_conformance_suites.py` (criteria battery C1..C6), each scenario in an isolated sandbox (`AIOSH_HOME` + temp `audit.db`, zero network).
- **CI registration**: add the suite to `tools/ci_suites.py` so `bash ci/run_all_smokes.sh` enforces `I-5` on every change.
- **Determinism**: fixed synthetic keys/timestamps where possible; seeded scenario fixtures; canonical JSON comparison for cross-surface equality.
- **Conformance manifest**: `docs/proof-of-restraint/CONFORMANCE.md` maps C1..C6 → tests → evidence, giving auditors a single attestation surface.
- **Failure policy**: fail-closed — any D1..D5 regression fails CI with the specific conformance criterion and surface named.

---

## 6. Open Questions Resolved

- **Scope**: conformance covers *all* dispatch paths discovered by the tool registry, not a hardcoded list — new tools are covered automatically (C1 scans registered tools for redeem-gate enforcement).
- **Cost**: the full loop is sandbox-local and sub-second; safe to run per-commit.
- **Rust surface**: wire-level checks reuse the M2 pattern from `test_ledger_matrix_smoke.py`; skipped gracefully when the Rust binaries are not built.
