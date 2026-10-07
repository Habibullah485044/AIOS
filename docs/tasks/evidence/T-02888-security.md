# Security Review: Continuous Restraint Conformance (Component 6)

**Task ID**: T-02888  
**Component**: Proof of Restraint — Continuous Restraint Conformance Suite (CRCS) (`code/aiosh-mcp/tests/test_por_conformance.py`, `tools/test_por_conformance_suites.py`, `tools/ci_suites.py`, `tools/ci_run.py`)  
**Architecture Reference**: ADR-0037, `docs/proof-of-restraint/PLAN.md` §4, Invariant I-5  
**Date**: 2026-10-08  
**Auditor**: AIOS Security & PEP Kernel Auditor  

---

## 1. Executive Summary

Component 6 implements the Continuous Conformance Gate (Invariant I-5): the mint → anchor → prove → verify loop executed on every CI run so new tool additions cannot bypass the redeem gate and restraint proofs for untouched grants consistently pass. This review evaluates the conformance harness against gate-bypass, command/path injection, untrusted proof content, sandbox escape, resource exhaustion, and fail-open masking.

The conformance artifacts are **developer tooling** (test suite + CI battery runner + orchestrator), not the runtime enforcement path. The runtime policy itself (PEP dispatch gate, mint/redeem, anchoring) is covered by Component reviews 1–5; this review covers the *gate that watches the policy*.

---

## 2. Threat Vectors and Abuse Scenarios

| Threat ID | Threat Vector | Attack Scenario | Impact | Current Mitigation & Findings |
|---|---|---|---|---|
| **TV-CRC-01** | **PATH-Based Interpreter Hijack (`bash` / `node`)** | Attacker plants a `bash.exe` or `node.exe` earlier on PATH (or relies on the Windows System32 WSL `bash.exe` shadow, the incident that motivated the `_effective_command` fix); CI executes the attacker's binary with repository privileges. | High (CI Code Execution) | **Partially Mitigated**: `ci_run.py` resolves bare `bash` via an explicit `$AIOSH_BASH` override or a PATH-only lookup (never `shell=True`); suite commands are static registry strings passed as argv lists. **Finding for Hardening (T-02889)**: the resolved binary is not validated against a known Git Bash / WSL / system location, and `node` in `test_por_conformance.py` is resolved as a bare name with the same PATH-hijack exposure. |
| **TV-CRC-02** | **Command / Node-ID Injection** | Attacker influences a criterion mapping or suite command to execute arbitrary shell syntax. | High (CI Code Execution) | **Mitigated**: `CRITERIA_TESTS` and the CI registry command are static, in-repo constants; `subprocess.run(...)` is invoked with argv lists and no shell interpolation anywhere in the harness (verified: zero `shell=True`, `os.system`, `Popen(shell=...)` occurrences). |
| **TV-CRC-03** | **Code Injection via Cross-Substrate `node -e` Script** | Attacker controls the filesystem path or proof payload fed into the C5 `node --input-type=module -e ...` oracle so that content executes as code rather than data. | High (CI Code Execution) | **Mitigated**: the scriptlet embeds `audit_js.as_uri()` through `json.dumps` (URI-encoded, quoted); the proof payload is passed exclusively over stdin and consumed by `JSON.parse` (data, never `eval`). The path derives from the repo layout, not from task input. |
| **TV-CRC-04** | **Sandbox Escape / Env-Var Leakage** | `_make_env` mutates the process-global `AIOSH_HOME`; a crash skipping `cleanup()` or parallel (xdist) execution could point another suite — or a real deployment home — at the wrong database. | Medium (Wrong-DB Read/Write; False Verdicts) | **Partially Mitigated**: fixture restores `AIOSH_HOME` in `cleanup()` and removes a `tempfile.mkdtemp(prefix="por-conform-")` sandbox with `shutil.rmtree`. **Finding for Hardening (T-02889)**: env mutation is process-global and not concurrency-safe; cleanup is skipped on hard crash (SIGKILL). |
| **TV-CRC-05** | **Fail-Open Masking via Skips** | Attacker (or accidental drift) removes `code/aiosh-cli/dist/cli.js` so C5 parity tests `pytest.skip`; the battery runner treats pytest exit 0 as criterion PASS and prints `CONFORMANT: C1..C6 PASS` without the parity checks ever executing. | Medium (Conformance Gate Bypass) | **Finding for Hardening (T-02889)**: the runner is fail-closed on test *failure* but skip-blind; skipped nodes must be surfaced (and skips in the parity/anchor criteria should fail the criterion or be reported as `PASS-SKIPPED`, honest-audit style per ADR-0035 §F-2). Runtime enforcement is unaffected — this weakens detection, not policy. |
| **TV-CRC-06** | **Hostile Proof Package Content** | C4 forges `RestraintProofPackage` structures (oversized lists, non-normalized timestamps, bloated JSON) to hang or confuse the conformance run itself. | Medium (Gate Denial of Service / False Verdict) | **Mitigated**: untrusted content is only ever handled by the T-02879-hardened verifier (payload caps, bounded lists, strict ISO-8601 UTC parsing); the harness passes packages as data and asserts rejection (`test_c4_forged_restraint_proof_rejected`). |
| **TV-CRC-07** | **Resource Exhaustion / Temp Leakage** | Repeated or crashed runs leak `por-conform-*` temp trees and SQLite handles until disk exhaustion. | Low (Local Disk Exhaustion) | **Partially Mitigated**: SQLite connections are context-managed and closed; temp trees are removed in `cleanup()`. Residual leak-on-hard-crash is accepted as low risk and folded into TV-CRC-04 remediation. |

---

## 3. Invariant & PEP Verification

- **Invariant I-5 (Continuous Conformance Gate)**: `por_conformance` is registered in `tools/ci_suites.py` (index 29 of 30) with the fail-closed battery `tools/test_por_conformance_suites.py` (exit 0 only when C1..C6 all pass).
- **PEP gating on state-changing paths (review instruction)**: C1 asserts every consequential dispatch without a grant is refused and spent-grant replay is refused, and scans the tool registry for consequential tools lacking redeem coverage (`test_c1_consequential_tool_coverage_complete`). Any new state-changing tool that skips redemption fails C1 — this is the anti-bypass guarantee of the component.
- **Audit-row emission**: C2 asserts mint/redeem row parity and canonical-JSON parity of the audit trail, so every state-changing path exercised by the loop must emit honest audit rows.
- **Untrusted-content handling**: proof packages produced by the loop are treated as data; forged packages are asserted to be rejected (C4), relying on the T-02879 input caps.

---

## 4. Hardening Recommendations for T-02889

1. **Resolve-and-validate interpreters**: resolve `bash` and `node` once (with `$AIOSH_BASH` / `$AIOSH_NODE` overrides) and validate the resolved path against known-good prefixes (Git Bash, WSL, system Node) before exec; reject re-execution of binaries from world-writable PATH entries.
2. **Skip-transparency in the battery runner**: parse pytest's summary and print `PASS (n skipped: nodes)` per criterion; add a strict mode (env `AIOSH_CONFORMANCE_STRICT=1`) where any skip in C1..C6 fails the criterion.
3. **Concurrency-safe sandboxing**: isolate `AIOSH_HOME` mutation (per-test monkeypatch instead of process-global `os.environ` mutation) and guarantee cleanup in `finally` blocks even under assertion failures.
4. **Temp-tree hygiene**: register atexit cleanup for `por-conform-*` trees so a hard-aborted run does not leak sandboxes across CI runs.

---

## 5. Verdict

**No policy bypass in the runtime enforcement path.** The conformance gate's own weaknesses (TV-CRC-01, TV-CRC-04, TV-CRC-05, TV-CRC-07) are detection/tooling hardening items, not blocking violations: they cannot mint grants, redeem without anchoring, or dispatch consequential tools without redemption. Per the task instruction, none constitutes a scenario where the *feature* bypasses policy, so no blocking note is raised; all findings are queued for T-02889 (Hardening).
