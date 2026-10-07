# Specification: Continuous Restraint Conformance Gate (Component 6)

- **Document ID**: `SPEC-RESTRAINT-CONFORMANCE-GATE-v1`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint (Component 6)
- **Status**: LOCKED / IMPLEMENTED
- **Related Documents**: ADR-0037, ADR-0035 §F-2, [PLAN.md](proof-of-restraint/PLAN.md), [SPEC-RESTRAINT-PROOF-GENERATOR.md](SPEC-RESTRAINT-PROOF-GENERATOR.md), [SPEC-RESTRAINT-PROOF-VERIFIER.md](SPEC-RESTRAINT-PROOF-VERIFIER.md)
- **Invariant**: `I-5` (Continuous Conformance Gate)

---

## 1. Overview & Purpose

The Continuous Restraint Conformance Suite (CRCS) executes the **mint → anchor → prove → verify** loop on every CI run so that:

1. new tool additions cannot bypass the redeem gate, and
2. restraint proofs for untouched grants consistently verify.

It is the gate that watches the policy: the runtime enforcement (PEP dispatch gate, mint/redeem, anchoring) is Components 1–5; the CRCS proves on every run that the enforcement still holds.

## 2. Shipped Components

| Artifact | Role |
|---|---|
| [`code/aiosh-mcp/tests/test_por_conformance.py`](../code/aiosh-mcp/tests/test_por_conformance.py) | The conformance suite: C1..C6 criteria tests over an isolated sandbox (`AIOSH_HOME` + temp `audit.db`, zero network) |
| [`code/aiosh-mcp/tests/test_por_conformance_meta.py`](../code/aiosh-mcp/tests/test_por_conformance_meta.py) | Meta-tests of the harness itself (M1..M6) + hardening tests (H1..H4) |
| [`tools/test_por_conformance_suites.py`](../tools/test_por_conformance_suites.py) | Fail-closed C1..C6 battery runner (CI entry point, exit 0 only when all criteria pass) |
| [`tools/ci_suites.py`](../tools/ci_suites.py) | CI registry: `por_conformance` at index 29 (30 suites) |

## 3. Criteria

| Criterion | Drift class | Guarantee |
|---|---|---|
| **C1** | D1 | Consequential tools are refused without a grant; spent-grant replay refused; tool-registry coverage scan — a new state-changing tool that skips redemption fails C1 |
| **C2** | D2 | Mint/redeem audit-row parity; canonical JSON identical across substrates |
| **C3** | D3 | Untouched grant proves restraint: `prove + verify == PROVABLY_RESTRAINED`, idempotent verdict |
| **C4** | D4 | Redeemed grants never prove restraint; forged packages rejected |
| **C5** | D5 | Substrate oracle parity: Python and TypeScript verdicts and canonical JSON byte-identical |
| **C6** | I-3 | Anchor chain verifies; window strictly bounded between anchors |

## 4. Invocation (copy-pasteable)

```bash
# Full conformance battery (CI entry point; fail-closed exit code)
python3 tools/test_por_conformance_suites.py

# Strict mode: any skipped node fails the criterion (recommended in CI)
AIOSH_CONFORMANCE_STRICT=1 python3 tools/test_por_conformance_suites.py

# The suite directly under pytest
python3 -m pytest code/aiosh-mcp/tests/test_por_conformance.py -q

# Harness meta-tests (incl. hardening verification)
python3 -m pytest code/aiosh-mcp/tests/test_por_conformance_meta.py -q

# Via the full CI orchestrator (runs all 30 registered suites)
python3 tools/ci_run.py
```

### Environment variables

| Variable | Effect |
|---|---|
| `AIOSH_CONFORMANCE_STRICT=1` | Skips fail the criterion (fail-closed to the maximum) |
| `AIOSH_BASH` | Explicit trusted bash for the CI orchestrator (validated otherwise) |
| `AIOSH_NODE` | Explicit trusted node for the cross-substrate oracle (validated otherwise) |

## 5. Hardening Properties (T-02889)

- **Bounded child processes**: each criterion 900s, CLI verify 120s, node oracle 60s; a hang is a loud FAIL, never a silent skip.
- **Skip transparency**: skipped nodes are always printed; strict mode turns them into FAIL (ADR-0035 §F-2 honest disclosure).
- **Interpreter validation**: `bash`/`node` resolved via explicit override or PATH-only lookup; world-writable parents rejected (POSIX); unresolvable interpreters fail loudly.
- **Sandbox hygiene**: per-test `monkeypatch` for `AIOSH_HOME` (concurrency-safe), explicit SQLite `close()` (the `sqlite3` context manager only commits — an unclosed handle blocked sandbox removal on Windows), `atexit` temp-tree cleanup.

## 6. Constraints & Known Limitations

- **Cross-substrate parity (C5) requires a compiled CLI** (`code/aiosh-cli/dist/cli.js`) and `node` on PATH; without them C5 skips (surfaced in the report, fatal under strict mode).
- **World-writable interpreter checks are POSIX-only** — Windows mode bits are unreliable, so the directory check is skipped there; explicit `AIOSH_BASH`/`AIOSH_NODE` overrides are the operator's tool for pinned binaries.
- **`rust_smoke` pre-existing defects**: the upstream suite has flaky cargo tests and a stale MCP wire-contract assertion (`expected 13 tools, got 205`); under the fail-fast orchestrator these can hide later suites in a single run. The conformance battery remains deterministically enforceable standalone (exit-code contract).
- The CRCS is **test tooling**: it detects policy drift; it does not enforce policy at runtime.

## 7. Evidence

- Research: [T-02882-research.md](tasks/evidence/T-02882-research.md)
- Specification: [T-02883-spec.md](tasks/evidence/T-02883-spec.md) (normative contract)
- Scaffold: [T-02884-scaffold.md](tasks/evidence/T-02884-scaffold.md)
- Implementation: [T-02885-implementation.md](tasks/evidence/T-02885-implementation.md)
- Unit tests: [T-02886-unit-test.md](tasks/evidence/T-02886-unit-test.md)
- Integration: [T-02887-integration.md](tasks/evidence/T-02887-integration.md)
- Security review: [T-02888-security.md](tasks/evidence/T-02888-security.md)
- Hardening: [T-02889-hardening.md](tasks/evidence/T-02889-hardening.md)
- Verification: [T-02891-verify.md](tasks/evidence/T-02891-verify.md)
