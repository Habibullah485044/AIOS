# Task Evidence: T-02868 — Restraint Proof Generator: Security Review

- **Task ID**: `T-02868`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator
- **Date**: 2026-10-07
- **Invariants Audited**: `I-1` (Atomic Mint/Redeem Audit), `I-2` (Redeem-Before-Act Gate), `I-3` (External Chain Anchoring), `I-4` (Self-Contained Restraint Proof)

---

## 1. Threat Modeling & Attack Surface Analysis

The Restraint Proof Generator constructs mathematical negative attestations ("Capability $C$ bound to grant $G$ was not consumed across time interval $[T_1, T_2]$").
Auditing this component requires examining both adversarial generation attempts (attempting to generate a valid proof for an action that was actually taken) and denial-of-service/tampering vectors against the generator.

### Threat Matrix

| Threat ID | Vector Description | Severity | Impact | Current Mitigations & Findings |
|---|---|---|---|---|
| **THREAT-POR-01** | **Window Boundary Under-coverage**: Window begins before first anchor or ends after latest anchor | **HIGH** | Potential gap in attestation coverage if generator falls back to unbounding anchors. | **FINDING-01**: `restraint.py` and `restraint.ts` fall back to `sorted_anchors[0]` or `sorted_anchors[-1]` when candidates are empty. Mitigate in T-02869 by requiring strict bounding ($T_{start\_anchor} \le T_{start}$ and $T_{end\_anchor} \ge T_{end}$). |
| **THREAT-POR-02** | **SQL Injection / Parameter Tampering**: Malicious `grant_id` with quotes or union statements | **LOW** | Potential unauthorized DB query execution | **CLEAN**: Both Python and TS use strictly parameterized queries (`?`) across `pep_grants`, `audit_ring`, and `audit_segments`. |
| **THREAT-POR-03** | **Path Traversal via `anchors_path` / `out`**: Escaping AIOSH_HOME to overwrite system files | **MEDIUM** | Arbitrary file read/write | **FINDING-02**: Paths should be resolved and checked against path traversal (e.g., null bytes, relative traversal out of permitted boundaries). Mitigate in T-02869. |
| **THREAT-POR-04** | **Bloom Filter Collision / False Positives**: Innocent grant rejected as "redeemed" | **LOW** | DoS on proof generation (safe fail) | **ACCEPTED / CLEAN**: By design, Bloom filters guarantee $P(\text{false negative}) = 0$. A false positive causes fail-closed rejection (`GRANT_REDEEMED`). Acceptable trade-off for zero-leakage security. |
| **THREAT-POR-05** | **Live Range Tampering / Truncation**: Chain deleted between anchors to conceal redemption | **CRITICAL** | False negative attestation | **CLEAN**: Live range hashes are extracted and checked sequentially; verifier checks continuity against anchor head hashes. |
| **THREAT-POR-06** | **Time Format / Locale Ambiguity**: ISO-8601 strings with variable offsets causing window skew | **MEDIUM** | Attestation window discrepancy | **FINDING-03**: Enforce strict UTC ISO-8601 format validation (`YYYY-MM-DDTHH:MM:SSZ` or with `.sssZ`). |

---

## 2. Codebase Audit Findings

### Finding 1: Strict Anchor Bounding Guard (High Priority for T-02869)
In `restraint.py`:
```python
start_candidates = [a for a in sorted_anchors if a.timestamp <= window_start]
start_anchor = start_candidates[-1] if start_candidates else sorted_anchors[0] # VULNERABILITY: fallback allows anchor > window_start!
```
If `start_candidates` is empty, the earliest anchor is *after* `window_start`. Falling back to `sorted_anchors[0]` leaves an unverified gap $[window\_start, anchor_0.timestamp]$.
**Remediation**: If `not start_candidates`, immediately raise `ValueError("NO_COVERING_ANCHORS: no anchor precedes window_start")`.
Similarly, if `not end_candidates`, immediately raise `ValueError("NO_COVERING_ANCHORS: no anchor succeeds window_end")`.

### Finding 2: Path Traversal & File Permission Hardening
In CLI `--out <path>` and `--anchors <path>`, paths must be checked to reject NUL bytes (`\0`) and ensure target directories have appropriate permissions.

### Finding 3: Time String Normalization
Validate that timestamps strictly parse as valid ISO-8601 UTC datetimes and reject non-chronological or unparseable strings before query execution.

---

## 3. Audit Conclusion & Recommendations
The implementation of Component 4 adheres to the zero-trust principles of ADR-0037.
Identified vulnerabilities (FINDING-01, FINDING-02, FINDING-03) will be systematically remediated in **T-02869: Hardening**.
