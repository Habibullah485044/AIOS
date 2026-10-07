# Security Review: Standalone Proof Verifier (Component 5)

**Task ID**: T-02878  
**Component**: Proof of Restraint — Standalone Proof Verifier (`aiosh_mcp.verifier`, `cli verifier.ts`)  
**Architecture Reference**: ADR-0037, `docs/proof-of-restraint/PLAN.md` §Layer 2, Invariant I-4  
**Date**: 2026-10-07  
**Auditor**: AIOS Security & PEP Kernel Auditor  

---

## 1. Executive Summary

Component 5 implements the zero-database mathematical and cryptographic verifier for `RestraintProofPackage`. In accordance with Invariant I-4, the verifier trusts **only** the self-contained proof package and a provided set of trusted Ed25519 public keys. It operates with zero access to `audit.db`, zero network dependencies, and zero reliance on operator honesty.

This security review systematically evaluates the verifier against hostile adversarial proofs, resource exhaustion, cryptographic malleability, key substitution, and boundary bypass attacks.

---

## 2. Threat Vectors and Abuse Scenarios

| Threat ID | Threat Vector | Attack Scenario | Impact | Current Mitigation & Findings |
|---|---|---|---|---|
| **TV-POR-01** | **Untrusted Public Key Injection** | Attacker creates a fraudulent anchor using their own Ed25519 key pair, signs arbitrary state, and embeds their public key in `anchors.start_anchor`. | Critical (Bypass of Restraint Verification) | **Mitigated**: Gate 3 (`CHECK_ANCHOR_KEYS`) enforces `pubkey in trusted_set`. The verifier strictly rejects keys not explicitly trusted by the auditor. |
| **TV-POR-02** | **Signature Malleability / Forged Anchors** | Attacker tampers with `head_hash` or `seq` in the anchor payload to hide illicit ledger rows without updating the Ed25519 signature. | Critical (Forged Negative Attestation) | **Mitigated**: Gate 4 (`CHECK_ANCHOR_SIGS`) canonicalizes JSON payload and verifies Ed25519 signature (`verify_checkpoint`). Any modified byte causes cryptographic signature failure. |
| **TV-POR-03** | **Unbounded Window / Narrow Anchor Truncation** | Attacker selects anchors *inside* the requested window ($T_{start\_a} > T_s$ or $T_{end\_a} < T_e$), claiming no actions occurred during the subset interval. | High (Incomplete Observation Window) | **Mitigated**: Gate 5 (`CHECK_ANCHOR_BOUNDS`) strictly enforces $T_{start\_a} \le T_s$ and $T_{end\_a} \ge T_e$, and $seq_{start\_a} \le seq_{end\_a}$. |
| **TV-POR-04** | **Re-Chaining / Live Range Disconnect** | Attacker provides genuine anchors but inserts forged hash chains in `live_range` that do not link to the anchor head hash. | High (Chain Substitution) | **Mitigated**: Gate 7 (`CHECK_LIVE_CHAIN`) asserts that the live chain tail hash strictly equals `end_anchor.head_hash`. |
| **TV-POR-05** | **JSON Bomb / Memory Exhaustion DoS** | Attacker supplies a 500MB proof file or a nested structure with millions of dummy hash entries to cause OOM in memory-constrained verifier runtimes. | Medium (Verifier Denial of Service) | **Finding for Hardening (T-02879)**: Proof loader lacks an explicit payload size cap (e.g. 10MB limit) and list element bounds before in-memory parsing. |
| **TV-POR-06** | **Non-Normalized ISO-8601 Timestamp Evasion** | Attacker provides non-UTC or non-canonical timestamp strings (e.g. `2026-10-07T14:00:00+00:00` vs `2026-10-07T14:00:00Z`), exploiting string comparison quirks. | Medium (Window Boundary Drift) | **Finding for Hardening (T-02879)**: Explicit ISO-8601 timestamp parsing and normalization must be enforced during validation. |

---

## 3. Invariant Verification

- **Invariant I-1 (Mint-Before-Redeem)**: Verifier checks `grant.single_use == True` and `grant.redeemed_at is None`.
- **Invariant I-2 (Window Anchoring)**: Verifier proves anchors encompass the entirety of $[T_{start}, T_{end}]$.
- **Invariant I-3 (Absence Verification via Retention)**: Verifier checks Bloom filter non-membership across all segments.
- **Invariant I-4 (Zero-Database Verifier)**: Confirmed: `verifier.py` and `verifier.ts` contain zero database imports (`sqlite3`, `better-sqlite3`, etc.) and zero database operations.

---

## 4. Hardening Recommendations for T-02879

1. **Max Payload Size Cap**: Enforce 20MB file / string size limit prior to parsing JSON in `_load_proof_dict` and `loadProof`.
2. **ISO-8601 UTC Strict Parser**: Normalize and validate timestamp strings to RFC 3339 / ISO 8601 UTC before performing window comparisons.
3. **Bound List Dimensions**: Limit max segments checked (e.g., 10,000) and max live hashes (e.g., 50,000) to protect against memory explosion.
