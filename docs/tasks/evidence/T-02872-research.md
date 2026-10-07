# Task Evidence: T-02872 — Standalone Proof Verifier: Research

- **Task ID**: `T-02872`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / standalone proof verifier
- **Date**: 2026-10-07
- **Invariants Researched**: `I-4` (Self-Contained Verifier, Zero Internal DB Access)

---

## 1. Problem Statement & Motivation
An auditor, AI liability insurer, or regulator cannot and should not be granted direct SQL access or file system access to the production `audit.db` or host environment.
To fulfill the nuclear-launch-key model of Proof of Restraint (ADR-0037 §Layer 2), negative attestation must be verifiable using **only**:
1. The self-contained proof package (`restraint_proof.json`).
2. Trusted Ed25519 public keys published out-of-band by the operator.

The verifier must be a zero-dependency, zero-database standalone utility (`aiosh-verify-restraint`).

---

## 2. Cryptographic & Mathematical Verifications Required

The verifier must execute an unforgeable verification pipeline:

### Step 1: Package Integrity & Schema Validation
- Parse JSON, confirm `schema_version == 1`.
- Verify presence of mandatory top-level fields: `proof_id`, `grant`, `window`, `anchors`, `segments_checked`, `live_range`.

### Step 2: Grant Consistency
- Confirm `grant.redeemed_at` is `null`.
- Confirm `grant.single_use == true`.
- Confirm grant validity window covers the requested restraint window:
  $grant.issued\_at \le window.start$ and $grant.expires\_at \ge window.end$.

### Step 3: Checkpoint Anchor Cryptography (Ed25519)
- Extract `start_anchor` and `end_anchor`.
- Verify that both public keys exist in the `trusted_pubkeys` whitelist.
- Verify Ed25519 signatures over the canonical checkpoint representation:
  $\text{Verify}(anchor.pubkey, \text{canonical}(payload), anchor.signature) == \text{True}$.
- Verify bounding condition:
  $start\_anchor.timestamp \le window.start$ and $end\_anchor.timestamp \ge window.end$.
  $start\_anchor.seq \le end\_anchor.seq$.

### Step 4: Archived Segment Bloom Filter Negative Attestation
- For each entry in `segments_checked`:
  - Verify that the segment row range lies within $[start\_anchor.seq, end\_anchor.seq]$.
  - Reconstruct bitset from `bloom_hex` with parameters $m, k$.
  - Evaluate `bloom_test(bits, m, k, grant_id)`.
  - Assert that `bloom_test` evaluates to `False`. Because Bloom filters have zero false negatives ($P(\text{false negative}) = 0$), a negative evaluation mathematically guarantees the grant was never written to that segment.

### Step 5: Live Range Hash Chain Verification
- If live rows exist between the segments and the end anchor:
  - Verify sequence numbers span $[live\_range.first\_seq, live\_range.last\_seq]$.
  - Verify that the final hash in `live_range.hashes` strictly matches `end_anchor.head_hash`.
  - Confirm no hash corresponds to a known redemption event.

---

## 3. Substrate Architectural Blueprint
- **Python Module**: `code/aiosh-mcp/aiosh_mcp/verifier.py`
  - Function: `verify_restraint_proof(proof_package: dict, trusted_pubkeys: list[str]) -> tuple[bool, str | None]`
  - CLI script: `aiosh-verify-restraint` entrypoint.
- **TypeScript Module**: `code/aiosh-cli/src/verifier.ts`
  - Function: `verifyRestraintProof(proof: RestraintProofPackage, trustedPubkeys: string[]): { valid: boolean; reason?: string }`
  - CLI command: `aiosh prove verify --proof <file> --pubkey <hex>`.

---

## 4. Conclusion & Next Steps
Research is complete and provides exact specifications for **T-02873 (Specification)**.
Zero database dependencies will be strictly enforced.
