# Research: Chain Anchoring & Completeness Checkpoints (T-02852)

**Task**: `T-02852` — Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / chain anchoring & completeness checkpoints: Research  
**Date**: 2026-10-07  
**Author**: Antigravity System  
**Status**: Completed  

---

## 1. Objective & Scope

Establish technical facts, constraints, security threat models, and architectural decisions for **Component 3: Chain Anchoring & Completeness Checkpoints** of the Proof of Restraint system (ADR-0037, `PLAN.md` §Layer 2, Invariant I-3).

The primary requirement is:
> Periodically sign the chain head (`seq`, `hash`, `timestamp`) with an external key that `audit.db` never stores, and persist these signed checkpoints in an external append-only log (`anchors.jsonl`). A rewritten or truncated chain must fail verification against external signed anchors.

---

## 2. Technical Facts vs Assumptions

### Facts (Empirically Verified in Codebase & Standards)
1. **Existing WAL Hash Chain**:
   - `code/aiosh-cli/src/audit.ts` and `code/aiosh-mcp/aiosh_mcp/audit_client.py` implement sequential rows with `prev_hash` chained using SHA-256 over canonical JSON.
   - Verification (`verify()`) validates contiguous hashes starting from `GENESIS_HASH` (`0000000000000000000000000000000000000000000000000000000000000000`).
2. **Existing Segment Retention**:
   - `code/aiosh-cli/src/retention.ts` and `code/aiosh-mcp/aiosh_mcp/retention.py` implement checkpointed segment rotation (`audit_segments` table).
   - Each segment records `{segment_id, closed_at, first_row_id, last_row_id, row_count, genesis_prev_hash, head_hash, archive_path, archive_sha256, bloom_hex}`.
   - However, `audit_segments` resides **inside** the SQLite database `audit.db`.
3. **Database Rewrite Vulnerability (Threat Model)**:
   - If an attacker obtains write access to `audit.db` (or a rogue agent operates with sqlite write access), they can regenerate an entirely valid alternative hash chain from genesis to head without breaking internal SQLite constraints.
   - Internal integrity checks alone cannot distinguish a genuine chain from a recomputed alternative chain.
4. **Standard Cryptographic Solution (RFC 9162 / RFC 6962 & RFC 8032)**:
   - Certificate Transparency logs use Signed Tree Heads (STH) signed by an independent log private key.
   - Ed25519 (RFC 8032) provides deterministic, collision-resistant, 64-byte signatures and 32-byte public keys without ECDSA nonce-leak vulnerabilities.
   - Ed25519 is built into Node.js `node:crypto` (`generateKeyPairSync`, `sign`, `verify`) and Python `cryptography.hazmat.primitives.asymmetric.ed25519`.

### Assumptions (To Be Codified in Specification T-02853)
1. **Key Separation**:
   - The anchor signing private key is strictly isolated from `audit.db`. The audit client does not store or embed the private key into SQLite tables.
   - Anchor verification requires only the corresponding public key.
2. **Anchor Format**:
   - Anchors are recorded as canonical JSON lines in an external file `$AIOSH_HOME/anchors.jsonl` (or alongside the database archive root).
   - Each anchor record contains: `version`, `seq`, `head_hash`, `timestamp`, `pubkey`, and `signature`.
3. **Anchor Cadence**:
   - Anchors can be emitted upon segment rotation (`audit.rotate`), explicitly via CLI (`aiosh anchor`), or after a designated number of rows (e.g., every 500 rows).

---

## 3. Threat Analysis & Invariant I-3

### Attack Scenarios:
1. **Chain Truncation**:
   - Attacker drops recent rows containing damning redeems.
   - *Mitigation*: Anchor signed at sequence $N$ proves the chain reached $N$. If the presented chain only extends to $N - k$, the truncation is cryptographically proven.
2. **Chain Re-Branching / Forking**:
   - Attacker mints a grant, uses it, then rewires subsequent rows with an alternate history omitting the redeem.
   - *Mitigation*: Anchor at $N$ binds the unique `head_hash`. Any alternate sequence yields a different `head_hash`, violating the signature against `pubkey`.
3. **Key Compromise Isolation**:
   - If `audit.db` is leaked, read, or compromised, the adversary obtains only public audit rows. They cannot forge future or past anchor signatures without the external private key.

---

## 4. Key Architectural Decisions Needed

1. **Deterministic Payload Representation**:
   - Anchor signing must hash a canonical byte sequence:
     `canonicalJson({ "head_hash": head_hash, "seq": seq, "timestamp": timestamp })`.
2. **Signature Engine**:
   - Use Ed25519 as primary algorithm across TypeScript and Python substrates.
3. **Verification Logic**:
   - `verify_anchor(anchor, pubkey)` -> validates Ed25519 signature.
   - `verify_chain_against_anchors(chain_rows, anchors, pubkey)` -> ensures every anchor's `(seq, head_hash)` exactly matches the row at sequence `seq`.

---

## 5. References & Prior Art
- RFC 9162: *Certificate Transparency Version 2.0*, §4.13 ("Shutting Down a Log") & §4.3 ("Signed Tree Head").
- RFC 8032: *Edwards-Curve Digital Signature Algorithm (Ed25519)*.
- ADR-0037: *Proof of Restraint Architecture*.
- `docs/proof-of-restraint/PLAN.md`: §Layer 2, Invariant I-3.
