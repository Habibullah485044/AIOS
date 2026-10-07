# Security Review: Chain Anchoring & Completeness Checkpoints (T-02858)

**Task**: `T-02858` — Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / chain anchoring & completeness checkpoints: Security Review  
**Date**: 2026-10-07  
**Author**: Antigravity System  
**Status**: Reviewed & Approved with Hardening Recommendations for T-02859  

---

## 1. Executive Security Summary

Component 3 implements external chain anchoring to satisfy **Invariant I-3** (External Anchor Immutability) and **ADR-0037 Layer 2**. This security review analyzes the key lifecycle, storage boundaries, input validation, and attack surfaces across Python and TypeScript implementations.

---

## 2. Threat Modeling & Abuse Scenarios

### Scenario 1: Private Key Exposure in Audit Log (WAL Leakage)
- **Attack**: An attacker queries `aios.audit.tail` or inspects `audit.db` to retrieve the Ed25519 private key used to sign checkpoints.
- **Analysis**:
  - In `aiosh_mcp/server.py`, the audit row `args` payload records only `{"has_key": true}`. The `key_hex` is strictly isolated and never written to the audit ring.
  - In `aiosh-cli/src/cli.ts`, the audit emission records `{ "seq": head.id, "head_hash": head.hash }`. The private key is never passed to `emit()`.
- **Verdict**: PASS. Private key is never persisted to the audit database.

### Scenario 2: Rogue Anchor Forgery via Untrusted Public Key
- **Attack**: An attacker with write access to `anchors.jsonl` appends a signed anchor using an arbitrary ephemeral keypair to validate a forged audit log.
- **Analysis**:
  - Both `verify_chain_against_anchors` implementations take an optional `trusted_pubkey` parameter (or `AIOSH_ANCHOR_PUBKEY` environment variable).
  - If any anchor record in the file has `anchor.pubkey != trusted_pubkey`, verification immediately fails with `UNTRUSTED_KEY`.
- **Verdict**: PASS. An adversary cannot bypass verification without possessing the private key corresponding to the pinned trusted public key.

### Scenario 3: Log Truncation / Rollback Attack
- **Attack**: An attacker executes an unauthorized action, then drops the latest $K$ rows from `audit.db` to hide the evidence.
- **Analysis**:
  - An external anchor signed at sequence $N > \text{tail}$ exists in `anchors.jsonl`.
  - When `verify_chain_against_anchors` runs, `max_chain_id < anchor.seq` triggers an immediate `TRUNCATION_DETECTED` failure.
- **Verdict**: PASS. Chain truncation is mathematically provable.

### Scenario 4: Chain Fork / History Rewrite Attack
- **Attack**: An attacker rewrites an intermediate row and recomputes all subsequent hashes to present a seemingly intact hash chain.
- **Analysis**:
  - The external anchor binds `(seq, head_hash)`.
  - Because SHA-256 is collision-resistant, altering any earlier row changes the hash at `seq`.
  - `verify_chain_against_anchors` compares `row_map.get(anchor.seq) != anchor.head_hash`, triggering `FORK_DETECTED`.
- **Verdict**: PASS. History rewrites fail verification.

---

## 3. Findings & Required Hardening for T-02859

1. **Finding SEC-PoR-01: Anchor Directory Permissions**:
   - `anchors.jsonl` and anchor key files should be created with restricted file permissions (`0700` for directory, `0600` for key file on POSIX systems) to prevent local unprivileged users from reading keys or corrupting anchor files.
2. **Finding SEC-PoR-02: Input Validation on Key Hex Length**:
   - Ensure `private_key_hex` and `pubkey` parameters strictly check for 64 hex characters (32 bytes) before passing to cryptographic decoding to avoid unhandled parsing exceptions.
3. **Finding SEC-PoR-03: Corrupted Line Handling in `load_anchors`**:
   - If `anchors.jsonl` contains a malformed line, the loader should either fail closed with an explicit error or validate JSON schema strictly.
