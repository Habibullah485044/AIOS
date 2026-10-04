# ADR-0037 — Proof of Restraint: Cryptographic Negative Attestation and External Anchoring

| Field | Value |
|---|---|
| **Status** | Accepted (binding) |
| **Date** | 2026-10-04 |
| **Authors** | AIOS Architecture Session |
| **Replaces** | — |
| **Supersedes** | — |
| **Index** | Entry **#37** in the project's ADR numbering; successor to ADR-0036 per its amendment procedure. |
| **Companion docs** | `docs/proof-of-restraint/PLAN.md` (living architectural plan), `docs/proof-of-restraint/LOG.md` (execution log), `mostimportanAIfolder/AI_CONSTITUTION.md` (P-1, P-2, O-2, O-4, C-4), `mostimportanAIfolder/ADR-0035-aios-s-rank-agent-architecture.md`, `mostimportanAIfolder/ADR-0036-audit-ring-retention.md`. |

---

## 1. Context

AIOS Constitution P-2 and ADR-0035 establish the append-only audit ring as the single tamper-evident record of all AI subsystem actions. Every row is linked via SHA-256 hash chains (`prev_hash`). ADR-0036 introduced segment checkpointing and Bloom filters for bounded retention.

However, all existing audit mechanisms provide **positive attestation** ("this happened"). In high-assurance environments and regulated AI applications (e.g., EU AI Act, AI liability insurance), operators must answer a fundamentally different question:
> *"Did the autonomous agent refrain from exercising a high-privilege capability during a specified time window?"*

In cryptography, absence of evidence is not evidence of absence. An empty or missing log entry cannot prove restraint if an operator or compromised agent could simply disable logging, erase records, or recompute the hash chain from genesis.

## 2. Decision

### D-1 — Three-Layer Negative Attestation
Adopt a three-layer defense to make absence of action structurally verifiable:
1. **Layer 1 (Structural One-Shot Capability Gate)**:
   Sensitive actions are physically unexecutable without presenting and atomically redeeming a single-use, scoped capability grant. The redeem row must be committed to the audit ring before the action is executed.
2. **Layer 2 (Provably Complete Anchored Hash Chain)**:
   The audit ring is periodically anchored by signing the chain head `(seq, head_hash, ts)` with an external key stored outside `audit.db`. Verifiers confirm that no gaps exist between anchors and walk the hash chain or consult segment Bloom filters to verify non-membership.
3. **Layer 3 (Hardware Enclave / TEE Roadmap)**:
   Dispatch verification within confidential computing enclaves (SGX / TrustZone), closing host root compromise threats for Phase 6 release.

### D-2 — Binding System Invariants (I-1 through I-5)
All implementations within the AIOS core must maintain:
- **I-1 (Mint/Redeem Audit Parity)**: Every grant creation writes a `pep.capability.mint` row; every consumption writes a `pep.capability.redeem` row.
- **I-2 (Redeem-Before-Act Gate)**: Consequential tools are unreachable without committing an atomic redemption receipt.
- **I-3 (External Anchor Immutability)**: External checkpoints signed at deterministic cadences; re-chained forks are cryptographically rejected.
- **I-4 (Zero-Trust Standalone Verifier)**: Restraint proofs are verified with zero access to the live `audit.db` using only the proof bundle and public anchor keys.
- **I-5 (Continuous Conformance Gate)**: CI smoke tests enforce non-bypassability across all dispatch paths.

### D-3 — Integration with ADR-0036 Bloom Filters
Archived segments retain Bloom filters (`bloom_hex`). Proof of Restraint queries against archived time windows check the Bloom filter: if `bloom.test(grant_token) == false`, non-execution is guaranteed without requiring full segment decompression.

---

## 3. Consequences

### Positive
- AIOS becomes the first agentic OS with mathematically verifiable negative attestation.
- Creates actuarial certainty required for autonomous AI liability insurance underwriting.
- Establishes full compliance artifacts for the EU AI Act.

### Negative / Trade-offs
- Slight latency overhead (~1-2ms SQLite WAL commit) per privileged action for atomic pre-execution redemption.
- External key management required for signing chain checkpoints.
