# Research: Restraint Proof Generator (T-02862)

**Task**: `T-02862` — Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator: Research  
**Date**: 2026-10-07  
**Author**: Antigravity System  
**Status**: Completed  

---

## 1. Objective & Architectural Context

Establish facts, constraints, cryptographic principles, and prior art for **Component 4: Restraint Proof Generator** of Proof of Restraint (ADR-0037, `PLAN.md` §Layer 2, Invariants I-1 through I-4).

The core requirement:
> Provide an automated generator (`aiosh prove restraint` and MCP tool `aios.restraint.prove`) that extracts cryptographic evidence from the audit ring, external checkpoints, and segment Bloom filters to prove negative attestation: that a given capability or grant was **never exercised** within a specified time window $[T_{start}, T_{end}]$.

---

## 2. Technical Facts vs Assumptions

### Facts (Empirically Grounded in Codebase & Prior Components)
1. **Structural Enforcement (Component 1 & 2)**:
   - When a capability is granted, `pep.capability.mint` is committed with a single-use token (`gr_...`).
   - Before executing privileged actions, `_dispatch.py` executes `audit_client.grant_redeem()`, writing `pep.capability.redeem` carrying `grant_token`.
   - Double-spend attempts are blocked at the gate.
2. **External Anchors (Component 3)**:
   - `$AIOSH_HOME/anchors/anchors.jsonl` contains Ed25519-signed checkpoints binding `(seq, head_hash, timestamp)`.
   - Any log truncation or history fork is detected by `verify_chain_against_anchors`.
3. **Segment Bloom Filter Exclusion (RFC 9162 & Sprint 3 Retention)**:
   - `audit_segments` table stores bit-identical Bloom filters (`bloom_m_bits`, `bloom_k`, `bloom_hex`) for each archived segment.
   - If `bloom_test(bits, m, k, grant_token) == False`, the grant token is guaranteed not to exist in that segment with zero false negatives ($P(\text{false negative}) = 0$).
4. **Live Table Row Traversal**:
   - For rows currently live in `audit_ring`, a linear walk over $[seq_{start}, seq_{end}]$ verifies that no row matches `grant_token == G` and `tool == "pep.capability.redeem"`.

### Assumptions (To Be Codified in Specification T-02863)
1. **Self-Contained Proof Package**:
   - The proof package must bundle everything required for an independent auditor:
     - Anchor records bounding the start and end of the query window.
     - The grant mint record (proving the capability existed and was active).
     - Segment IDs and Bloom exclusion proofs for archived periods.
     - Canonical hashes of all live rows in the interval linking $A_{start}$ to $A_{end}$.
2. **Zero Live Database Dependency for Verifier**:
   - An auditor with only `restraint_proof.json` and the public anchor key can verify non-use without access to `audit.db` (Invariant I-4).

---

## 3. Cryptographic Proof Composition

The proof is formed by a 4-part cryptographic bundle:
$$\Pi = \left\langle A_{start}, A_{end}, \mathcal{R}_{mint}, \mathcal{S}_{archived}, \mathcal{H}_{live} \right\rangle$$

1. **Window Anchors**:
   - $A_{start}$: valid signature at sequence $S_1$ with timestamp $\le T_{start}$.
   - $A_{end}$: valid signature at sequence $S_2$ with timestamp $\ge T_{end}$.
2. **Capability Grant Binding**:
   - Row $\mathcal{R}_{mint}$ at sequence $S_{mint} \le S_2$ asserting grant $G$ for capability $C$ and target $T$.
3. **Archived Segments**:
   - For all segments $k \in \mathcal{S}_{archived}$, $\text{BloomTest}(k, G) = \text{False}$, proving absence.
4. **Live Chain Continuous Link**:
   - Sequence of hashes from $S_1$ to $S_2$ verifying that $H_{i} = \text{SHA-256}(H_{i-1} \parallel \text{row}_i)$, and $\forall i \in [S_1, S_2]$, $\text{row}_i.\text{grant\_token} \neq G$.

---

## 4. Architectural Decisions for T-02863
1. **CLI Surface**: `aiosh prove restraint --grant <token> --window <duration> --out <path>`.
2. **MCP Surface**: `aios.restraint.prove(grant_id, window_start, window_end)`.
3. **Format**: JSON artifact conforming to `PLAN.md` §5.2.
