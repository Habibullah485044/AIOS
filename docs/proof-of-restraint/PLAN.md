# AIOS — Proof of Restraint: Architectural Plan & Living Specification

| Field | Value |
|---|---|
| **Feature ID** | `proof-of-restraint` |
| **Status** | Accepted & Locked via ADR-0037 |
| **Date Initiated** | 2026-10-04 |
| **Pillar** | Pillar C (AI Kernel Subsystem) & Pillar 2 (Security Kernel & PEP Fabric) |
| **Ledger Epic** | `Proof of Restraint` |
| **Ledger Block** | `docs/proof-of-restraint/ledger_block.json` |
| **Execution Log** | `docs/proof-of-restraint/LOG.md` |
| **Target ADR** | `mostimportanAIfolder/ADR-0037-proof-of-restraint.md` (Accepted & Binding) |

---

## 1. Executive Summary & Vision

### 1.1 The Concept
Traditional system audit rings provide **positive attestation**: every record proves that an action took place.
**Proof of Restraint** provides the inverse: **cryptographically verifiable negative attestation**.
> *"This agent possessed the capability to modify or access target $X$ between time $T_1$ and $T_2$, and provably did not exercise it."*

While capability is a commodity, **provable restraint is a trust moat**. In autonomous agent systems, proving what an agent *abstained* from doing is foundational for:
1. **AI Liability Insurance**: Enabling actuaries to mathematically bound exposure and price agent-behavior policies.
2. **EU AI Act & Regulatory Conformity**: Demonstrating continuous adherence to operational constraints without relying on blind trust in operator logs.
3. **High-Privilege Delegation**: Allowing operators to grant high-tier permissions with mathematical certainty that dormant privileges were never abused.

### 1.2 The Core Problem: Absence of Evidence vs. Evidence of Absence
Anyone can present an empty or clean log by simply turning off the logger or deleting lines. To make negative attestation cryptographically sound, we must ensure:
1. **Actions cannot occur without spending a one-time token** (Structural gate).
2. **Tokens cannot be spent without writing an immutable ledger record** (Redeem-before-act).
3. **The audit ring cannot be truncated or rewritten without detection** (External anchoring).

---

## 2. Threat Model & Security Bounds

| Threat ID | Threat Description | Mitigation Mechanism |
|---|---|---|
| **T-1: Covert Erasure & Re-Chaining** | An adversary or rogue process deletes an action row and recomputes hashes from genesis to present a "clean" ring. | **Signed external checkpoints (Layer 2)**: Chain head hashes are published to immutable anchors outside `audit.db`. Re-chaining breaks anchor alignment. |
| **T-2: Direct Access Bypass** | An agent or sub-process accesses sensitive resources directly, bypassing PEP and logging. | **Structural mediation (Layer 1)**: Consequential resources are walled behind the PEP gate. Capabilities are single-use, tightly scoped tokens. |
| **T-3: Double Redemption** | A single capability token is spent multiple times while only one audit row is logged. | **Atomic one-shot token invalidation**: Token status is marked redeemed atomically in WAL transaction before tool execution starts. |
| **T-4: Log Truncation** | An operator truncates the end of the log to hide recent unauthorized usage. | **Completeness proof**: Verifier checks the queried interval $[T_1, T_2]$ against contiguous checkpoints covering up to $T \ge T_2$. |
| **T-5: Cross-Substrate Hash Drift** | Differences in JSON serialization between TypeScript, Python, and Rust lead to broken hash chains during verification. | **Strict canonical JSON invariant**: Lexicographical key sorting, explicit `null` coercion, zero whitespace (cross-language test parity). |

---

## 3. The Three-Layer Architecture

```
+-------------------------------------------------------------------------+
| Layer 3: Hardware Enclave / TEE (Roadmap / Enterprise)                 |
|   - Remote attestation of PEP dispatcher and audit ring binary          |
|   - Closes "compromised host root" threat                               |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Layer 2: Provably Complete Anchored Hash Chain (Core)                   |
|   - External Head Anchoring (GPG/Ed25519 signatures, git commits)       |
|   - Segment Bloom Filter negative exclusion                             |
|   - Range completeness verification over [T1, T2]                       |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Layer 1: Structural Non-Use & One-Shot Token Gate (Foundation)          |
|   - One-shot expiring capability grants (grant.mint)                    |
|   - Mandatory atomic redemption before dispatch (grant.redeem)          |
|   - Resource structurally inaccessible without redemption receipt       |
+-------------------------------------------------------------------------+
```

### Layer 1: Structural Non-Use (One-Shot Capability Gate)
1. **Grant Minting**: When an agent is granted a capability, a `pep.capability.mint` row is appended to the audit ring. The grant contains:
   - `grant_token`: Unique cryptographically random identifier (`gr_...`).
   - `capability`: e.g., `prod.ledger.write`, `database.drop`, `network.raw`.
   - `target`: Target URI, path, or resource identifier.
   - `valid_window`: `[not_before, expires_at]`.
   - `single_use`: Boolean flag enforcing one-shot redemption.
2. **Atomic Redemption**: Before any privileged tool or syscall executes, PEP executes an atomic redemption transaction:
   - Checks token validity and unspent status.
   - Commits a `pep.capability.redeem` row to `audit_ring`.
   - Passes execution to the tool only after the row hash is committed.
3. **Absence Property**: If a capability token expired without a corresponding `pep.capability.redeem` entry in the chain, it was **never exercised**.

### Layer 2: Anchored Hash Chain & Completeness Proofs
1. **Live Chain Invariants**: Every row links to the previous row via `prev_hash` using `SHA-256(prev_hash || canonicalJson(proto))`.
2. **External Anchoring**: At fixed cadences (time-based or row-count based), the current head hash and sequence number are signed by a designated anchor key and appended to `$AIOSH_HOME/anchors.jsonl` (or committed to external storage).
3. **Retention & Bloom Filters**: When rows are rotated into archive segments (ADR-0036), the segment Bloom filter records all `grant_token` IDs and tool names present in that segment.
   - If `bloom.test(token_id) == false`, the token is guaranteed not present in that entire segment without decompressing or replaying millions of rows.
4. **Interval Proof Generation**:
   Given a capability token $G$ and window $[T_1, T_2]$:
   - Collect anchor $A_{start} \le T_1$ and $A_{end} \ge T_2$.
   - Extract relevant segment Bloom filters and live row sequences.
   - Produce a cryptographic package proving that no row in the range contains `grant_token == G` and `action == "pep.capability.redeem"`.

### Layer 3: Hardware Enclave (TEE)
- Running dispatch inside an SGX/TrustZone enclave with remote attestation is the ultimate defense against an adversary with host root privileges.
- In accordance with the pragmatic engineering roadmap, Layers 1 and 2 deliver 90% of the mathematical assurance and are delivered first. Layer 3 is positioned in Phase 6 (Kernel-Level Control).

---

## 4. System Invariants (I-1 through I-5)

Any code modifying grants, audit, PEP, or dispatch **must uphold these invariants**:

* **Invariant I-1 (Mint/Redeem Audit Parity)**:
  Every grant issuance writes exactly one `pep.capability.mint` audit row. Every grant consumption writes exactly one `pep.capability.redeem` audit row. Both must be verifiable across TypeScript, Python, and Rust environments via canonical JSON.
* **Invariant I-2 (Redeem-Before-Act Enforcement)**:
  No consequential tool execution may proceed without first committing a valid, unspent `pep.capability.redeem` row. Any failure during execution leaves the redemption recorded (preventing replay).
* **Invariant I-3 (External Anchor Immutability)**:
  Chain heads must be periodically anchored outside `audit.db`. Verification of restraint requires valid anchor signatures covering the entire query window.
* **Invariant I-4 (Zero-Trust Standalone Verifier)**:
  The standalone verifier (`aiosh-verify-restraint`) must require only the proof package and public anchor keys. It must have zero network or disk access to the live `audit.db`.
* **Invariant I-5 (Continuous Conformance Gate)**:
  CI must execute automated conformance suites verifying that new tool additions cannot bypass the redeem gate and that restraint proofs for untouched grants consistently pass.

---

## 5. Specification of Formats & Interfaces

### 5.1 Audit Row Schema Extensions
In `AuditRow`:
- `tool`: `"pep.capability.mint"` | `"pep.capability.redeem"` | ...
- `grant_token`: String identifier (`gr_<hex16>`)
- `args`:
  - For `mint`: `{ "capability": string, "target": string, "valid_from": ISO8601, "valid_to": ISO8601, "single_use": boolean }`
  - For `redeem`: `{ "capability": string, "target": string, "command": string }`

### 5.2 Restraint Proof Package (`restraint_proof.json`)
```json
{
  "schema_version": 1,
  "proof_id": "por_9f83a1b2c4...",
  "generated_at": "2026-10-04T18:00:00Z",
  "capability": {
    "grant_token": "gr_a1b2c3d4e5f67890",
    "capability": "ledger.admin.write",
    "target": "docs/tasks/MASTER_TASK_LEDGER.jsonl",
    "window": {
      "start": "2026-10-04T14:00:00Z",
      "end": "2026-10-04T14:20:00Z"
    }
  },
  "anchors": {
    "start_anchor": { "seq": 12040, "head_hash": "e3b0c44...", "ts": "2026-10-04T13:59:50Z", "sig": "..." },
    "end_anchor": { "seq": 12510, "head_hash": "4a5e1e...", "ts": "2026-10-04T14:20:15Z", "sig": "..." }
  },
  "segments_checked": [
    { "segment_id": 4, "bloom_negative": true, "archive_sha256": "..." }
  ],
  "live_range": {
    "first_seq": 12041,
    "last_seq": 12509,
    "merkle_subroot": "...",
    "chain_hashes": ["..."]
  },
  "verdict": "PROVABLY_RESTRAINED"
}
```

### 5.3 CLI & MCP Surface
- **CLI Commands**:
  - `aiosh cap mint --cap <name> --target <target> --ttl <duration>` -> outputs grant token
  - `aiosh prove restraint --grant <token> --window <duration> --out <file.json>`
  - `aiosh verify restraint --proof <file.json> --anchor-key <pubkey>`
- **MCP Wire Tools**:
  - `aios.capability.mint`
  - `aios.restraint.prove`
  - `aios.restraint.verify`

---

## 6. Living Document Protocol: Rules for Coding Agents

To ensure that multiple agents (Claude, Gemini, Codex, or human operators) maintain this feature cohesively over 10,000 tasks:

1. **Check Before Work**:
   Before implementing any task touching grants, audit, or dispatch, the agent must read `docs/proof-of-restraint/PLAN.md`.
2. **Log After Completion**:
   Every completed step or task must append an entry to `docs/proof-of-restraint/LOG.md` recording:
   - Date & Task ID (e.g. `T-02831`)
   - Summary of changes made
   - Files created or modified
   - Tests run and verification output
3. **Plan Mutation Invariant**:
   If an implementation detail uncovers a technical flaw, the agent **must not silently diverge**. The agent must:
   - Update `docs/proof-of-restraint/PLAN.md`.
   - Add a row to the **Change Log** table in Section 7 explaining *what* changed and *why*.
   - If standing rules change, run `python tools/ledger_insert_block.py refresh-rules --spec docs/proof-of-restraint/ledger_block.json`.

---

## 7. Change Log (Living Document Tracking)

| Date | Task ID | Author | Section | Nature of Change & Technical Justification |
|---|---|---|---|---|
| 2026-10-04 | Pre-T-02831 | Architecture Agent | All | Initial comprehensive baseline plan & living specification created. |
| 2026-10-04 | T-02831 | Architecture Agent | All | Locked ADR-0037 as accepted and binding; verified code baseline. |
