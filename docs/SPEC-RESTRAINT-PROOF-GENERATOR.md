# Specification: Restraint Proof Generator (Component 4)

- **Document ID**: `SPEC-RESTRAINT-PROOF-GENERATOR-v1`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint (Component 4)
- **Status**: LOCKED / IMPLEMENTED
- **Related Documents**: [ADR-0037](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/mostimportanAIfolder/ADR-0037-proof-of-restraint.md), [PLAN.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/proof-of-restraint/PLAN.md)
- **Invariant**: `I-4` (Self-Contained Negative Attestation Package)

---

## 1. Overview & Architectural Role

Traditional audit logging produces **positive attestations**: proof that an agent executed specific actions at specific times. However, in high-security, autonomous agent deployments (e.g., granting temporary elevated or root-level capability), compliance auditors and AI liability insurers require the inverse: **Proof of Restraint** — a mathematical and cryptographic proof that an authorized capability was *never consumed* during a defined operational window $[T_{start}, T_{end}]$.

The **Restraint Proof Generator** is the core cryptographic engine responsible for synthesizing positive logs, external Ed25519 completeness anchors, and archived segment Bloom filters into an immutable, self-contained `RestraintProofPackage` (`restraint_proof.json`).

```
+-----------------------------------------------------------------------------------+
|                           Restraint Proof Generator                               |
|                                                                                   |
|  [Grant ID]  [Window Start]  [Window End]  [anchors.jsonl]  [audit.db]            |
|       |             |              |               |             |                |
|       v             v              v               v             v                |
|  +-----------------------------------------------------------------------------+  |
|  | 1. Parameter Validation (Strict ISO-8601 UTC & Safe Path Traversal Guards)  |  |
|  +-----------------------------------------------------------------------------+  |
|       |                                                                           |
|       v                                                                           |
|  +-----------------------------------------------------------------------------+  |
|  | 2. Grant State Verification (pep_grants table: unredeemed + unrevoked)      |  |
|  +-----------------------------------------------------------------------------+  |
|       |                                                                           |
|       v                                                                           |
|  +-----------------------------------------------------------------------------+  |
|  | 3. Covering Anchor Discovery (Strict bounding: T_start_a <= T_s, T_end_a >= T_e)  |
|  +-----------------------------------------------------------------------------+  |
|       |                                                                           |
|       v                                                                           |
|  +-----------------------------------------------------------------------------+  |
|  | 4. Archived Segment Bloom Exclusion Check (Zero False Negative Attestation) |  |
|  +-----------------------------------------------------------------------------+  |
|       |                                                                           |
|       v                                                                           |
|  +-----------------------------------------------------------------------------+  |
|  | 5. Live Range Scan (Contiguous WAL hash chain between anchors)               |  |
|  +-----------------------------------------------------------------------------+  |
|       |                                                                           |
|       v                                                                           |
|  +-----------------------------------------------------------------------------+  |
|  | 6. Package Assembly & Canonical JSON Serialization (verdict: PROVABLY_RESTRAINED)|
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 2. RestraintProofPackage Schema (v1)

The output proof is deterministic, self-contained, and serialized in canonical JSON (lexicographically sorted keys, no extraneous whitespace).

```json
{
  "schema_version": 1,
  "proof_id": "por_0123456789abcdef01234567",
  "generated_at": "2026-10-07T12:05:00.000000Z",
  "grant": {
    "grant_id": "grant-root-ledger-01",
    "issued_at": "2026-10-07T12:00:00Z",
    "expires_at": "2026-10-07T23:59:59Z",
    "issued_to": "agent:auto-rebalance",
    "single_use": true,
    "redeemed_at": null
  },
  "window": {
    "start": "2026-10-07T12:01:00Z",
    "end": "2026-10-07T12:04:00Z"
  },
  "anchors": {
    "start_anchor": {
      "schema_version": 1,
      "seq": 1,
      "head_hash": "4a5e1e4baab89f3a...",
      "timestamp": "2026-10-07T12:00:00Z",
      "pubkey": "05bf33a105...",
      "signature": "3f98a2..."
    },
    "end_anchor": {
      "schema_version": 1,
      "seq": 20,
      "head_hash": "9b1287cba1450e12...",
      "timestamp": "2026-10-07T12:05:00Z",
      "pubkey": "05bf33a105...",
      "signature": "c87a11..."
    }
  },
  "segments_checked": [
    {
      "segment_id": 1,
      "row_range": [1, 10],
      "archive_sha256": "deadbeef...",
      "bloom_negative": true
    }
  ],
  "live_range": {
    "first_seq": 11,
    "last_seq": 20,
    "row_count": 10,
    "hashes": [
      "hash_0011",
      "hash_0012",
      "..."
    ]
  },
  "verdict": "PROVABLY_RESTRAINED"
}
```

---

## 3. Generator Algorithm & Invariant Rules

### Invariant I-4 Check Sequence
1. **Timestamp Normalization**: Reject non-ISO-8601 or non-UTC timestamps. Ensure `window_start <= window_end`.
2. **Grant Uniqueness & Non-Redemption**:
   - Query `pep_grants` by `grant_id`. Must exist and `redeemed_at` must be `NULL`.
   - Query `audit_ring` where `grant_token = ? AND tool = 'pep.capability.redeem'`. Must return 0 rows.
3. **Bounding Anchors Selection (Strict Bounding Guard)**:
   - Load signed external anchors from `anchors.jsonl`.
   - Identify candidate set $S = \{ A \mid A.timestamp \le window\_start \}$. If $S = \emptyset$, fail with `NO_COVERING_ANCHORS`. Select $start\_anchor = \max_{seq}(S)$.
   - Identify candidate set $E = \{ A \mid A.timestamp \ge window\_end \}$. If $E = \emptyset$, fail with `NO_COVERING_ANCHORS`. Select $end\_anchor = \min_{seq}(E)$.
   - Verify $start\_anchor.seq \le end\_anchor.seq$.
4. **Archived Segment Bloom Verification**:
   - For all archived segments intersecting $[start\_anchor.seq, end\_anchor.seq]$:
   - Query segment record (`bloom_m_bits`, `bloom_k`, `bloom_hex`).
   - Run `bloom_test(bits, m, k, grant_id)`. If true, fail closed with `GRANT_REDEEMED`.
   - Record `bloom_negative: true` in `segments_checked`.
5. **Live Range Continuity Verification**:
   - Query live `audit_ring` rows between $[start\_anchor.seq, end\_anchor.seq]$.
   - Confirm no row carries `grant_token == grant_id && tool == 'pep.capability.redeem'`.
   - Extract contiguous sequence of row hashes.
6. **Deterministic Seed & Proof ID**:
   - Seed: `grant_id:window_start:window_end:now_iso`
   - Proof ID: `por_${sha256(seed).hexdigest()[:24]}`

---

## 4. API & CLI Interface

### FastMCP Protocol
- **Tool Name**: `aios.restraint.prove`
- **Arguments**:
  - `grant_id: str` (required)
  - `window_start: str` (required, ISO-8601 UTC)
  - `window_end: str` (required, ISO-8601 UTC)
  - `anchors_path: str | None` (optional)
  - `caller_grant_id: str | None` (optional)
- **Return Type**:
  - Success: `{ ok: True, tool: "aios.restraint.prove", proof: {...}, audit_id: int }`
  - Failure: `{ ok: False, tool: "aios.restraint.prove", error: str, audit_id: int }`

### CLI Command
```bash
aiosh prove restraint \
  --grant grant-root-01 \
  --window-start 2026-10-07T12:00:00Z \
  --window-end 2026-10-07T12:30:00Z \
  --anchors ~/.aios/anchors/anchors.jsonl \
  --out /tmp/proof.json
```

---

## 5. Error Catalog

| Error Code | Meaning | Remediation |
|---|---|---|
| `PARAM_INVALID` | Invalid timestamp format, empty parameter, or path containing NUL byte | Provide valid ISO-8601 UTC timestamps and clean paths |
| `WINDOW_INVALID` | `window_start > window_end` | Ensure interval is chronological |
| `GRANT_NOT_FOUND` | `grant_id` is not present in `pep_grants` | Mint grant prior to attestation query |
| `GRANT_REDEEMED` | Grant was marked redeemed in grant store, WAL, or segment Bloom filter | Grant was consumed; negative attestation refused |
| `NO_COVERING_ANCHORS` | Missing external anchors bounding window | Run `aiosh anchor create` or configure automated checkpointing |

---

## 6. Verifier Hand-off (Component 5 Contract)
The output package generated by this specification contains all information required by `aiosh-verify-restraint` (Component 5). The verifier requires zero database access: it takes only `restraint_proof.json` and trusted public keys, validating signatures, Bloom parameters, and hash chains purely mathematically.
