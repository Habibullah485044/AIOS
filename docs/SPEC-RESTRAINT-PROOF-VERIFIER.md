# Specification: Standalone Proof Verifier (Component 5)

- **Document ID**: `SPEC-RESTRAINT-PROOF-VERIFIER-v1`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint (Component 5)
- **Status**: LOCKED / IMPLEMENTED
- **Related Documents**: ADR-0037, [PLAN.md](proof-of-restraint/PLAN.md), [SPEC-RESTRAINT-PROOF-GENERATOR.md](SPEC-RESTRAINT-PROOF-GENERATOR.md)
- **Invariant**: `I-4` (Self-Contained Negative Attestation Package)

---

## 1. Overview & Architectural Role

The **Standalone Proof Verifier** is the zero-trust counterpart of the Restraint Proof Generator (Component 4). Where the generator *produces* a `RestraintProofPackage`, the verifier *adjudicates* it: given nothing but the proof package and a set of explicitly trusted Ed25519 public keys, it decides mathematically whether the claim of restraint holds.

Per Invariant `I-4`, the verifier operates with:

- **Zero database access** — it never opens `audit.db`, never queries `pep_grants`, and never touches the agent host state.
- **Zero network reliance** — no RPC, no anchor fetching, no clock queries.
- **Zero operator honesty assumptions** — every field is either cryptographically checked or structurally bounded.

The verifier is therefore safe to run inside an auditor's or insurer's own infrastructure, on a machine that has never seen the AIOS host. The only inputs are the proof bytes and the trusted key set.

```
+----------------------------------------------------------------------------------+
|                        Standalone Proof Verifier (Component 5)                    |
|                                                                                  |
|  [restraint_proof.json / JSON string / dict]   [trusted Ed25519 pubkeys]         |
|              |                                              |                   |
|              v                                              v                   |
|  +-----------------------------------------------------------------------------+ |
|  | 0. Payload & Structure Hardening (size caps, collection caps, type guards)  | |
|  +-----------------------------------------------------------------------------+ |
|              |                                                                   |
|              v                                                                   |
|  +-----------------------------------------------------------------------------+ |
|  | 1. CHECK_SCHEMA        — schema_version=1, mandatory fields, strict types   | |
|  | 2. CHECK_GRANT         — unredeemed, single_use, window inside grant bounds | |
|  | 3. CHECK_ANCHOR_KEYS   — both anchor pubkeys ∈ trusted set                  | |
|  | 4. CHECK_ANCHOR_SIGS   — Ed25519 signatures over canonical anchor payloads | |
|  | 5. CHECK_ANCHOR_BOUNDS — T_start_a <= T_s, T_end_a >= T_e, seq ordering    | |
|  | 6. CHECK_BLOOM_EXCLUSION — grant absent from every archived segment Bloom  | |
|  | 7. CHECK_LIVE_CHAIN    — live chain tail == end_anchor.head_hash            | |
|  +-----------------------------------------------------------------------------+ |
|              |                                                                   |
|              v                                                                   |
|   VerificationResult { valid, proof_id, reason?, checks{1..7} }                  |
+----------------------------------------------------------------------------------+
```

Verification is **fail-closed**: any malformed, oversized, unparseable, or hostile input produces `valid=false` with an explicit `VERIFY_FAILED: <CODE>` reason. The verifier never throws on hostile input — exceptions are converted to rejection verdicts.

---

## 2. VerificationResult Schema

```json
{
  "valid": false,
  "proof_id": "por_0123456789abcdef01234567",
  "reason": "VERIFY_FAILED: BLOOM_INDICATES_PRESENCE: segment 1 bloom matches grant grant-root-ledger-01",
  "checks": {
    "schema": true,
    "grant": true,
    "anchor_keys": true,
    "anchor_sigs": true,
    "anchor_bounds": true,
    "bloom_exclusion": false,
    "live_chain": false
  }
}
```

- `checks` is always fully populated (all 7 gates present); gates not reached remain `false`.
- `to_canonical_json()` serializes deterministically (sorted keys, no whitespace) for evidence embedding.

---

## 3. Gate Semantics & Invariant Rules

| Gate | Assertion | Rejection Code |
|---|---|---|
| `CHECK_SCHEMA` | `schema_version == 1`; `proof_id`, `grant`, `window`, `anchors`, `segments_checked`, `live_range` present; structural types correct (objects/lists/strings); collection caps hold | `UNSUPPORTED_SCHEMA_VERSION`, `MISSING_FIELD`, `INVALID_SCHEMA`, `PROOF_TOO_COMPLEX` |
| `CHECK_GRANT` | `grant_id` a bounded non-empty string; `redeemed_at is None`; `single_use == true`; window parses as ISO-8601 UTC and `T_s <= T_e`; grant validity interval contains `[T_s, T_e]` | `GRANT_INVALID`, `GRANT_REDEEMED`, `WINDOW_INVALID`, `TIMESTAMP_INVALID` |
| `CHECK_ANCHOR_KEYS` | `start_anchor.pubkey` and `end_anchor.pubkey` are both members of the caller-supplied trusted set | `UNTRUSTED_KEY`, `MISSING_ANCHORS` |
| `CHECK_ANCHOR_SIGS` | Both anchor records reconstruct to their canonical payload and verify under Ed25519 | `INVALID_ANCHOR_PAYLOAD`, `INVALID_ANCHOR_SIGNATURE` |
| `CHECK_ANCHOR_BOUNDS` | `T_start_a <= T_s`, `T_end_a >= T_e`, `seq_start_a <= seq_end_a` — as **UTC instants**, not strings | `UNBOUNDED_WINDOW`, `TIMESTAMP_INVALID` |
| `CHECK_BLOOM_EXCLUSION` | For every archived segment: either a certified `bloom_negative`, or an embedded Bloom filter in which the `grant_id` does **not** test positive | `BLOOM_POSITIVE`, `BLOOM_INDICATES_PRESENCE`, `BLOOM_INVALID` |
| `CHECK_LIVE_CHAIN` | If live hashes are present, `hashes[-1] == end_anchor.head_hash` (chain substitution detection) | `HEAD_HASH_MISMATCH` |

Mathematically, acceptance means:

$$\forall\, s \in \texttt{segments\_checked}: \mathrm{bloom\_test}(s, grant\_id) = \text{false} \;\wedge\; \mathrm{tail}(live) = H_{end\_anchor} \;\wedge\; T_{start\_a} \le T_s < T_e \le T_{end\_a}$$

with both anchors authentic under keys the *auditor* trusts — a zero-false-negative negative attestation over the whole claimed window.

---

## 4. Hardening Bounds (T-02879)

| Constant | Value | Purpose |
|---|---|---|
| `MAX_PROOF_PAYLOAD_BYTES` | 20 MiB | Caps proof file size and raw JSON string size **before parsing** (`PAYLOAD_TOO_LARGE`) |
| `MAX_SEGMENTS_COUNT` | 10 000 | Caps `segments_checked` length (`PROOF_TOO_COMPLEX`) |
| `MAX_LIVE_HASHES_COUNT` | 100 000 | Caps `live_range.hashes` length (`PROOF_TOO_COMPLEX`) |
| `MAX_BLOOM_BITS` | 16 000 000 | Caps `bloom_m_bits` per segment; must be a positive multiple of 8 |
| `MAX_BLOOM_K` | 64 | Caps Bloom hash-count `k` (`BLOOM_INVALID`) |
| `MAX_FIELD_STR_LEN` | 4 096 | Caps `grant_id` length (`GRANT_INVALID`) |

Additional decode guarantees:

- `bloom_hex` must be strict hex with exact `m/4` length (TypeScript `Buffer.from(hex)` silently truncates malformed hex, so a regex guard enforces Python `bytes.fromhex` strictness).
- All timestamps (`window.start/end`, `grant.issued_at/expires_at`, `start/end_anchor.timestamp`) are parsed to UTC instants (naive values coerced to UTC, offsets normalized) and compared chronologically — never lexicographically (`TIMESTAMP_INVALID`).

---

## 5. API, MCP & CLI Interface

### Python (`code/aiosh-mcp/aiosh_mcp/verifier.py`)

```python
from aiosh_mcp.verifier import verify_restraint_proof, VerificationResult

result = verify_restraint_proof(proof, trusted_pubkeys)   # proof: dict | JSON str | file path
if result.valid:
    ...                                                   # result.checks holds all 7 gates
```

Standalone CLI (zero imports beyond the package):

```bash
python -m aiosh_mcp.verifier restraint_proof.json --pubkey <ed25519-hex> [--pubkey <hex2> ...]
# exit 0 + canonical JSON when valid; exit 1 + reason when rejected
```

### TypeScript (`code/aiosh-cli/src/verifier.ts`)

```typescript
import { verifyRestraintProof } from "./verifier.js";
const res = verifyRestraintProof(proofOrPath, ["<ed25519-hex>", ...]);
```

### MCP tool

`aios.restraint.verify` — arguments: `proof` (package or path), `trusted_pubkeys: string[]`; returns the `VerificationResult` envelope; refusal outcome carries the `VERIFY_FAILED` reason.

### CLI

```bash
aiosh prove verify --proof restraint_proof.json --pubkey <ed25519-hex> ...
# falls back to AIOSH_ANCHOR_PUBKEY when --pubkey is omitted
```

---

## 6. Error Catalog

| Code | Meaning | Operator Action |
|---|---|---|
| `PARAM_INVALID` | Proof input type unparseable (not dict/JSON/path) | Re-emit the proof as canonical JSON or a file path |
| `PAYLOAD_TOO_LARGE` | Proof exceeds 20 MiB | Request a re-export; oversized proofs are refused before parsing |
| `PROOF_TOO_COMPLEX` | Segment/hash collections exceed caps | Request a re-export with bounded collections |
| `INVALID_SCHEMA` | Structural type violation | Reject the producer; the package is not schema-conformant |
| `UNSUPPORTED_SCHEMA_VERSION` | `schema_version != 1` | Upgrade verifier or re-export at v1 |
| `MISSING_FIELD` | Mandatory top-level field absent | Reject; incomplete attestation |
| `TIMESTAMP_INVALID` | Non ISO-8601 UTC timestamp | Reject; producer must normalize timestamps |
| `GRANT_INVALID` / `GRANT_REDEEMED` | Grant missing, malformed, non-single-use, expired, or redeemed | Restraint claim does not hold for this grant |
| `WINDOW_INVALID` | `T_s > T_e` or window outside grant validity | Re-request with a coherent window |
| `UNTRUSTED_KEY` | Anchor signed by a key outside the trusted set | Out-of-band key verification required |
| `INVALID_ANCHOR_SIGNATURE` / `INVALID_ANCHOR_PAYLOAD` | Anchor cryptographically invalid | Reject; tampering or corruption |
| `UNBOUNDED_WINDOW` | Anchors do not bracket the claimed window | Reject; the window is not fully observed |
| `BLOOM_POSITIVE` / `BLOOM_INDICATES_PRESENCE` | Grant found (or uncertified) in an archived segment | Restraint claim **violated** |
| `BLOOM_INVALID` | Bloom parameters/hex malformed | Reject; producer defect or tampering |
| `HEAD_HASH_MISMATCH` | Live chain tail ≠ end anchor head | Reject; chain substitution attempt |

---

## 7. Trust Model & Invariants

- **Trusted key custody**: the verifier never derives trust. Anchor public keys must arrive from the auditor out-of-band; `AIOSH_ANCHOR_PUBKEY` or `--pubkey` are the only trust inputs.
- **Fail-closed**: every gate failure returns `valid=false`; there is no code path returning `valid=true` with any check unmet (`checks` all true is required).
- **I-4 conformance**: the verdict depends only on the proof bytes and the trusted keys — verified by the zero-database test in `code/aiosh-mcp/tests/test_por_verifier.py` (no `sqlite3` usage on the verify path).
- **Substrate parity**: Python and TypeScript implementations enforce identical bounds, codes, and gate order; the shared test battery (38 passed, 1 skipped) exercises both surfaces.
