# SPEC-0038: Chain Anchoring & Completeness Checkpoints

**Status**: Shipped (Tasks T-02852 – T-02861)  
**Parent Architecture**: ADR-0037 (Proof of Restraint), `docs/proof-of-restraint/PLAN.md` §Layer 2  
**Key Invariant**: **Invariant I-3 (External Anchor Immutability)**  

---

## 1. Overview & Threat Model

While the internal SQLite audit ring (`audit.db`) maintains a cryptographic hash chain from genesis, an adversary with database write privileges could potentially recalculate a synthetic hash chain from genesis to head, rewriting history to omit evidence of actions.

**Chain Anchoring** resolves this by periodically signing the chain head (`seq`, `head_hash`, `timestamp`) with an external Ed25519 private key that `audit.db` **never stores**, persisting signed checkpoints to an append-only JSONL log (`$AIOSH_HOME/anchors/anchors.jsonl`).

Any attempt to:
1. **Truncate** the audit chain (drop recent rows) triggers `TRUNCATION_DETECTED`.
2. **Fork or rewrite** intermediate history triggers `FORK_DETECTED`.
3. **Forge** checkpoints without the designated private key triggers `SIGNATURE_INVALID` or `UNTRUSTED_KEY`.

---

## 2. Anchor Format & Storage

### 2.1 Anchor Record (`AnchorRecord`)
Stored in `$AIOSH_HOME/anchors/anchors.jsonl` as canonical JSON lines:

```json
{
  "schema_version": 1,
  "seq": 105,
  "head_hash": "c1a4e231b40286438072bc5df89032ad8e2cf5e1435790a88b56f9e9e1c31204",
  "timestamp": "2026-10-07T05:30:00Z",
  "pubkey": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  "signature": "e5564300d984...<64-byte Ed25519 signature in 128 hex chars>..."
}
```

### 2.2 Canonical Payload
Cross-substrate determinism between Python and TypeScript is maintained via canonical JSON serialization:

$$\text{payload} = \text{canonicalJson}(\{\text{"head\_hash"}: H, \text{"seq"}: S, \text{"timestamp"}: T\})$$

---

## 3. Operational Invocations

### 3.1 CLI Commands (`aiosh-cli`)

1. **Create Anchor**:
   ```bash
   aiosh anchor create --key <64_HEX_PRIVATE_KEY>
   ```
   *Or with environment variable:*
   ```bash
   export AIOSH_ANCHOR_KEY="<64_HEX_PRIVATE_KEY>"
   aiosh anchor create
   ```

2. **Verify Against Anchors**:
   ```bash
   aiosh anchor verify --pubkey <64_HEX_TRUSTED_PUBKEY>
   ```

### 3.2 MCP Tool Surface (`aiosh-mcp`)

1. **`aios.anchor.create`**:
   ```json
   {
     "name": "aios_anchor_create",
     "arguments": {
       "key_hex": "<optional_64_hex_key>"
     }
   }
   ```

2. **`aios.anchor.verify`**:
   ```json
   {
     "name": "aios_anchor_verify",
     "arguments": {
       "pubkey": "<optional_trusted_pubkey>"
     }
   }
   ```

---

## 4. Security Invariants & Limitations

1. **Zero Key Storage in Database**:
   - `audit.db` contains NO private key columns or tables.
   - Audit emissions record only `{ "has_key": true }` to prevent leakage.
2. **Permissions**:
   - Anchors directory is enforced at `0700` and anchor log files at `0600`.
3. **Known Limitations**:
   - Anchors protect against unauthorized truncation and re-branching. If the host disk containing `$AIOSH_HOME/anchors/anchors.jsonl` is completely wiped alongside `audit.db`, external multi-destination replication (e.g. cloud or witness logging) is required for full disaster recovery.

---

## 5. Linked Evidence
- Research: [T-02852-research.md](file:///C:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02852-research.md)
- Specification: [T-02853-spec.md](file:///C:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02853-spec.md)
- Scaffolding: [T-02854-scaffold.md](file:///C:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02854-scaffold.md)
- Implementation: [T-02855-implementation.md](file:///C:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02855-implementation.md)
- Unit Test: [T-02856-unit-test.md](file:///C:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02856-unit-test.md)
- Integration: [T-02857-integration.md](file:///C:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02857-integration.md)
- Security Review: [T-02858-security.md](file:///C:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02858-security.md)
- Hardening: [T-02859-hardening.md](file:///C:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02859-hardening.md)
