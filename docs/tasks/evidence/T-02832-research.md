# T-02832: Capability Mint/Redeem Records — Research

- **Task**: `T-02832`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records
- **Date**: 2026-10-04
- **Status**: Research Complete

---

## 1. Context & Prior Art

### 1.1 Existing Implementations in AIOS
- **TypeScript (`code/aiosh-cli/src/pep.ts`)**:
  - `PepGrantManager.create()` inserts records into `pep_grants` table (`grant_id`, `issued_at`, `expires_at`, `issued_to`, `scope_json`, `scope_hash`, `revoked_at`).
  - Grants currently have a TTL (`ttl_seconds`, default 3600s) and can be revoked, but are **multi-use** during their active window.
  - Grant creation does not automatically emit a `pep.capability.mint` row into `audit_ring`.
- **Audit Ring (`code/aiosh-cli/src/audit.ts`)**:
  - SQLite WAL table with `grant_token TEXT` column already present.
  - Rows are hashed via `SHA-256(prev_hash || canonicalJson(proto))`.
- **Rust Core (`code/aiosh-rust/aiosh-core/src/pep_grant_service.rs`)**:
  - Parallel data structures for PEP grants in Rust.
- **Python MCP (`code/aiosh-mcp/aiosh_mcp/`)**:
  - `audit_client.py` and `server.py` enforce canonical JSON formatting.

---

## 2. Authoritative Sources & Standards
1. **Capability-Based Computer Systems (Saltzer & Schroeder, 1975)**:
   - Confinement Problem: Verifying that an authorized entity did not propagate or misuse authority.
2. **Macaroons: Cookies with Contextual Caveats for Decentralized Authorization (Birgisson et al., NDSS 2014)**:
   - First-party and third-party caveats with single-use attenuation.
3. **RFC 9162 (Certificate Transparency Log)**:
   - Cryptographic proofs of inclusion and exclusion in append-only ledgers.

---

## 3. Fact vs. Assumption

| Category | Finding | Evidence / Citation |
|---|---|---|
| **Fact** | `audit_ring` already has `grant_token` column indexed. | `code/aiosh-cli/src/audit.ts:175` |
| **Fact** | `pep_grants` lacks `single_use` and `redeemed_at` columns. | `code/aiosh-cli/src/pep.ts:87-96` |
| **Fact** | Canonical JSON serializer is deterministic across TS/Py/Rust. | `code/aiosh-cli/src/audit.ts:30-43` |
| **Assumption (False)** | "Grants are currently one-shot." | Code review proves grants can be presented multiple times until expiry. |
| **Requirement** | Every mint must emit a `pep.capability.mint` audit row with `grant_token`. | PLAN.md §3 Layer 1 & Invariant I-1 |
| **Requirement** | Every redemption must emit a `pep.capability.redeem` audit row with `grant_token`. | PLAN.md §3 Layer 1 & Invariant I-1 |

---

## 4. Decisions & Unknowns for Specification (`T-02833`)
1. **Decision**: Extend `pep_grants` schema with `single_use INTEGER DEFAULT 1` and `redeemed_at TEXT`.
2. **Decision**: `PepGrantManager.create()` must take an optional `AuditRing` instance (or be called via coordinator) to write `pep.capability.mint`.
3. **Decision**: `PepGrantManager.redeem()` method must atomically mark the token redeemed and write `pep.capability.redeem` to the audit ring within a SQLite WAL transaction.
4. **Unknown**: Ensure backward compatibility for grants created by existing CLI tests where `AuditRing` was not injected.
