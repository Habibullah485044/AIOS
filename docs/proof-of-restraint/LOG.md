# Proof of Restraint — Execution & Progress Log

This log is an append-only living record tracking all engineering work, architectural changes, test runs, and validations performed for the **Proof of Restraint** epic.

All agents (Gemini, Claude, or human developers) working on tasks within this feature block or on downstream tasks governed by `[PoR]` standing rules must append entries here upon task completion.

---

## Log Entries

### 2026-10-04 — Genesis & Tooling Preparation
- **Task**: Pre-Kickoff Architectural Setup & Ledger Tooling
- **Agent**: Antigravity System
- **Summary**:
  - Researched existing `AuditRing` WAL table, canonical JSON hash chains, PEP grant architecture, and segment bloom filters.
  - Formulated the 3-Layer Proof-of-Restraint model (Layer 1: Structural one-shot redeem gate; Layer 2: Anchored hash chain & completeness proofs; Layer 3: Hardware enclave / TEE).
  - Drafted formal `docs/proof-of-restraint/PLAN.md` with system invariants `I-1` through `I-5` and living document rules.
  - Drafted `docs/proof-of-restraint/ledger_block.json` defining the 62-task sequential REP block and standing rules for downstream tasks.
  - Implemented `tools/ledger_insert_block.py` with `insert` and `refresh-rules` commands to safely insert tasks into the master ledger without breaking history, contiguous IDs, or event logs.
  - Added unit test suite `tools/test_ledger_insert_block.py` verifying sandboxed insertion, renumbering, duplicate prevention, and standing rules refresh (6/6 tests passing).
- **Files Touched**:
  - `tools/generate_master_tasks.py` (added overwrite guard and reusable `build_component_tasks` helper)
  - `docs/proof-of-restraint/ledger_block.json` (created)
  - `docs/proof-of-restraint/PLAN.md` (created)
  - `docs/proof-of-restraint/LOG.md` (created)
  - `tools/ledger_insert_block.py` (created)
  - `tools/test_ledger_insert_block.py` (created)
- **Status / Next Steps**:
  - Ready for formal insertion of the Proof of Restraint feature block into `MASTER_TASK_LEDGER.jsonl`.

### 2026-10-04 — T-02831: Kickoff ADR + Living Plan Locked
- **Task ID**: `T-02831`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / Kickoff
- **Agent**: Antigravity System
- **Summary**:
  - Locked `mostimportanAIfolder/ADR-0037-proof-of-restraint.md` as accepted and binding.
  - Formally linked ADR-0037 in `docs/proof-of-restraint/PLAN.md`.
  - Audited security posture: verified that without external anchoring, a simple SHA-256 WAL hash chain can be rewritten from genesis; certified Layer 1 (one-shot token gate) and Layer 2 (external checkpoints & Bloom exclusion) as required counter-measures.
  - Verified ledger invariants and all smoke suites green.
- **Files Touched**:
  - `mostimportanAIfolder/ADR-0037-proof-of-restraint.md` (created)
  - `docs/proof-of-restraint/PLAN.md` (updated status and change log)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Kickoff complete. Advancing to T-02832 (`capability mint/redeem records: Research`).

### 2026-10-04 — T-02832: Capability Mint/Redeem Records — Research
- **Task ID**: `T-02832`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records
- **Agent**: Antigravity System
- **Summary**:
  - Researched existing `PepGrantManager` in `code/aiosh-cli/src/pep.ts` and `AuditRing` in `code/aiosh-cli/src/audit.ts`.
  - Established fact vs assumption: `audit_ring` already has `grant_token` column, but `pep_grants` table lacks `single_use` and `redeemed_at` tracking; grants are currently multi-use during their active TTL.
  - Confirmed architectural requirement: every grant issue must write `pep.capability.mint` and every use must atomically write `pep.capability.redeem` to establish Layer 1 Proof of Restraint.
  - Recorded findings and decisions for specification in `docs/tasks/evidence/T-02832-research.md`.
- **Files Touched**:
  - `docs/tasks/evidence/T-02832-research.md` (created)
  - `docs/tasks/evidence/T-02832-capability-mint-redeem-records-research.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Research complete. Advancing to T-02833 (`capability mint/redeem records: Specification`).

### 2026-10-04 — T-02833: Capability Mint/Redeem Records — Specification
- **Task ID**: `T-02833`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records
- **Agent**: Antigravity System
- **Summary**:
  - Specified contracts for `PepGrant` type extensions (`single_use`, `redeemed_at`, `RedeemResult`).
  - Specified database schema migration for `pep_grants` in SQLite WAL audit DB.
  - Specified atomic pre-execution redemption semantics for `PepGrantManager.redeem()` and emission of `pep.capability.mint` / `pep.capability.redeem` audit rows.
  - Formulated failure envelopes and negative error codes.
  - Captured complete specification in `docs/tasks/evidence/T-02833-spec.md`.
- **Files Touched**:
  - `docs/tasks/evidence/T-02833-spec.md` (created)
  - `docs/tasks/evidence/T-02833-capability-mint-redeem-records-specification.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Specification complete. Advancing to T-02834 (`capability mint/redeem records: Scaffold`).

### 2026-10-04 — T-02834: Capability Mint/Redeem Records — Scaffold
- **Task ID**: `T-02834`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records
- **Agent**: Antigravity System
- **Summary**:
  - Added `single_use` and `redeemed_at` to `PepGrant` and `CreateOpts`, and created `RedeemResult` in `code/aiosh-cli/src/types.ts`.
  - Added typed method stub `PepGrantManager.redeem()` in `code/aiosh-cli/src/pep.ts` (throwing `NotImplementedError`).
  - Ran `npm run build` (zero TypeScript errors) and verified `test_capability_cli_smoke.py` PASS.
- **Files Touched**:
  - `code/aiosh-cli/src/types.ts` (modified)
  - `code/aiosh-cli/src/pep.ts` (modified)
  - `docs/tasks/evidence/T-02834-capability-mint-redeem-records-scaffold.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Scaffold complete. Advancing to T-02835 (`capability mint/redeem records: Implementation`).
### 2026-10-04 — T-02835: Capability Mint/Redeem Records — Implementation
- **Task ID**: `T-02835`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records
- **Agent**: Antigravity System
- **Summary**:
  - Implemented `single_use` and `redeemed_at` tracking in SQLite WAL table `pep_grants` in `code/aiosh-cli/src/pep.ts`.
  - Added emission of `pep.capability.mint` audit event during grant creation in `PepGrantManager.create()`.
  - Implemented atomic `redeem()` method with SQL writeback of `redeemed_at` and emission of `pep.capability.redeem` audit row with outcome="ok".
  - Enforced single-use gate: second redemption attempts return `allowed: false` with error `"single-use grant already redeemed at ..."`.
  - Added unit test `code/aiosh-cli/tests/test_restraint_mint_redeem.py` verifying full mint, check, redeem, double-redemption refusal, and audit ring hash-chain integrity.
- **Files Touched**:
  - `code/aiosh-cli/src/pep.ts` (modified)
  - `code/aiosh-cli/tests/test_restraint_mint_redeem.py` (created)
  - `docs/tasks/evidence/T-02835-capability-mint-redeem-records-implementation.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-04 — T-02836: Capability Mint/Redeem Records — Unit Test
- **Task ID**: `T-02836`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records
- **Agent**: Antigravity System
- **Summary**:
  - Expanded unit test suite `code/aiosh-cli/tests/test_restraint_mint_redeem.py` with 7 dedicated test cases.
  - Verified mint audit event generation, pre-redemption unspent status, atomic single-use redemption, and double-spend rejection.
  - Verified expired grant rejection and tamper detection pinpointing corruption at exact sequence number.
  - Passed all existing capability CLI smoke tests.
- **Files Touched**:
  - `code/aiosh-cli/tests/test_restraint_mint_redeem.py` (modified)
  - `docs/tasks/evidence/T-02836-capability-mint-redeem-records-unit-test.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-04 — T-02837: Capability Mint/Redeem Records — Integration
- **Task ID**: `T-02837`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records
- **Agent**: Antigravity System
- **Summary**:
  - Implemented and executed cross-substrate integration test in `code/aiosh-cli/tests/test_por_integration.py`.
  - Verified shared SQLite WAL synchronization between TypeScript grant management and Python MCP audit client.
  - Confirmed 100% hash chain compatibility across cross-language boundaries with identical canonical JSON serialization.
  - Validated full lifecycle: mint event -> unspent verification -> single-use redemption event -> replay rejection -> complete chain audit.
- **Files Touched**:
  - `code/aiosh-cli/tests/test_por_integration.py` (created)
  - `docs/tasks/evidence/T-02837-capability-mint-redeem-records-integration.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-04 — T-02838: Capability Mint/Redeem Records — Security Review
- **Task ID**: `T-02838`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records
- **Agent**: Antigravity System
- **Summary**:
  - Performed comprehensive security audit of capability mint and redeem implementation.
  - Verified Invariants I-1 and I-2 under `[PoR]` standing rule: confirmed no state-changing path executes without token consumption.
  - Audited race condition defenses: validated atomic SQL conditional update (`WHERE redeemed_at IS NULL`) preventing double-spend and TOCTOU.
  - Verified SQL parameterized query hygiene, fail-closed handling on expiry/revocation, and SHA-256 chain tamper-evidence.
  - Documented findings in `docs/tasks/evidence/T-02838-capability-mint-redeem-records-security-review.md`.
- **Files Touched**:
  - `docs/tasks/evidence/T-02838-capability-mint-redeem-records-security-review.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-04 — T-02839: Capability Mint/Redeem Records — Hardening
- **Task ID**: `T-02839`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records
- **Agent**: Antigravity System
- **Summary**:
  - Hardened `PepGrantManager.redeem()` in `code/aiosh-cli/src/pep.ts`.
  - Added strict parameter bounding (8192 characters) for `tool` and `command` strings to block DoS.
  - Implemented explicit distinction between single-use conditional locking (`redeemed_at IS NULL`) and multi-use timestamp recording.
  - Added atomic rollback of `redeemed_at` in the event of `AuditRing` write failure to preserve fail-closed synchronization.
  - Passed clean TypeScript build and all unit & integration test suites.
- **Files Touched**:
  - `code/aiosh-cli/src/pep.ts` (modified)
  - `docs/tasks/evidence/T-02839-capability-mint-redeem-records-hardening.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02840: Capability Mint/Redeem Records — Documentation
- **Task ID**: `T-02840`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records
- **Agent**: Antigravity System
- **Summary**:
  - Authored comprehensive specification document `docs/SPEC-RESTRAINT-MINT-REDEEM.md`.
  - Documented schema contracts for `pep_grants` table and event payloads for `pep.capability.mint` and `pep.capability.redeem`.
  - Provided working TypeScript and Python cross-substrate usage examples.
  - Honestly documented security bounds, unanchored chain limitations, and crash consistency semantics.
- **Files Touched**:
  - `docs/SPEC-RESTRAINT-MINT-REDEEM.md` (created)
  - `docs/tasks/evidence/T-02840-capability-mint-redeem-records-documentation.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02841: Capability Mint/Redeem Records — Verification & Evidence
- **Task ID**: `T-02841`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records
- **Agent**: Antigravity System
- **Summary**:
  - Executed full test verification suite: unit test (`test_restraint_mint_redeem.py`), integration test (`test_por_integration.py`), and CLI smoke test (`test_capability_cli_smoke.py`). All passed 100% green.
  - Formally certified Invariant I-1 (1:1 mint:redeem mapping) and Invariant I-2 (atomic single-use gate).
  - Closed Component 1 ("capability mint/redeem records") with evidence in `docs/tasks/evidence/T-02841-verify.md`.
- **Files Touched**:
  - `docs/tasks/evidence/T-02841-verify.md` (created)
  - `docs/tasks/evidence/T-02841-capability-mint-redeem-records-verification-evidenc.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02842: Redeem-Before-Act Gate — Research
- **Task ID**: `T-02842`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate
- **Agent**: Antigravity System
- **Summary**:
  - Researched all tool dispatch pathways across Python MCP server (`_dispatch.py`, `server.py`), TypeScript agent loop (`agent.ts`), CLI tools (`cli.ts`), and Rust kernel.
  - Identified critical invariant gap: `_dispatch.py` checked scope and expiry via `grant_check()` but failed to execute atomic single-use redemption, allowing arbitrary re-use of grants for consequential tools.
  - Established concrete architectural blueprint: implement `grant_redeem()` in `audit_client.py` and bind it into `_dispatch.dispatch()` to enforce Invariant I-2 before tool execution starts.
- **Files Touched**:
  - `docs/tasks/evidence/T-02842-research.md` (created)
  - `docs/tasks/evidence/T-02842-redeem-before-act-gate-research.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02843: Redeem-Before-Act Gate — Specification
- **Task ID**: `T-02843`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate
- **Agent**: Antigravity System
- **Summary**:
  - Specified contracts for `audit_client.grant_redeem()` with atomic conditional SQL update and fail-closed rollback.
  - Specified integration of `grant_redeem()` into `aiosh_mcp._dispatch.dispatch()`.
  - Defined explicit failure envelopes and rejection reasons (`"already redeemed at ..."`, `"expired"`).
  - Formally guaranteed Invariant I-2: tool invocation is blocked if single-use redemption fails, ensuring zero unrecorded consequential actions.
- **Files Touched**:
  - `docs/tasks/evidence/T-02843-spec.md` (created)
  - `docs/tasks/evidence/T-02843-redeem-before-act-gate-specification.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02844: Redeem-Before-Act Gate — Scaffold
- **Task ID**: `T-02844`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate
- **Agent**: Antigravity System
- **Summary**:
  - Scaffolded typed stub for `audit_client.grant_redeem()` in `code/aiosh-mcp/aiosh_mcp/audit_client.py`.
  - Verified clean module imports and verified that un-implemented invocation raises `NotImplementedError`.
  - Ran capability CLI smoke tests (100% green).
- **Files Touched**:
  - `code/aiosh-mcp/aiosh_mcp/audit_client.py` (modified)
  - `docs/tasks/evidence/T-02844-redeem-before-act-gate-scaffold.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02845: Redeem-Before-Act Gate — Implementation
- **Task ID**: `T-02845`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate
- **Agent**: Antigravity System
- **Summary**:
  - Implemented `audit_client.grant_redeem()` in `code/aiosh-mcp/aiosh_mcp/audit_client.py` with atomic conditional SQL update and rollback protection.
  - Wired Gate #2.5 redeem-before-act validation into `_dispatch.dispatch()` in `code/aiosh-mcp/aiosh_mcp/_dispatch.py`.
  - Added unit test `code/aiosh-mcp/tests/test_por_redeem_gate.py` verifying single-use token consumption, replay rejection, and hash chain verification.
- **Files Touched**:
  - `code/aiosh-mcp/aiosh_mcp/audit_client.py` (modified)
  - `code/aiosh-mcp/aiosh_mcp/_dispatch.py` (modified)
  - `code/aiosh-mcp/tests/test_por_redeem_gate.py` (created)
  - `docs/tasks/evidence/T-02845-redeem-before-act-gate-implementation.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02846: Redeem-Before-Act Gate — Unit Test
- **Task ID**: `T-02846`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate
- **Agent**: Antigravity System
- **Summary**:
  - Expanded unit test suite `code/aiosh-mcp/tests/test_por_redeem_gate.py` with 6 dedicated test cases.
  - Verified happy path redemption, double-spend replay refusal at Gate #2.5, expired token rejection, out-of-scope tool rejection, and missing grant handling.
  - Verified multi-use grant semantics and end-to-end hash chain integrity across all events.
- **Files Touched**:
  - `code/aiosh-mcp/tests/test_por_redeem_gate.py` (modified)
  - `docs/tasks/evidence/T-02846-redeem-before-act-gate-unit-test.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02847: Redeem-Before-Act Gate — Integration
- **Task ID**: `T-02847`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate
- **Agent**: Antigravity System
- **Summary**:
  - Wired and verified the redeem-before-act gate through the real FastMCP and `pentest` tool execution surface (`aios_pentest_nmap`).
  - Added end-to-end integration test `code/aiosh-mcp/tests/test_por_gate_integration.py` proving that consequential tool execution commits `pep.capability.redeem` prior to host execution and blocks replay attempts.
  - Verified 100% hash chain integrity across all test runs.
- **Files Touched**:
  - `code/aiosh-mcp/tests/test_por_gate_integration.py` (created)
  - `docs/tasks/evidence/T-02847-redeem-before-act-gate-integration.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02848: Redeem-Before-Act Gate — Security Review
- **Task ID**: `T-02848`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate
- **Agent**: Antigravity System
- **Summary**:
  - Performed deep security review of the redeem-before-act gate across all dispatch paths.
  - Verified standing rule `[PoR]` / Invariant I-2: certified zero bypass paths exist across FastMCP tools and pentest wrappers.
  - Audited race condition defenses in atomic conditional SQLite updates and validated fail-closed rollback handling on audit failure.
  - Documented findings in `docs/tasks/evidence/T-02848-security.md`.
- **Files Touched**:
  - `docs/tasks/evidence/T-02848-security.md` (created)
  - `docs/tasks/evidence/T-02848-redeem-before-act-gate-security-review.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02849: Redeem-Before-Act Gate — Hardening
- **Task ID**: `T-02849`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate
- **Agent**: Antigravity System
- **Summary**:
  - Hardened `audit_client.grant_redeem()` with SQLite WAL `busy_timeout = 5000` to prevent lock errors under concurrency.
  - Added input parameter sanitization and length bounds (8192 characters).
  - Isolated Gate #2.5 redemption in `_dispatch.dispatch()` with exception trapping and honest refusal audit row logging, guaranteeing fail-closed execution.
  - Verified all integration, unit, and capability smoke test suites green.
- **Files Touched**:
  - `code/aiosh-mcp/aiosh_mcp/audit_client.py` (modified)
  - `code/aiosh-mcp/aiosh_mcp/_dispatch.py` (modified)
  - `docs/tasks/evidence/T-02849-redeem-before-act-gate-hardening.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02850: Redeem-Before-Act Gate — Documentation
- **Task ID**: `T-02850`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate
- **Agent**: Antigravity System
- **Summary**:
  - Authored specification document `docs/SPEC-REDEEM-BEFORE-ACT-GATE.md`.
  - Documented complete dispatch sequence (Gate #1 -> Gate #2 -> Gate #2.5 -> Execution -> Commit).
  - Provided copy-pasteable examples for FastMCP tool calls and dispatch checks.
  - Formulated honest limitations regarding crash consistency and lock timeouts.
- **Files Touched**:
  - `docs/SPEC-REDEEM-BEFORE-ACT-GATE.md` (created)
  - `docs/tasks/evidence/T-02850-redeem-before-act-gate-documentation.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02851: Redeem-Before-Act Gate — Verification & Evidence
- **Task ID**: `T-02851`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate
- **Agent**: Antigravity System
- **Summary**:
  - Executed full test verification suite: integration test (`test_por_gate_integration.py`), unit test (`test_por_redeem_gate.py`), and capability smoke tests (`test_capability_cli_smoke.py`). All passed 100% green.
  - Formally certified Invariant I-2: consequential actions cannot run without committing a `pep.capability.redeem` audit row first, and replay attempts are rejected at the dispatch gate.
  - Closed Component 2 ("redeem-before-act gate") with evidence in `docs/tasks/evidence/T-02851-verify.md`.
- **Files Touched**:
  - `docs/tasks/evidence/T-02851-verify.md` (created)
  - `docs/tasks/evidence/T-02851-redeem-before-act-gate-verification-evidenc.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Component 2 complete! Advancing to Component 3: T-02852 (`chain anchoring & completeness checkpoints: Research`).

### 2026-10-07 — T-02852: Chain Anchoring & Completeness Checkpoints — Research
- **Task ID**: `T-02852`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / chain anchoring & completeness checkpoints
- **Agent**: Antigravity System
- **Summary**:
  - Researched external chain anchoring and completeness checkpoints for Layer 2 Proof of Restraint and Invariant I-3.
  - Analyzed threat model: an adversary with SQLite write access can recompute a valid alternative hash chain from genesis if all state resides solely inside `audit.db`.
  - Identified cryptographic grounding in RFC 9162 (Signed Tree Heads) and RFC 8032 (Ed25519 digital signatures).
  - Codified key separation: signing key must reside strictly outside `audit.db` (in filesystem keyfile or environment), verified using standalone public keys.
  - Outlined external append-only anchor log format (`$AIOSH_HOME/anchors.jsonl`) and canonical JSON payload structure.
  - Documented findings in `docs/tasks/evidence/T-02852-research.md` and pointer artifact.
- **Files Touched**:
  - `docs/tasks/evidence/T-02852-research.md` (created)
  - `docs/tasks/evidence/T-02852-chain-anchoring-completeness-checkpoints-research.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02853 (`chain anchoring & completeness checkpoints: Specification`).

### 2026-10-07 — T-02853: Chain Anchoring & Completeness Checkpoints — Specification
- **Task ID**: `T-02853`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / chain anchoring & completeness checkpoints
- **Agent**: Antigravity System
- **Summary**:
  - Authored formal specification for Chain Anchoring & Completeness Checkpoints implementing Invariant I-3.
  - Specified `AnchorRecord` schema with `schema_version`, `seq`, `head_hash`, `timestamp`, `pubkey`, and 64-byte Ed25519 signature.
  - Specified canonical JSON byte payload hashing rules to guarantee cross-substrate determinism between Python and TypeScript.
  - Defined external persistence contract: `$AIOSH_HOME/anchors/anchors.jsonl`, strict key file permissions, and zero private key presence in `audit.db`.
  - Defined comprehensive verification API contract (`verify_chain_against_anchors`) handling truncation, forks, and signature corruption.
  - Documented specification in `docs/tasks/evidence/T-02853-spec.md` and pointer artifact.
- **Files Touched**:
  - `docs/tasks/evidence/T-02853-spec.md` (created)
  - `docs/tasks/evidence/T-02853-chain-anchoring-completeness-checkpoints-specification.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02854 (`chain anchoring & completeness checkpoints: Scaffold`).

### 2026-10-07 — T-02854: Chain Anchoring & Completeness Checkpoints — Scaffold
- **Task ID**: `T-02854`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / chain anchoring & completeness checkpoints
- **Agent**: Antigravity System
- **Summary**:
  - Created module skeletons for Chain Anchoring in Python (`code/aiosh-mcp/aiosh_mcp/anchors.py`) and TypeScript (`code/aiosh-cli/src/anchors.ts`).
  - Implemented typed `AnchorRecord` data model with canonical JSON conversion and schema parsing.
  - Defined strict method signatures with `NotImplementedError` / `Error("Not implemented")` bodies for key generation, signing, verification, and chain integrity checking.
  - Verified Python import and TypeScript `npm run build` and `npm run typecheck` pass with 0 errors.
  - Documented scaffolding in `docs/tasks/evidence/T-02854-scaffold.md` and pointer artifact.
- **Files Touched**:
  - `code/aiosh-mcp/aiosh_mcp/anchors.py` (created)
  - `code/aiosh-cli/src/anchors.ts` (created)
  - `docs/tasks/evidence/T-02854-scaffold.md` (created)
  - `docs/tasks/evidence/T-02854-chain-anchoring-completeness-checkpoints-scaffold.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02855 (`chain anchoring & completeness checkpoints: Implementation`).

### 2026-10-07 — T-02855: Chain Anchoring & Completeness Checkpoints — Implementation
- **Task ID**: `T-02855`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / chain anchoring & completeness checkpoints
- **Agent**: Antigravity System
- **Summary**:
  - Implemented cross-substrate Ed25519 signing and verification in Python (`code/aiosh-mcp/aiosh_mcp/anchors.py`) and TypeScript (`code/aiosh-cli/src/anchors.ts`).
  - Implemented canonical JSON byte payload hashing guaranteeing cross-language signature determinism.
  - Implemented `append_anchor`, `load_anchors`, and `verify_chain_against_anchors` validating against tampering, key mismatch, truncation, and forks.
  - Validated Python assertions and TypeScript runtime behavior. Rebuilt TypeScript (`npm run build`) cleanly.
  - Validated zero regression in existing test suite (`test_por_gate_integration.py`).
  - Documented implementation in `docs/tasks/evidence/T-02855-implementation.md` and pointer artifact.
- **Files Touched**:
  - `code/aiosh-mcp/aiosh_mcp/anchors.py` (updated)
  - `code/aiosh-cli/src/anchors.ts` (updated)
  - `code/aiosh-cli/dist/anchors.js` (compiled)
  - `code/aiosh-cli/dist/anchors.d.ts` (compiled)
  - `docs/tasks/evidence/T-02855-implementation.md` (created)
  - `docs/tasks/evidence/T-02855-chain-anchoring-completeness-checkpoints-implementation.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02856 (`chain anchoring & completeness checkpoints: Unit Test`).

### 2026-10-07 — T-02856: Chain Anchoring & Completeness Checkpoints — Unit Test
- **Task ID**: `T-02856`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / chain anchoring & completeness checkpoints
- **Agent**: Antigravity System
- **Summary**:
  - Added unit test suite `code/aiosh-mcp/tests/test_por_chain_anchoring.py` verifying Invariant I-3.
  - Tested positive and negative cases: Ed25519 keypair generation, signature verification, corrupt signature rejection, tampered seq/head_hash/timestamp rejection, untrusted key rejection.
  - Verified chain completeness checks against signed checkpoints: untampered chain passes, truncated chain fails with `TRUNCATION_DETECTED`, forked/modified chain fails with `FORK_DETECTED`.
  - Verified key separation invariant (no private key material stored in `audit.db`).
  - Executed tests standalone and via `pytest` (9/9 passed).
  - Documented evidence in `docs/tasks/evidence/T-02856-unit-test.md` and pointer artifact.
- **Files Touched**:
  - `code/aiosh-mcp/tests/test_por_chain_anchoring.py` (created)
  - `docs/tasks/evidence/T-02856-unit-test.md` (created)
  - `docs/tasks/evidence/T-02856-chain-anchoring-completeness-checkpoints-unit-test.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02857 (`chain anchoring & completeness checkpoints: Integration`).

### 2026-10-07 — T-02857: Chain Anchoring & Completeness Checkpoints — Integration
- **Task ID**: `T-02857`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / chain anchoring & completeness checkpoints
- **Agent**: Antigravity System
- **Summary**:
  - Wired external chain anchoring into FastMCP tool surface (`aios_anchor_create`, `aios_anchor_verify`) in `code/aiosh-mcp/aiosh_mcp/server.py`.
  - Added CLI command group `aiosh anchor create` and `aiosh anchor verify` in `code/aiosh-cli/src/cli.ts`.
  - Added helper `head()` to `code/aiosh-mcp/aiosh_mcp/audit_client.py` for reading the current chain head.
  - Added end-to-end integration test `code/aiosh-mcp/tests/test_por_anchoring_integration.py` exercising tool registration, anchor creation, audit row recording, verification, fork detection, and truncation detection.
  - Ran full test suite across all PoR components (11/11 tests passing).
  - Documented evidence in `docs/tasks/evidence/T-02857-integration.md` and pointer artifact.
- **Files Touched**:
  - `code/aiosh-mcp/aiosh_mcp/server.py` (updated)
  - `code/aiosh-mcp/aiosh_mcp/audit_client.py` (updated)
  - `code/aiosh-cli/src/cli.ts` (updated)
  - `code/aiosh-cli/dist/cli.js` (compiled)
  - `code/aiosh-mcp/tests/test_por_anchoring_integration.py` (created)
  - `docs/tasks/evidence/T-02857-integration.md` (created)
  - `docs/tasks/evidence/T-02857-chain-anchoring-completeness-checkpoints-integration.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02858 (`chain anchoring & completeness checkpoints: Security Review`).

### 2026-10-07 — T-02858: Chain Anchoring & Completeness Checkpoints — Security Review
- **Task ID**: `T-02858`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / chain anchoring & completeness checkpoints
- **Agent**: Antigravity System
- **Summary**:
  - Conducted security review of Component 3 (chain anchoring & completeness checkpoints).
  - Evaluated key separation: verified zero private key storage in `audit.db` and zero private key leakage in `audit_ring` arguments across both MCP and CLI surfaces.
  - Analyzed threat models and attack scenarios: private key WAL leakage (prevented), rogue anchor forgery (prevented via pinned `trusted_pubkey`), chain truncation (detected via `TRUNCATION_DETECTED`), and history rewrites (detected via `FORK_DETECTED`).
  - Identified hardening recommendations for T-02859: directory permission enforcement, strict key length validation, and malformed JSONL error handling.
  - Documented findings in `docs/tasks/evidence/T-02858-security.md` and pointer artifact.
- **Files Touched**:
  - `docs/tasks/evidence/T-02858-security.md` (created)
  - `docs/tasks/evidence/T-02858-chain-anchoring-completeness-checkpoints-security-review.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02859 (`chain anchoring & completeness checkpoints: Hardening`).

### 2026-10-07 — T-02859: Chain Anchoring & Completeness Checkpoints — Hardening
- **Task ID**: `T-02859`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / chain anchoring & completeness checkpoints
- **Agent**: Antigravity System
- **Summary**:
  - Hardened Python (`anchors.py`) and TypeScript (`anchors.ts`) against input injection, memory exhaustion, and invalid keys.
  - Added strict 64-hex string regex and decoding validation on all private and public keys.
  - Added file size limit (`MAX_ANCHORS_FILE_SIZE = 10MB`) to prevent DoS via oversized log files.
  - Added directory permission enforcement (`0700`) and key/anchor file permission restrictions (`0600`).
  - Added fail-closed line parsing with explicit line number reporting on corrupted records in `anchors.jsonl`.
  - Rebuilt TypeScript (`npm run build`) and verified full test suite passes (11/11 tests).
  - Documented evidence in `docs/tasks/evidence/T-02859-hardening.md` and pointer artifact.
- **Files Touched**:
  - `code/aiosh-mcp/aiosh_mcp/anchors.py` (hardened)
  - `code/aiosh-cli/src/anchors.ts` (hardened)
  - `code/aiosh-cli/dist/anchors.js` (compiled)
  - `docs/tasks/evidence/T-02859-hardening.md` (created)
  - `docs/tasks/evidence/T-02859-chain-anchoring-completeness-checkpoints-hardening.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02860 (`chain anchoring & completeness checkpoints: Documentation`).

### 2026-10-07 — T-02860: Chain Anchoring & Completeness Checkpoints — Documentation
- **Task ID**: `T-02860`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / chain anchoring & completeness checkpoints
- **Agent**: Antigravity System
- **Summary**:
  - Authored comprehensive specification document `docs/SPEC-CHAIN-ANCHORING.md` documenting Invariant I-3, canonical JSON formatting, Ed25519 signatures, and error responses.
  - Documented CLI invocations (`aiosh anchor create`, `aiosh anchor verify`) and FastMCP tool invocations (`aios_anchor_create`, `aios_anchor_verify`).
  - Outlined known limitations and linked all architectural evidence files.
  - Documented evidence in `docs/tasks/evidence/T-02860-documentation.md` and pointer artifact.
- **Files Touched**:
  - `docs/SPEC-CHAIN-ANCHORING.md` (created)
  - `docs/tasks/evidence/T-02860-documentation.md` (created)
  - `docs/tasks/evidence/T-02860-chain-anchoring-completeness-checkpoints-documentation.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02861 (`chain anchoring & completeness checkpoints: Verification & Evidence`).

### 2026-10-07 — T-02861: Chain Anchoring & Completeness Checkpoints — Verification & Evidence
- **Task ID**: `T-02861`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / chain anchoring & completeness checkpoints
- **Agent**: Antigravity System
- **Summary**:
  - Successfully verified Component 3 ("chain anchoring & completeness checkpoints") and Invariant I-3.
  - Validated all 11 unit and integration tests across PoR components with 100% pass rate in 2.40s.
  - Validated clean TypeScript compilation with zero type errors.
  - Closed Component 3 with comprehensive evidence in `docs/tasks/evidence/T-02861-verify.md`.
- **Files Touched**:
  - `docs/tasks/evidence/T-02861-verify.md` (created)
  - `docs/tasks/evidence/T-02861-chain-anchoring-completeness-checkpoints-verification-evidenc.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Component 3 complete! Advancing to Component 4: T-02862 (`restraint proof generator: Research`).

### 2026-10-07 — T-02862: Restraint Proof Generator — Research
- **Task ID**: `T-02862`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator
- **Agent**: Antigravity System
- **Summary**:
  - Researched cryptographic and architectural requirements for Component 4 (Restraint Proof Generator).
  - Formulated negative attestation model: proving non-redemption of a capability grant $G$ over window $[T_{start}, T_{end}]$ by combining external anchors, archived segment Bloom filter exclusions, and unbroken live hash chains.
  - Established that segment Bloom filters guarantee zero false negatives ($P=0$) for unexercised grants across cold storage.
  - Outlined self-contained proof package format (`restraint_proof.json`) enabling zero-trust offline verification (Invariant I-4).
  - Documented research in `docs/tasks/evidence/T-02862-research.md` and pointer artifact.
- **Files Touched**:
  - `docs/tasks/evidence/T-02862-research.md` (created)
  - `docs/tasks/evidence/T-02862-restraint-proof-generator-research.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02863 (`restraint proof generator: Specification`).

### 2026-10-07 — T-02863: Restraint Proof Generator — Specification
- **Task ID**: `T-02863`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator
- **Agent**: Antigravity System
- **Summary**:
  - Authored formal specification for Component 4 (Restraint Proof Generator) and Invariant I-4.
  - Specified self-contained `restraint_proof.json` package format encompassing capability parameters, window anchors, archived segment Bloom exclusions, and live range hash continuities.
  - Defined generator API (`generate_restraint_proof`), error conditions (`GRANT_NOT_FOUND`, `GRANT_REDEEMED`, `NO_COVERING_ANCHORS`, `WINDOW_INVALID`), and audit trails.
  - Documented specification in `docs/tasks/evidence/T-02863-spec.md` and pointer artifact.
- **Files Touched**:
  - `docs/tasks/evidence/T-02863-spec.md` (created)
  - `docs/tasks/evidence/T-02863-restraint-proof-generator-specification.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02864 (`restraint proof generator: Scaffold`).

### 2026-10-07 — T-02864: Restraint Proof Generator — Scaffold
- **Task ID**: `T-02864`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator
- **Agent**: Antigravity System
- **Summary**:
  - Created module skeletons for Restraint Proof Generator in Python (`code/aiosh-mcp/aiosh_mcp/restraint.py`) and TypeScript (`code/aiosh-cli/src/restraint.ts`).
  - Implemented typed `RestraintProofPackage` data models with serialization support.
  - Defined strict method signatures with `NotImplementedError` / `Error("Not implemented")` bodies for proof generation.
  - Verified Python import and TypeScript `npm run build` pass with zero errors.
  - Documented scaffolding in `docs/tasks/evidence/T-02864-scaffold.md` and pointer artifact.
- **Files Touched**:
  - `code/aiosh-mcp/aiosh_mcp/restraint.py` (created)
  - `code/aiosh-cli/src/restraint.ts` (created)
  - `docs/tasks/evidence/T-02864-scaffold.md` (created)
  - `docs/tasks/evidence/T-02864-restraint-proof-generator-scaffold.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02865: Restraint Proof Generator — Implementation
- **Task ID**: `T-02865`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator
- **Agent**: Antigravity System
- **Summary**:
  - Implemented `generate_restraint_proof` in Python (`code/aiosh-mcp/aiosh_mcp/restraint.py`) and TypeScript (`code/aiosh-cli/src/restraint.ts`).
  - Implemented validation for grant existence, unredeemed status, bounding anchors selection from `anchors.jsonl`, archived segment Bloom exclusion testing, and live range continuous hash walks.
  - Aligned `_PEP_SCHEMA` in `audit_client.py` with `single_use` and `redeemed_at` columns.
  - Verified targeted tests and confirmed 11/11 tests passing in pytest suite.
  - Documented evidence in `docs/tasks/evidence/T-02865-implementation.md` and pointer artifact.
- **Files Touched**:
  - `code/aiosh-mcp/aiosh_mcp/restraint.py` (updated)
  - `code/aiosh-cli/src/restraint.ts` (updated)
  - `code/aiosh-mcp/aiosh_mcp/audit_client.py` (updated)
  - `code/aiosh-cli/dist/restraint.js` (compiled)
  - `docs/tasks/evidence/T-02865-implementation.md` (created)
  - `docs/tasks/evidence/T-02865-restraint-proof-generator-implementation.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02866 (`restraint proof generator: Unit Test`).

### 2026-10-07 — T-02866: Restraint Proof Generator — Unit Test
- **Task ID**: `T-02866`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator
- **Agent**: Antigravity System
- **Summary**:
  - Implemented unit test suite `code/aiosh-mcp/tests/test_por_restraint_generator.py` (8 test cases).
  - Validated valid proof generation, canonical JSON output, and `PROVABLY_RESTRAINED` verdict.
  - Verified negative security paths: `WINDOW_INVALID`, `GRANT_NOT_FOUND`, `GRANT_REDEEMED` in `pep_grants`, `GRANT_REDEEMED` in `audit_ring`, `GRANT_REDEEMED` via Bloom match, and `NO_COVERING_ANCHORS`.
  - Conducted security audit of test harness and verified cryptographic zero-false-negative guarantees for archived segment Bloom tests.
  - All 8 tests passed in 1.36s (22/22 total PoR suite tests passing).
- **Files Touched**:
  - `code/aiosh-mcp/tests/test_por_restraint_generator.py` (created)
  - `docs/tasks/evidence/T-02866-unit-test.md` (created)
  - `docs/tasks/evidence/T-02866-restraint-proof-generator-unit-test.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02867: Restraint Proof Generator — Integration
- **Task ID**: `T-02867`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator
- **Agent**: Antigravity System
- **Summary**:
  - Registered `aios_restraint_prove` MCP tool in `code/aiosh-mcp/aiosh_mcp/server.py`.
  - Added `aiosh prove restraint` CLI subcommand in `code/aiosh-cli/src/cli.ts` supporting `--grant`, `--window-start`, `--window-end`, `--anchors`, and `--out`.
  - Compiled and typechecked TypeScript distribution (`npm run build`).
  - Implemented integration test suite `code/aiosh-mcp/tests/test_por_restraint_integration.py` verifying MCP tool and CLI proof generation and audit ring emission.
  - Performed security audit verifying error envelopes, parameters, and audit logging.
- **Files Touched**:
  - `code/aiosh-mcp/aiosh_mcp/server.py` (updated)
  - `code/aiosh-cli/src/cli.ts` (updated)
  - `code/aiosh-cli/dist/cli.js` (compiled)
  - `code/aiosh-mcp/tests/test_por_restraint_integration.py` (created)
  - `docs/tasks/evidence/T-02867-integration.md` (created)
  - `docs/tasks/evidence/T-02867-restraint-proof-generator-integration.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02868: Restraint Proof Generator — Security Review
- **Task ID**: `T-02868`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator
- **Agent**: Antigravity System
- **Summary**:
  - Conducted threat modeling and vulnerability assessment across Python and TypeScript implementations of Restraint Proof Generator.
  - Audited 6 threat vectors: window boundary under-coverage, SQL injection, path traversal, Bloom filter collision dynamics, live range tampering, and timestamp skew.
  - Identified critical security finding: anchor candidate fallback logic allowed unbounding anchors if window extended beyond external anchor coverage.
  - Documented findings, threat matrix, and hardening backlog in `docs/tasks/evidence/T-02868-security.md` and pointer artifact.
- **Files Touched**:
  - `docs/tasks/evidence/T-02868-security.md` (created)
  - `docs/tasks/evidence/T-02868-restraint-proof-generator-security-review.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02869: Restraint Proof Generator — Hardening
- **Task ID**: `T-02869`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator
- **Agent**: Antigravity System
- **Summary**:
  - Remediated anchor boundary fallback vulnerability in `restraint.py` and `restraint.ts`: strictly enforce covering bounding anchors ($T_{start\_anchor} \le T_{start}$ and $T_{end\_anchor} \ge T_{end}$) without unsafe fallback.
  - Hardened input validation: added strict ISO-8601 UTC timestamp parsing and sanitized path traversal against NUL bytes.
  - Rebuilt TypeScript distribution (`npm run build`) with zero compiler warnings.
  - Expanded unit test suite `code/aiosh-mcp/tests/test_por_restraint_generator.py` to 11 tests verifying all hardened security guards.
  - Documented hardening evidence in `docs/tasks/evidence/T-02869-hardening.md` and pointer artifact.
- **Files Touched**:
  - `code/aiosh-mcp/aiosh_mcp/restraint.py` (updated)
  - `code/aiosh-cli/src/restraint.ts` (updated)
  - `code/aiosh-mcp/tests/test_por_restraint_generator.py` (updated)
  - `docs/tasks/evidence/T-02869-hardening.md` (created)
  - `docs/tasks/evidence/T-02869-restraint-proof-generator-hardening.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02870: Restraint Proof Generator — Documentation
- **Task ID**: `T-02870`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator
- **Agent**: Antigravity System
- **Summary**:
  - Authored comprehensive architecture and reference specification `docs/SPEC-RESTRAINT-PROOF-GENERATOR.md`.
  - Detailed `RestraintProofPackage` schema v1 canonical JSON format, generator execution flow, strict bounding anchor invariants, Bloom exclusion proofs, error catalog, and API surfaces.
  - Formally defined handoff contracts for Component 5 (Standalone Proof Verifier).
  - Documented evidence in `docs/tasks/evidence/T-02870-doc.md` and pointer artifact.
- **Files Touched**:
  - `docs/SPEC-RESTRAINT-PROOF-GENERATOR.md` (created)
  - `docs/tasks/evidence/T-02870-doc.md` (created)
  - `docs/tasks/evidence/T-02870-restraint-proof-generator-documentation.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02871: Restraint Proof Generator — Verification & Evidence
- **Task ID**: `T-02871`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator
- **Agent**: Antigravity System
- **Summary**:
  - Ran comprehensive regression and verification test suite across Component 4 (14 tests executed, 13 passed, 1 skipped).
  - Validated TypeScript distribution build with zero compiler warnings/errors (`npm run build`).
  - Certified Component 4 (Restraint Proof Generator) as feature-complete, hardened, and locked.
  - Documented verification evidence in `docs/tasks/evidence/T-02871-verify.md` and pointer artifact.
- **Files Touched**:
  - `docs/tasks/evidence/T-02871-verify.md` (created)
  - `docs/tasks/evidence/T-02871-restraint-proof-generator-verification-and-evidence.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02872: Standalone Proof Verifier — Research
- **Task ID**: `T-02872`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / standalone proof verifier
- **Agent**: Antigravity System
- **Summary**:
  - Researched standalone zero-knowledge / zero-trust verifier requirements for Proof of Restraint (Invariant I-4).
  - Formulated 5-step mathematical verification sequence: schema validity, grant non-redemption and window coverage, Ed25519 external anchor signatures and bounding timestamps, Bloom filter negative evaluation, and live range terminal hash matching.
  - Certified zero dependency on host database (`audit.db`), file system, or network credentials.
  - Documented findings in `docs/tasks/evidence/T-02872-research.md` and pointer artifact.
- **Files Touched**:
  - `docs/tasks/evidence/T-02872-research.md` (created)
  - `docs/tasks/evidence/T-02872-standalone-proof-verifier-research.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02873: Standalone Proof Verifier — Specification
- **Task ID**: `T-02873`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / standalone proof verifier
- **Agent**: Antigravity System
- **Summary**:
  - Specified API contracts, data models (`VerificationResult`), and 7 verification stages for Standalone Proof Verifier across Python and TypeScript substrates.
  - Specified pure mathematical and cryptographic verification rules (zero database dependencies).
  - Documented error states, return envelopes, and CLI interface syntax in `docs/tasks/evidence/T-02873-spec.md` and pointer artifact.
- **Files Touched**:
  - `docs/tasks/evidence/T-02873-spec.md` (created)
  - `docs/tasks/evidence/T-02873-standalone-proof-verifier-specification.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02874: Standalone Proof Verifier — Scaffold
- **Task ID**: `T-02874`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / standalone proof verifier
- **Agent**: Antigravity System
- **Summary**:
  - Scaffolding of `code/aiosh-mcp/aiosh_mcp/verifier.py` (Python) and `code/aiosh-cli/src/verifier.ts` (TypeScript).
  - Defined data structures `VerificationResult` and function signatures `verify_restraint_proof` / `verifyRestraintProof`.
  - Verified Python imports and completed TypeScript compilation cleanly (`npm run build`).
  - Documented scaffolding in `docs/tasks/evidence/T-02874-scaffold.md` and pointer artifact.
- **Files Touched**:
  - `code/aiosh-mcp/aiosh_mcp/verifier.py` (created)
  - `code/aiosh-cli/src/verifier.ts` (created)
  - `docs/tasks/evidence/T-02874-scaffold.md` (created)
  - `docs/tasks/evidence/T-02874-standalone-proof-verifier-scaffold.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02875: Standalone Proof Verifier — Implementation
- **Task ID**: `T-02875`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / standalone proof verifier
- **Agent**: Antigravity System
- **Summary**:
  - Implemented standalone zero-trust cryptographic verifier in Python (`code/aiosh-mcp/aiosh_mcp/verifier.py`) and TypeScript (`code/aiosh-cli/src/verifier.ts`).
  - Implemented 7-gate verification pipeline: schema validation, grant validity & bounds, anchor key whitelist verification, Ed25519 signature checks, bounding timestamp verification, archived segment Bloom filter negative evaluations, and live range tail hash verification.
  - Zero database access: verifier runs with 100% mathematical autonomy.
  - Rebuilt TypeScript with zero errors (`npm run build`).
  - Documented implementation in `docs/tasks/evidence/T-02875-implementation.md` and pointer artifact.
- **Files Touched**:
  - `code/aiosh-mcp/aiosh_mcp/verifier.py` (updated)
  - `code/aiosh-cli/src/verifier.ts` (updated)
  - `docs/tasks/evidence/T-02875-implementation.md` (created)
  - `docs/tasks/evidence/T-02875-standalone-proof-verifier-implementation.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02876: Standalone Proof Verifier — Unit Test
- **Task ID**: `T-02876`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / standalone proof verifier
- **Agent**: Antigravity System
- **Summary**:
  - Implemented unit test suite `code/aiosh-mcp/tests/test_por_verifier.py` (11 test cases).
  - Validated all 7 gates: valid proof acceptance, schema validation, unredeemed & single-use checks, timestamp and window bounds, anchor public key whitelisting, Ed25519 signature verification, Bloom filter negative evaluation, and live chain continuity.
  - Certified zero database interactions during verification.
  - All 11 tests passed in 0.38s.
  - Documented evidence in `docs/tasks/evidence/T-02876-unit-test.md` and pointer artifact.
- **Files Touched**:
  - `code/aiosh-mcp/tests/test_por_verifier.py` (created)
  - `docs/tasks/evidence/T-02876-unit-test.md` (created)
  - `docs/tasks/evidence/T-02876-standalone-proof-verifier-unit-test.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02877: Standalone Proof Verifier — Integration
- **Task ID**: `T-02877`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / standalone proof verifier
- **Agent**: Antigravity System
- **Summary**:
  - Registered `aios_restraint_verify` MCP tool in `code/aiosh-mcp/aiosh_mcp/server.py`.
  - Added `aiosh prove verify` subcommand in `code/aiosh-cli/src/cli.ts` supporting `--proof` and `--pubkey`.
  - Rebuilt TypeScript distribution cleanly (`npm run build`).
  - Authored and verified integration test suite `code/aiosh-mcp/tests/test_por_verifier_integration.py` (3 tests passed).
  - Confirmed end-to-end integration across proof generation, standalone verification, MCP remote calls, and anti-forgery rejection.
- **Files Touched**:
  - `code/aiosh-mcp/aiosh_mcp/server.py` (updated)
  - `code/aiosh-cli/src/cli.ts` (updated)
  - `code/aiosh-mcp/tests/test_por_verifier_integration.py` (created)
  - `docs/tasks/evidence/T-02877-integration.md` (created)
  - `docs/tasks/evidence/T-02877-standalone-proof-verifier-integration.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
### 2026-10-07 — T-02878: Standalone Proof Verifier — Security Review
- **Task ID**: `T-02878`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / standalone proof verifier
- **Agent**: Antigravity System
- **Summary**:
  - Conducted comprehensive threat modeling and vulnerability assessment of Standalone Proof Verifier across Python and TypeScript implementations.
  - Audited 6 threat vectors: untrusted public key injection, signature malleability/forgery, unbounded window/narrow anchor truncation, re-chaining/live range disconnect, JSON memory exhaustion DoS, and non-normalized ISO-8601 timestamp evasion.
  - Verified Invariants I-1, I-2, I-3, and I-4: verified zero database operations, zero network reliance, and strict Ed25519 cryptographic checking.
  - Formulated hardening recommendations for T-02879 (strict payload size limit, ISO-8601 UTC timestamp validation, and array dimension caps).
  - Documented evidence in `docs/tasks/evidence/T-02878-security.md` and pointer artifact.
- **Files Touched**:
  - `docs/tasks/evidence/T-02878-security.md` (created)
  - `docs/tasks/evidence/T-02878-standalone-proof-verifier-security-review.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02879 (`standalone proof verifier: Hardening`).













### 2026-10-07 — T-02879: Standalone Proof Verifier — Hardening
- **Task ID**: `T-02879`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / standalone proof verifier
- **Summary**:
  - Closed security-review findings TV-POR-05 (JSON bomb / memory exhaustion DoS) and TV-POR-06 (non-normalized ISO-8601 timestamp evasion) from T-02878.
  - Enforced 20 MiB payload cap on proof files and raw JSON strings, `MAX_SEGMENTS_COUNT` (10 000) / `MAX_LIVE_HASHES_COUNT` (100 000) collection caps (`PROOF_TOO_COMPLEX`), and Bloom parameter bounds (`bloom_m_bits` ≤ 16M bits and multiple of 8, `bloom_k` ∈ [1, 64], strict hex with exact length — `BLOOM_INVALID`).
  - Replaced all lexicographic timestamp comparisons with strict ISO-8601 UTC instant parsing (`_parse_iso8601_utc` / `parseIso8601Utc`) across window, grant, and anchor fields (`TIMESTAMP_INVALID` on failure).
  - Added structural type guards for `grant`/`window`/`anchors`/`live_range`/`segments_checked` and `grant_id` string validation (`MAX_FIELD_STR_LEN`).
  - Full Python/TypeScript substrate parity (`aiosh_mcp/verifier.py`, `cli/src/verifier.ts`); zero `tsc` errors.
  - Added 11 `test_hardened_*` unit tests; full PoR battery green (38 passed, 1 skipped; CLI-side 4 passed).
- **Files Touched**:
  - `code/aiosh-mcp/aiosh_mcp/verifier.py` (hardened)
  - `code/aiosh-cli/src/verifier.ts` (hardened)
  - `code/aiosh-mcp/tests/test_por_verifier.py` (11 hardening tests added)
  - `docs/tasks/evidence/T-02879-hardening.md` (created)
  - `docs/tasks/evidence/T-02879-standalone-proof-verifier-hardening.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02880 (`standalone proof verifier: Documentation`).

### 2026-10-07 — T-02880: Standalone Proof Verifier — Documentation
- **Task ID**: `T-02880`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / standalone proof verifier
- **Summary**:
  - Authored `docs/SPEC-RESTRAINT-PROOF-VERIFIER.md`: zero-trust architectural role, 7-gate verification pipeline (CHECK_SCHEMA .. CHECK_LIVE_CHAIN), `VerificationResult` schema, and formal acceptance condition.
  - Documented the T-02879 hardening bounds table (20 MiB payload cap, collection caps, Bloom parameter bounds, strict hex decode, ISO-8601 UTC instant comparison).
  - Documented the complete interface surface: Python `verify_restraint_proof`, standalone `python -m aiosh_mcp.verifier`, TypeScript `verifyRestraintProof`, MCP tool `aios.restraint.verify`, and CLI `aiosh prove verify` with `AIOSH_ANCHOR_PUBKEY` fallback.
  - Authored the 16-code error catalog with operator remediation guidance and the fail-closed trust model (Invariants I-4).
  - Verified documentation accuracy against both Python and TypeScript implementations and live test expectations.
- **Files Touched**:
  - `docs/SPEC-RESTRAINT-PROOF-VERIFIER.md` (created)
  - `docs/tasks/evidence/T-02880-doc.md` (created)
  - `docs/tasks/evidence/T-02880-standalone-proof-verifier-documentation.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02881 (`standalone proof verifier: Verification & Evidence`).

### 2026-10-07 — T-02881: Standalone Proof Verifier — Verification & Evidence (Component 5 Closeout)
- **Task ID**: `T-02881`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / standalone proof verifier
- **Summary**:
  - Component 5 (T-02872..T-02881) lifecycle complete: Research -> Specification -> Scaffold -> Implementation -> Unit Test -> Integration -> Security Review -> Hardening -> Documentation -> Verification & Evidence.
  - Verification matrix: Python core 22/22, integration 3/3, CLI-side 4/4, `tsc` 0 errors, full PoR battery 38 passed / 1 skipped — no regressions.
  - Certified zero-database Invariant I-4 (no `sqlite3` on the verify path) and fail-closed gate semantics.
  - Evidence recorded in `docs/tasks/evidence/T-02881-verify.md` with full test telemetry.
- **Files Touched**:
  - `docs/tasks/evidence/T-02881-verify.md` (created)
  - `docs/tasks/evidence/T-02881-standalone-proof-verifier-verification-and-evidence.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Component 5 certified complete, hardened, documented, and locked.
  - Advancing to T-02882 (`continuous restraint conformance: Research`).

### 2026-10-07 — T-02882: Continuous Restraint Conformance — Research
- **Task ID**: `T-02882`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / continuous restraint conformance (Component 6)
- **Summary**:
  - Researched the Invariant I-5 Continuous Conformance Gate: a CI-enforced regression oracle for negative attestation.
  - Defined drift model D1..D5 (redeem-gate bypass, mint/redeem parity drift, untouched-grant instability, touched-grant leakage, substrate divergence) with D4 identified as the catastrophic direction.
  - Defined conformance dimensions C1..C6 (non-bypassability, audit parity, restraint stability, invalidation, substrate oracle parity, anchor/chain continuity).
  - Surveyed existing assets (`tools/ci_suites.py` registry, `test_ledger_matrix_smoke.py` M1..M6, mint/redeem tests, PoR batteries); identified the standing-gate gap: no suite re-executes mint -> anchor -> prove -> verify per CI run.
  - Blueprinted the harness (`test_por_conformance.py`, `tools/test_por_conformance_suites.py`, CI registration, `CONFORMANCE.md` manifest).
- **Files Touched**:
  - `docs/tasks/evidence/T-02882-research.md` (created)
  - `docs/tasks/evidence/T-02882-continuous-restraint-conformance-research.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02883 (`continuous restraint conformance: Specification`).

### 2026-10-07 — T-02883: Continuous Restraint Conformance — Specification
- **Task ID**: `T-02883`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / continuous restraint conformance (Component 6)
- **Summary**:
  - Authored the normative CRCS specification: formal criteria C1..C6 (non-bypassability, mint/redeem parity, untouched-grant stability, touched-grant invalidation, substrate oracle parity, anchor/chain continuity).
  - Defined deterministic scenario fixtures F-UNTOUCHED, F-REDEEMED, F-SPENT-RETRY, F-NO-GRANT, F-PARITY, F-ANCHOR-CADENCE.
  - Specified harness interface (`test_por_conformance.py`, `tools/test_por_conformance_suites.py`), CI registration contract (`tools/ci_suites.py`, `ci_service.py check`), and the `CONFORMANCE.md` auditor manifest.
  - Locked binding acceptance criteria for T-02884..T-02891, including the D4 catastrophic-direction guarantee.
- **Files Touched**:
  - `docs/tasks/evidence/T-02883-spec.md` (created)
  - `docs/tasks/evidence/T-02883-continuous-restraint-conformance-specification.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02884 (`continuous restraint conformance: Scaffold`).

### 2026-10-07 — T-02884: Continuous Restraint Conformance — Scaffold
- **Task ID**: `T-02884`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / continuous restraint conformance (Component 6)
- **Summary**:
  - Scaffolded `code/aiosh-mcp/tests/test_por_conformance.py`: 14 scenario nodes spanning C1..C6 with sandbox fixtures `conform_env` / `anchor_keys`, bodies failing loudly until T-02885.
  - Scaffolded `tools/test_por_conformance_suites.py`: fail-closed criteria battery C1..C6 with per-criterion PASS/FAIL report and `NON-CONFORMANT` exit envelope.
  - Verified scaffold integrity: 14 tests collected cleanly; battery module imports with criteria map C1..C6.
- **Files Touched**:
  - `code/aiosh-mcp/tests/test_por_conformance.py` (created)
  - `tools/test_por_conformance_suites.py` (created)
  - `docs/tasks/evidence/T-02884-scaffold.md` (created)
  - `docs/tasks/evidence/T-02884-continuous-restraint-conformance-scaffold.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02885 (`continuous restraint conformance: Implementation`).

### 2026-10-07 — T-02885: Continuous Restraint Conformance — Implementation
- **Task ID**: `T-02885`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / continuous restraint conformance (Component 6)
- **Summary**:
  - Implemented all 14 CRCS scenario tests: C1 non-bypassability (gate + dispatch surfaces, spent-grant replay, source-scanned tool coverage), C2 mint/redeem parity + canonical JSON, C3 untouched-grant stability, C4 touched-grant invalidation (catastrophic direction), C5 live Python/TypeScript oracle parity, C6 anchor continuity + window bounding.
  - Implemented the fail-closed criteria battery (`tools/test_por_conformance_suites.py`); fixed scaffold path-resolution bug; reports `CONFORMANT: C1..C6 PASS`.
  - C5 runs the real TS substrate (`node dist/cli.js prove verify`) with byte-level canonical parity; C2.2 compares against TS `canonicalJson` via live node invocation.
  - Results: 14/14 conformance tests PASS; full PoR battery 52 passed, 1 skipped (no regressions).
- **Files Touched**:
  - `code/aiosh-mcp/tests/test_por_conformance.py` (implemented)
  - `tools/test_por_conformance_suites.py` (implemented)
  - `docs/tasks/evidence/T-02885-implementation.md` (created)
  - `docs/tasks/evidence/T-02885-continuous-restraint-conformance-implementation.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02886 (`continuous restraint conformance: Unit Test`).

### 2026-10-07 — T-02886: Continuous Restraint Conformance — Unit Test
- **Task ID**: `T-02886`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / continuous restraint conformance (Component 6)
- **Summary**:
  - Authored `test_por_conformance_meta.py` (M1..M6): battery criteria completeness, node-id resolution, no-orphan enforcement, fail-closed runner behavior, sandbox isolation + env restore, and T-02883 contract fixture identifiers.
  - Refactored `conform_env` into a `_make_env()` factory + fixture wrapper for unit-testable sandbox lifecycle.
  - Results: 20/20 (6 meta + 14 conformance) PASS.
- **Files Touched**:
  - `code/aiosh-mcp/tests/test_por_conformance_meta.py` (created)
  - `code/aiosh-mcp/tests/test_por_conformance.py` (fixture refactor)
  - `docs/tasks/evidence/T-02886-unit-test.md` (created)
  - `docs/tasks/evidence/T-02886-continuous-restraint-conformance-unit-test.md` (created)
  - `docs/proof-of-restraint/LOG.md` (updated)
- **Status / Next Steps**:
  - Advancing to T-02887 (`continuous restraint conformance: Integration`).


## T-02887 - continuous restraint conformance: Integration (2026-10-08)
- Registered `por_conformance` in `tools/ci_suites.py` (index 29, 30 suites total) with command `python3 tools/test_por_conformance_suites.py`.
- Fixed `tools/ci_run.py` `_effective_command` to resolve bare `bash` via `$AIOSH_BASH` or a PATH-only lookup, bypassing the Windows System32 WSL shadow that killed every bash suite on this host.
- Verified: registry schema validates; `tools/test_por_conformance_suites.py` -> `CONFORMANT: C1..C6 PASS` (exit 0); two full orchestrator runs wrote schema-valid summary artifacts. Both runs stopped at pre-existing `rust_smoke` defects (flaky cargo tests; stale wire-contract assertion 13 vs 205 tools) before reaching suite 30 - follow-up work.
- Evidence: docs/tasks/evidence/T-02887-*.md

## T-02888 - continuous restraint conformance: Security Review (2026-10-08)
- Reviewed CRCS (test_por_conformance.py, test_por_conformance_suites.py, ci_suites.py, ci_run.py bash fix) against 7 threat vectors TV-CRC-01..07.
- Verdict: no runtime policy bypass; PEP gating + audit emission verified by C1/C2. Findings for hardening (T-02889): PATH-interpreter validation, skip-transparent fail-closed runner, concurrency-safe AIOSH_HOME sandbox, temp-tree hygiene.
- Evidence: docs/tasks/evidence/T-02888-*.md

## T-02889 - continuous restraint conformance: Hardening (2026-10-08)
- Closed TV-CRC-01 (interpreter resolution validation, AIOSH_NODE/AIOSH_BASH overrides, world-writable rejection), TV-CRC-05 (skip-transparent fail-closed runner + AIOSH_CONFORMANCE_STRICT), TV-CRC-04 (monkeypatch-based AIOSH_HOME sandbox), TV-CRC-07 (temp-root atexit hygiene; fixed real sqlite3 connection leak that blocked sandbox removal on Windows).
- Bounded external processes (900s criteria, 120s CLI verify, 60s node oracle; hangs fail loudly). Verified: 24 tests green, CONFORMANT C1..C6 in both modes, PoR suite 77 passed / 1 skipped.
- Evidence: docs/tasks/evidence/T-02889-*.md

## T-02890 - continuous restraint conformance: Documentation (2026-10-08)
- Created docs/SPEC-RESTRAINT-CONFORMANCE-GATE.md (SPEC-RESTRAINT-CONFORMANCE-GATE-v1): components, C1..C6 criteria, copy-pasteable invocation, env vars (AIOSH_CONFORMANCE_STRICT/AIOSH_BASH/AIOSH_NODE), hardening properties, honest constraints, evidence links T-02882..T-02891.
- Evidence: docs/tasks/evidence/T-02890-*.md

## T-02891 - continuous restraint conformance: Verification & Evidence (2026-10-08)
- Component 6 (I-5) closeout, series T-02882..T-02891. Fresh verification: PoR battery 77 passed / 1 skipped; CONFORMANT C1..C6 PASS in strict + default modes (zero skips); CI registry valid (30 suites). Residual risks recorded (rust_smoke pre-existing defects, POSIX-only interpreter checks, C5 dist/node dependency).
- Evidence: docs/tasks/evidence/T-02891-*.md

## T-02892 - Proof of Restraint: milestone close & live demo (2026-10-08) [FINAL - MILESTONE SHIPPED]
- Live demo (tools/demo_por.py): mint -> anchor -> prove -> verify PASS (7/7 checks, standalone CLI exit 0); tamper (delete row + re-chain) REJECTED with HEAD_HASH_MISMATCH (CLI exit 1). Transcript: docs/tasks/evidence/T-02892-demo.md.
- Updated GOALS.md (What is already done), task_plan.md (milestone entry), PLAN.md (status -> 'Shipped - maintained by standing rules', new §8 Demo + Change Log row).
- Proof of Restraint (ADR-0037, I-1..I-5) is SHIPPED; maintained by standing rules (PLAN.md §6) and the por_conformance CI gate.

## T-02893 - Compliance Mapping / MCP-API surface: Research (2026-10-08)
- Collected facts (MCP spec 2025-06-18 / 2026-07-28, JSON-RPC 2.0, Python SDK 1.29.1; repo: _recorded_call envelope, PEP gating, Rust ComplianceService substrate, docs/compliance_map.json store, aiosh compliance CLI). 4 assumptions flagged, 8 decisions queued for spec. No code changed.
- Evidence: docs/tasks/evidence/T-02893-*.md
