# Documentation Evidence: Compliance Mapping Documentation (T-02951)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Documentation
- **Task ID**: `T-02951`
- **Normative Specification**: `docs/SPEC-COMPLIANCE-DOCUMENTATION.md`
- **Files Modified / Updated**:
  - `docs/SPEC-COMPLIANCE-DOCUMENTATION.md`: Updated status to `IMPLEMENTED & VERIFIED`. Documented architecture, canonical taxonomy, query bounds, relevance scoring rules, security invariants (COMPLYDOC1..COMPLYDOC5), MCP tool actions (`doc-list`, `doc-get`, `doc-search`), and hardening controls.
  - Test references linked to both Rust (`aiosh-core`) and Python (`aiosh_mcp`) test suites.

## 1. Documented Specifications & Contracts

### 1.1 Canonical Categories & Topics
- Canonical taxonomy: Architecture, Frameworks, Lifecycle, Service, Policy, Observability, and Recovery.
- Documented all 7 canonical topics with exact IDs, summaries, and section layouts.

### 1.2 Relevance Scoring & Determinism
- Documented deterministic relevance score calculation (+50 exact ID, +25 title, +15 summary, +5 section title, +2 section content).
- Documented bounding guarantees: max 128 characters query length, max 10 results, max 200 characters snippet length.

### 1.3 Security & PoR Guarantees
- Documented Proof-of-Restraint invariant `I-2`: doc actions are read-only, mutating zero system state, requiring no capability token grants, while preserving honest audit log accountability via `_recorded_call`.

## 2. Verification
- `tools/check_evidence.py`: Validated and verified.
