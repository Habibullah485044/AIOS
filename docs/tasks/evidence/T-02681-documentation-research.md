# T-02681: Secrets Handling Documentation Research

- **Task**: `T-02681`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Secrets Handling / documentation
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Research Objectives
Establish facts, constraints, and prior art for the embedded reference documentation and search subsystem of Secrets Handling (`code/aiosh-rust/aiosh-core/src/secret_doc.rs`).

## 2. Established Architectural Facts & Prior Art
1. **Self-Contained Offline Knowledge Base**:
   - Following AIOS standards established in `privilege_doc.rs`, `pep_doc.rs`, and `sandbox_doc.rs`, the documentation subsystem must be self-contained and compile directly into `aiosh-core`.
   - Operators and autonomous agents operating in air-gapped or network-isolated sandboxes must be able to discover usage guidelines, error recovery strategies, and security policies without external network calls.
2. **Deterministic Search Engine**:
   - Query length bounded by `MAX_SECRET_DOC_QUERY_LEN = 128`.
   - Results capped by `MAX_SECRET_DOC_SEARCH_RESULTS = 10`.
   - Snippet lengths capped by `MAX_SECRET_DOC_SNIPPET_LEN = 200`.
   - Simple keyword and multi-term scoring ranking topic titles, summaries, and section contents.
3. **Topic Taxonomy**:
   - Six canonical categories: `Architecture`, `Lifecycle`, `Policy`, `Observability`, `Security`, `Recovery`.
   - Standard error codes: `SECDOC_ERR_NOT_FOUND` ("SECDOC_ERR_NOT_FOUND") and `SECDOC_ERR_QUERY_BOUNDS` ("SECDOC_ERR_QUERY_BOUNDS").

## 3. Decisions Needed for Specification (T-02682)
1. **Contract Document**: Specify `docs/SPEC-SECRETS-DOCUMENTATION.md` detailing topic schemas, error handling, scoring algorithms, and CLI/MCP interfaces.
2. **Topic Corpus**: Pre-seed the repository with authoritative topics:
   - `secrets-overview` (Vault architecture and zero-disclosure rules)
   - `secrets-lifecycle` (Registration, retrieval, masking, rotation, and revocation)
   - `secrets-policy` (Tri-state security policy, payload caps, and prohibited kinds)
   - `secrets-observability` (Telemetry aggregation, distribution maps, and metrics)
   - `secrets-security` (Threat model, CWE protections, and memory safety)
   - `secrets-recovery` (Vault validation, corruption repairs, and atomic persistence)
3. **Scaffold Target**: `code/aiosh-rust/aiosh-core/src/secret_doc.rs` registered in `lib.rs`.
