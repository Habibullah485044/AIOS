# Documentation: Chain Anchoring & Completeness Checkpoints (T-02860)

**Task**: `T-02860` — Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / chain anchoring & completeness checkpoints: Documentation  
**Date**: 2026-10-07  
**Author**: Antigravity System  
**Status**: Documented  

---

## 1. Documentation Artifacts Shipped

1. **`docs/SPEC-CHAIN-ANCHORING.md`**:
   - Comprehensive technical reference for Component 3 (Chain Anchoring & Completeness Checkpoints).
   - Details threat model, Invariant I-3, canonical serialization format, Ed25519 signing rules, and persistence layout.
   - Provides copy-pasteable CLI commands (`aiosh anchor create`, `aiosh anchor verify`) and FastMCP tool calls (`aios_anchor_create`, `aios_anchor_verify`).
   - Details error codes (`SIGNATURE_INVALID`, `UNTRUSTED_KEY`, `TRUNCATION_DETECTED`, `FORK_DETECTED`).
   - Documents known constraints and links all evidence files from T-02852 through T-02859.
