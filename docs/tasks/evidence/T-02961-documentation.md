# Documentation Evidence: Compliance Mapping Recovery & Validation (T-02961)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Recovery & Validation
- **Task ID**: `T-02961`
- **Documentation Updated**:
  - `docs/SPEC-COMPLIANCE-RECOVERY.md`

## 1. Documentation Enhancements
- Updated status to `IMPLEMENTED & VERIFIED`.
- Included exact Rust structs, enums, error codes, and service method signatures.
- Documented CLI invocation syntax with copy-pasteable examples for `verify`, `backup`, `repair`, and `restore`.
- Documented MCP JSON-RPC call examples, highlighting read-only vs grant-gated mutating actions (PoR Invariant I-2).
- Added explicit section on constraints and limitations (5MB file size cap, local filesystems only, quarantine retention limit of 10).
- Linked all task evidence files from Research (`T-02953`) to Hardening (`T-02960`).
