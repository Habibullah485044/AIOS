# T-02911 — Compliance Mapping / configuration: Documentation

**Task ID**: T-02911 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / configuration: Documentation)  
**Depends on**: T-02910 (Hardening — `docs/tasks/evidence/T-02910-configuration-hardening.md`)  
**Contract**: `docs/tasks/evidence/T-02904-spec.md`  
**Date**: 2026-10-10  
**Status**: COMPLETE — Published normative specification and operator guide `docs/SPEC-COMPLIANCE-CONFIG.md`.

---

## 1. Documentation Deliverables

1. **New Specification Document**:
   - [`docs/SPEC-COMPLIANCE-CONFIG.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/SPEC-COMPLIANCE-CONFIG.md)
   - Documents the 4-level precedence ladder (`--path > AIOSH_COMPLIANCE_MAP_PATH > config file > default`).
   - Documents configuration schema, size caps (64 KiB), clamping intervals, and error codes.
   - Provides copy-pasteable CLI and Python MCP usage examples.
   - States limitations and security guarantees.

2. **Linked Evidence Files**:
   - Research: [`docs/tasks/evidence/T-02903-configuration-research.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02903-configuration-research.md)
   - Specification: [`docs/tasks/evidence/T-02904-spec.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02904-spec.md)
   - Scaffold: [`docs/tasks/evidence/T-02905-configuration-scaffold.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02905-configuration-scaffold.md)
   - Implementation: [`docs/tasks/evidence/T-02906-configuration-implementation.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02906-configuration-implementation.md)
   - Unit Tests: [`docs/tasks/evidence/T-02907-configuration-unit-test.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02907-configuration-unit-test.md)
   - Integration: [`docs/tasks/evidence/T-02908-configuration-integration.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02908-configuration-integration.md)
   - Security Review: [`docs/tasks/evidence/T-02909-security.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02909-security.md)
   - Hardening: [`docs/tasks/evidence/T-02910-configuration-hardening.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02910-configuration-hardening.md)

---

## 2. Acceptance Criteria Check

- [x] Docs updated with working example — included CLI and Python usage in `SPEC-COMPLIANCE-CONFIG.md`.
- [x] Limitations are stated, not omitted — UTF-8 JSON only, local filesystem only, no remote URLs.
