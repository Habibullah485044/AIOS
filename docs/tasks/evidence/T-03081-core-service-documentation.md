# Documentation Evidence: AI Control Plane MCP Server Core Service (T-03081)

**Task ID**: T-03081 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / core service: Documentation)  
**Contract Reference**: `docs/tasks/evidence/T-03074-spec.md`, `docs/SPEC-MCP-SERVER-CORE-SERVICE.md`  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: APPROVED — Technical specification document `docs/SPEC-MCP-SERVER-CORE-SERVICE.md` created with working copy-pasteable examples, error taxonomy, sizing boundaries, and invariant definitions.

---

## 1. Documentation Deliverables

- **Specification Document**: `docs/SPEC-MCP-SERVER-CORE-SERVICE.md`
  - Formal definition of `McpServerCoreService` architecture across Rust (`aiosh-core`) and Python (`aiosh-mcp`).
  - Catalog invariants (`MCPSVC-INV1..MCPSVC-INV5`), sizing boundaries (64 sessions, 256 tools), and complete error code taxonomy.
  - Working Rust and Python copy-pasteable snippets for registration, session management, timeout-bounded safe dispatch, and session pruning.
  - Integration mapping with FastMCP production server (`aios_mcp_core_list_tools`, `aios_mcp_core_dispatch`).

---

## 2. Upstream Task Evidence Links

- **T-03073 (Research)**: `docs/tasks/evidence/T-03073-core-service-research.md`
- **T-03074 (Specification)**: `docs/tasks/evidence/T-03074-core-service-specification.md`
- **T-03075 (Scaffold)**: `docs/tasks/evidence/T-03075-core-service-scaffold.md`
- **T-03076 (Implementation)**: `docs/tasks/evidence/T-03076-core-service-implementation.md`
- **T-03077 (Unit Test)**: `docs/tasks/evidence/T-03077-core-service-unit-test.md`
- **T-03078 (Integration)**: `docs/tasks/evidence/T-03078-core-service-integration.md`
- **T-03079 (Security Review)**: `docs/tasks/evidence/T-03079-core-service-security-review.md`
- **T-03080 (Hardening)**: `docs/tasks/evidence/T-03080-core-service-hardening.md`
