# Specification Evidence: AI Control Plane MCP Server Core Documentation (T-03144)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / documentation
- **Artifact**: `docs/tasks/evidence/T-03144-documentation-specification.md`
- **Specification Document**: [docs/SPEC-MCP-SERVER-CORE-DOC.md](../../SPEC-MCP-SERVER-CORE-DOC.md)

---

## 1. Specification Summary

1. **Contracts Defined**:
   - `McpDocTopic`: Immutable dataclass representing a documentation topic.
   - `McpDocSearchResult`: Lightweight summary envelope for query results.
   - `McpServerCoreDocCatalog`: In-memory registry with keyword search and topic indexing.
2. **Invariants Specified**:
   - `MCPDOC-INV1`: Query string clamped to 128 characters.
   - `MCPDOC-INV2`: Search results clamped to 10 entries.
   - `MCPDOC-INV3`: Topic ID traversal protection (`..`, `/`, `\`, `\0` rejected).
   - `MCPDOC-INV4`: Clean text bodies without unredacted secrets.
   - `MCPDOC-INV5`: Pure read-only operation; zero privilege escalation under PoR Invariant I-2.
3. **Core Topic Catalog**:
   - `core.overview`: Architecture, wire transport, FastMCP integration.
   - `core.api`: JSON-RPC 2.0 framing and standard methods.
   - `core.config`: Configuration keys, hierarchy, and validation.
   - `core.tests`: Automated diagnostic categories and test report schema.
   - `core.policy`: Security policy engine and PoR Invariant I-2 enforcement.
   - `core.observability`: Operational telemetry, health calculations, and sanitization.
