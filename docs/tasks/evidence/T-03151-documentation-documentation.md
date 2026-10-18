# Documentation Evidence: AI Control Plane MCP Server Core Documentation (T-03151)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / documentation
- **Artifact**: `docs/tasks/evidence/T-03151-documentation-documentation.md`
- **Documentation Updated**: [code/aiosh-mcp/README.md](../../code/aiosh-mcp/README.md)

---

## 1. Documentation Updates Summary

1. **Architecture & Scope**:
   - Documented the self-contained reference repository and topic search index for MCP Server Core.
   - Clarified zero-dependency operation, schema discovery, and immunity to traversal attacks.
2. **Tool Invocations & Working Examples**:
   - `aios_mcp_doc_lookup`: Copy-pasteable JSON-RPC 2.0 requests and response structures for:
     - Listing all canonical topics
     - Retrieving specific topic details (`core.policy`)
     - Keyword search (`"fastmcp"`)
3. **Constraints & Known Limitations**:
   - Search query length clamped to 128 characters.
   - Search results clamped to 10 matches.
   - Topic ID syntax and traversal rejection (`..`, `/`, `\`, `\0`).
   - Unicode NFKC normalization and homoglyph protection.
   - Catalog capacity cap of 256 topics (`MAX_TOPICS_LIMIT = 256`).
   - Error messages sanitized with path redaction (`[REDACTED_PATH]`).
   - Pure read-only operation under PoR Invariant I-2.
4. **Lifecycle & Traceability Links**:
   - Linked specification (`SPEC-MCP-SERVER-CORE-DOC`) and task evidence files (`T-03143` through `T-03151`).
