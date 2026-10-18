# Security Review Evidence: AI Control Plane MCP Server Core Documentation (T-03149)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / documentation
- **Artifact**: `docs/tasks/evidence/T-03149-documentation-security-review.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MCP-SERVER-CORE-DOC

---

## 1. Threat Modeling & Abuse Scenario Assessment

We evaluated 5 realistic threat vectors against the MCP Server Core Documentation Subsystem:

### Scenario 1: Path Traversal & Arbitrary File Read via Crafted `topic_id` (CWE-22)
- **Attack Vector**: An adversary passes `topic_id="../../etc/shadow"` or `topic_id="..\\Windows\\win.ini"` attempting to escape the memory catalog into the host filesystem.
- **Analysis**:
  - The documentation subsystem operates purely on an in-memory hash map (`_topics: Dict[str, McpDocTopic]`), never touching disk directly upon `get()` calls.
  - `validate_topic_id` checks for `..`, `/`, and `\` before querying the catalog, raising `MCPDOC_ERR_INVALID_ID` fail-closed.
- **Verdict**: **MITIGATED** (Immune by design and input validation).

### Scenario 2: NUL Byte Injection & Truncation (CWE-626)
- **Attack Vector**: Attacker provides `topic_id="core.overview\0secret"` or `query="token\0payload"` attempting C-string termination attacks or bypass.
- **Analysis**:
  - `validate_topic_id` explicitly inspects for `\0` and rejects the request immediately.
  - `sanitize_doc_query` strips codepoints $< 32$, stripping `\0` entirely.
- **Verdict**: **MITIGATED**.

### Scenario 3: Denial-of-Service via Query Flooding & Token Explosion (CWE-400)
- **Attack Vector**: Sending massive search strings ($> 100\text{ KiB}$) or thousands of whitespace tokens to monopolize CPU cycles during search.
- **Analysis**:
  - `MAX_MCP_DOC_QUERY_LEN = 128` strictly limits query string length.
  - `sanitize_doc_query` truncates any query beyond 128 characters prior to tokenization.
  - Search results are capped to `MAX_MCP_DOC_SEARCH_RESULTS = 10`, preventing response ballooning.
- **Verdict**: **MITIGATED**.

### Scenario 4: Topic Catalog Flooding & Memory Exhaustion (CWE-770)
- **Attack Vector**: Unauthenticated callers attempting to dynamically register millions of topics to trigger Out-Of-Memory (OOM).
- **Analysis**:
  - `aios_mcp_doc_lookup` exposes only read-only lookups and searches; registration is strictly internal during server bootstrap.
  - External callers cannot invoke `register()`.
- **Verdict**: **MITIGATED**.

### Scenario 5: Secret Information Leakage in Documentation Bodies (CWE-200)
- **Attack Vector**: Exposure of cryptographic keys, API tokens, or internal credentials inside documentation markdown bodies.
- **Analysis**:
  - Documentation content contains only structural architecture, protocol rules, and sanitize usage examples.
  - All automated unit and security tests assert absence of private keys and credentials.
- **Verdict**: **MITIGATED**.

---

## 2. Proof-of-Restraint Invariant I-2 Audit

- **Verification**: `aios_mcp_doc_lookup` is classified as `READ_ONLY`.
- **Outcome**: Requires no capability token, executes with zero state mutations, and cannot be abused for privilege escalation.
