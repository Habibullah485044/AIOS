# Security Review: Compliance Mapping Documentation (T-02949)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Documentation
- **Task ID**: `T-02949`
- **Scope**: Rust `compliance_doc.rs`, Python `compliance_doc.py`, MCP `aios.compliance(action in {"doc-list", "doc-get", "doc-search"})`

---

## 1. Executive Summary

A formal security audit was conducted for the Compliance Mapping Documentation subsystem. The review examined input sanitization, potential path traversal (CWE-22), denial-of-service and algorithmic complexity risks (CWE-400), terminal log injection (CWE-117), authorization bypasses (CWE-862), and Proof-of-Restraint invariant `I-2`.

Zero policy bypasses, information disclosure vulnerabilities, or uncontrolled resource consumption risks were identified.

---

## 2. Threat & Abuse Scenarios (AS-COMPDOC-01 .. AS-COMPDOC-06)

### AS-COMPDOC-01: Path Traversal via Topic Identifier (CWE-22)
- **Attack Vector**: Attacker provides relative path traversal sequences (e.g. `../../etc/passwd`, `C:\Windows\System32`) to read arbitrary files from the filesystem.
- **Defense**: `validate_topic_id` rejects any identifier containing `..`, `/`, `\`, null bytes (`\0`), or control characters. Furthermore, `ComplianceDocRepository` operates purely on an in-memory compile-time seeded catalog without issuing filesystem I/O operations.
- **Status**: VERIFIED & MITIGATED.

### AS-COMPDOC-02: Algorithmic Complexity & Long Query DoS (CWE-400)
- **Attack Vector**: Attacker provides megabyte-scale query strings to `search` to induce excessive regex or string matching latency and memory exhaustion.
- **Defense**: Strict query length ceiling `MAX_COMPLIANCE_DOC_QUERY_LEN = 128` characters. Queries exceeding 128 characters or containing solely whitespace are rejected with `COMPLYDOC_ERR_QUERY_BOUNDS`.
- **Status**: VERIFIED & MITIGATED.

### AS-COMPDOC-03: Result Flooding & Memory Exhaustion (CWE-400)
- **Attack Vector**: Submitting generic queries that match all documentation topics to exhaust client memory buffers.
- **Defense**: Results are hard-capped at `MAX_COMPLIANCE_DOC_SEARCH_RESULTS = 10` items. Snippets are truncated to `MAX_COMPLIANCE_DOC_SNIPPET_LEN = 200` characters.
- **Status**: VERIFIED & MITIGATED.

### AS-COMPDOC-04: Terminal Poisoning & Log Injection (CWE-117)
- **Attack Vector**: Injected ANSI escape codes, null bytes, or carriage return/newline combinations (`\r\n`) to forge log rows or disrupt terminal screens.
- **Defense**: `sanitize_doc_query` strips all control characters (`c.is_control()`). `validate_topic_id` rejects any control characters in topic IDs.
- **Status**: VERIFIED & MITIGATED.

### AS-COMPDOC-05: Unauthorized State Mutation (CWE-862)
- **Attack Vector**: Invoking documentation actions to trigger implicit updates, state modifications, or store overwrites.
- **Defense**: Documentation lookup is strictly read-only, taking immutable `&self` references on repositories. No storage writes or mutations occur.
- **Status**: VERIFIED & MITIGATED.

### AS-COMPDOC-06: Proof-of-Restraint (PoR) Invariant I-2 Compliance
- **Requirement**: Mutating paths require capability grants; read-only paths must not permit side-effects.
- **Assessment**: `doc-list`, `doc-get`, and `doc-search` are strictly registered in `READ_ACTIONS`. They require no capability grants, emit honest audit rows through `_recorded_call`, and never modify the underlying compliance catalog. Mutating actions (`register`, `status`, `init`) remain strictly guarded in `WRITE_ACTIONS`.
- **Status**: CERTIFIED CONFORMANT (Invariant I-2 preserved).

---

## 3. Findings & Recommendations

- All six abuse scenarios are fully mitigated.
- Zero open vulnerabilities or security regressions.
- Subsystem certified for hardening (T-02950).
