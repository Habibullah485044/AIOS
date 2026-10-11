# Hardening Evidence: Compliance Mapping Documentation (T-02950)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Documentation
- **Task ID**: `T-02950`
- **Specification**: `docs/SPEC-COMPLIANCE-DOCUMENTATION.md`
- **Files Modified / Implemented**:
  - `code/aiosh-rust/aiosh-core/src/compliance_doc.rs`: Added bidirectional text and invisible Unicode filtering (`is_bidi_or_invisible`); hardened topic ID boundary validator rejecting leading/trailing dots/hyphens and non-permitted characters.
  - `code/aiosh-mcp/aiosh_mcp/compliance_doc.py`: Added parity bidi/invisible filtering and boundary validation in Python.
  - `code/aiosh-rust/aiosh-core/tests/test_compliance_doc_hardening.rs`: Hardening verification test suite in Rust.
  - `code/aiosh-mcp/tests/test_compliance_doc_hardening.py`: Hardening verification test suite in Python.

## 1. Hardened Defenses

### 1.1 Bidi & Invisible Character Sanitization
- Strips bidirectional text override characters (`\u{202A}`..`\u{202E}`), invisible formatting codepoints (`\u{2060}`..`\u{2069}`), zero-width characters (`\u{200B}`..`\u{200F}`), and byte-order marks (`\u{FEFF}`) to prevent terminal spoofing and search confusion attacks.

### 1.2 Topic Identifier Boundary Rules
- Enforces strict character allowlist (`[a-zA-Z0-9._-]`).
- Prohibits identifiers starting or ending with dots (`.`) or hyphens (`-`).
- Rejects paths containing forbidden special characters (`$`, `@`, spaces, control codes).

### 1.3 Empty Sanitized Query Defense
- Validates that queries composed entirely of stripped invisible/control codepoints correctly collapse to empty queries and trigger `COMPLYDOC_ERR_QUERY_BOUNDS` instead of executing wasteful full-scan searches.

## 2. Test Execution
- `cargo test --test test_compliance_doc_hardening`: PASS (3/3 passed)
- `python -m pytest code/aiosh-mcp/tests/test_compliance_doc_hardening.py`: PASS (3/3 passed)
