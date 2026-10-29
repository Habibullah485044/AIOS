# T-03249 Security Review: Model Backend Adapters Documentation Subsystem

## Scope & Target
- Target: `code/aiosh-mcp/aiosh_mcp/model_backend_adapters_doc.py`
- MCP Surface: `aios_model_doc_get`, `aios_model_doc_search`, `aios_model_doc_list`
- Standard: ADR-0035 §D-2, Proof-of-Restraint Invariant I-2, CWE-22, CWE-400

---

## Threat Matrix & Abuse Scenarios

| Scenario ID | Attack Vector | Risk | Mitigation | Status |
|-------------|---------------|------|------------|--------|
| SEC-MODDOC-01 | Directory traversal / LFI via `topic_id` (`../../etc/passwd`, `C:\boot.ini`) | Critical | `validate_topic_id` strictly blocks traversal tokens (`..`, `/`, `\`, `\0`) and enforces `^[a-zA-Z0-9_\-\.]{1,64}$`. Catalog is 100% in-memory with 0 disk I/O. | Mitigated |
| SEC-MODDOC-02 | Resource Exhaustion (DoS) via unbounded search queries | Medium | `sanitize_doc_query` clamps query length to 128 characters. `limit` parameter clamped to max 10. | Mitigated |
| SEC-MODDOC-03 | Terminal injection & Bidi spoofing | Low | Strips ASCII control codes (<32, 127-159) and invisible/Bidi codepoints (`\u200b`, `\ufeff`, `\u202a`–`\u202e`, `\u2060`–`\u2069`). | Mitigated |
| SEC-MODDOC-04 | State mutation of catalog topics | Medium | `ModelAdapterDocTopic` is an immutable frozen dataclass. No state-mutating endpoints exposed. | Mitigated |
| SEC-MODDOC-05 | Token expenditure bypass (PoR Invariant I-2) | High | All documentation queries operate strictly in-memory without external model calls, consuming 0 tokens. | Verified |

---

## Proof-of-Restraint (PoR) Verification (Invariant I-2)
- State-changing paths: None added. Documentation is purely read-only.
- Token consumption: Verified 0 capability tokens expended.
- Gating: No state changes occur; capability token redemption is therefore not triggered. Pure read queries remain free from token overhead.

---

## Conclusion
The security review found no open vulnerabilities or policy bypasses. The documentation subsystem meets all security and PoR invariants.
