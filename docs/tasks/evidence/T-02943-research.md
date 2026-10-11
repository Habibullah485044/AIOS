# Research Document: Compliance Mapping Documentation (T-02943)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Documentation
- **Task ID**: `T-02943`
- **Focus**: In-Kernel Reference Repository, Framework Mapping Catalog, Topic Index, and Full-Text Search
- **Authoritative Standards & RFCs**:
  - NIST Special Publication 800-53 Revision 5: Security and Privacy Controls for Information Systems
  - ISO/IEC 27001:2022: Information Security Management Systems
  - AICPA 2017 Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy (SOC 2)
  - Center for Internet Security (CIS) Critical Security Controls Version 8
  - AIOS ADR-0035 (Security Architecture) & ADR-0037 (Proof of Restraint)

---

## 1. Executive Summary

The Compliance Mapping Documentation subsystem establishes an offline, air-gapped reference repository and search index for regulatory compliance mapping in AIOS. 

Operators, security auditors, and autonomous agents require local access to regulatory framework taxonomies (NIST, ISO, SOC 2, CIS), lifecycle progression rules, PEP gate mappings, security policy enforcement gates, telemetry metrics, and recovery protocols without relying on external internet connectivity or centralized documentation services.

---

## 2. Invariants & Design Principles

| Invariant | Name | Description |
|:---|:---|:---|
| `COMPLYDOC1` | **Canonical Knowledge Seeding** | Documentation repository is pre-seeded at compile time with canonical reference topics covering all architectural facets of compliance mapping. |
| `COMPLYDOC2` | **Relevance-Scored Search** | Bounded in-memory search ranking matching query tokens against titles (weight 10), summaries (weight 5), and section content (weight 1). |
| `COMPLYDOC3` | **Bounded Resource Consumption (CWE-400)** | Search query length capped at 128 characters (`MAX_COMPLIANCE_DOC_QUERY_LEN`), snippets capped at 200 bytes (`MAX_COMPLIANCE_DOC_SNIPPET_LEN`), search results capped at 10 items (`MAX_COMPLIANCE_DOC_SEARCH_RESULTS`). |
| `COMPLYDOC4` | **Identifier Sanitization (CWE-22, CWE-20)** | Topic IDs checked against strict dot-separated alphanumeric and hyphen syntax, rejecting directory traversal (`..`), path separators (`/`, `\`), and control characters. |
| `COMPLYDOC5` | **Comprehensive Domain Coverage** | Complete documentation across all supported frameworks, lifecycle status rules, PEP coverage gates, security policy gates, observability metrics, and recovery protocols. |

---

## 3. Fact vs. Assumption Separation

### 3.1 Facts
1. **Established Architecture**: Similar documentation repositories exist across AIOS in `threat_model_doc.rs`, `capability_doc.rs`, `pep_doc.rs`, and `audit_chain_doc.rs`.
2. **Current Subsystem Scope**: `ComplianceService`, `ComplianceSecurityPolicy`, and `ComplianceObservabilityReport` are fully implemented in `aiosh-core` and `aiosh-mcp`, but currently lack an in-kernel documentation query index.
3. **Regulatory Scope**: Canonical frameworks supported in `compliance_data_model.rs` are NIST SP 800-53 Rev 5, SOC 2 Type II, ISO 27001:2022, CIS Controls v8, HIPAA Security, and PCI DSS v4.

### 3.2 Assumptions
1. Autonomous agents performing automated compliance assessments benefit from queryable knowledge of control mappings and mitigation criteria.
2. Query validation capped at 128 characters and bounded snippet lengths guarantees sub-millisecond search performance with zero memory inflation risk.

---

## 4. Unknowns & Decisions Needed

- **Decision D1 (Module Organization)**: Implement `code/aiosh-rust/aiosh-core/src/compliance_doc.rs` in Rust and `code/aiosh-mcp/aiosh_mcp/compliance_doc.py` in Python.
- **Decision D2 (Categories Taxonomy)**: Categorize topics into `Architecture`, `Frameworks`, `Lifecycle`, `Service`, `Policy`, `Observability`, `Recovery`.
- **Decision D3 (Canonical Topics)**: Pre-seed 7 core topics:
  1. `compliance.arch.frameworks`: Regulatory standards taxonomy and control mappings.
  2. `compliance.lifecycle.states`: State progression rules, mitigation summary requirements, and transitions.
  3. `compliance.service.api`: Core Service operations, store snapshots, and PEP gate coverage checks.
  4. `compliance.config.ladder`: Four-level configuration ladder and path resolution.
  5. `compliance.policy.gates`: Security policy modes, framework whitelisting, and threshold evaluation.
  6. `compliance.observability.telemetry`: Point-in-time metrics aggregation, distributions, and audit correlation.
  7. `compliance.recovery.backup`: Store backups, corruption recovery, and rollback procedures.
- **Decision D4 (Error Taxonomy)**: Define error codes `COMPLYDOC_ERR_NOT_FOUND` and `COMPLYDOC_ERR_QUERY_BOUNDS`.
- **Decision D5 (MCP Integration)**: Expose documentation querying through `aios.compliance` via actions `doc-list`, `doc-get`, and `doc-search`.

---

## 5. Next Steps
- **T-02944**: Author formal normative specification `docs/SPEC-COMPLIANCE-DOCUMENTATION.md`.
- **T-02945**: Scaffold data structures, repository traits, and test stubs.
