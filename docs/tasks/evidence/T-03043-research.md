# Research Document: Incident Response Runbooks Documentation (T-03043)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / Documentation
- **Task ID**: `T-03043`
- **Focus**: In-Kernel Reference Repository, Runbook Playbook Catalog, Topic Index, and Full-Text Search
- **Authoritative Standards & RFCs**:
  - NIST Special Publication 800-61 Revision 2: Computer Security Incident Handling Guide
  - CISA Federal Government Cybersecurity Incident and Vulnerability Response Playbooks (Nov 2021)
  - MITRE ATT&CK for Enterprise (Incident Response & Mitigation Matrices)
  - AIOS ADR-0035 (Security Architecture) & ADR-0037 (Proof of Restraint)

---

## 1. Executive Summary

The Incident Response Runbooks Documentation subsystem establishes an offline, air-gapped reference repository and search index for incident response playbooks, operational security tooling, safety enforcement policies, and telemetry schemas within the AIOS kernel and userland runtime.

Operators, security incident handlers, autonomous agents, and forensic auditors require immediate local access to incident taxonomy, step phase progression rules, containment confirmation gates, RustSec diagnostic scanning capabilities (`net`, `files`, `web`), security policies, and failure recovery protocols without dependency on external network access or central documentation hosts.

---

## 2. Invariants & Design Principles

| Invariant | Name | Description |
|:---|:---|:---|
| `IRDOC1` | **Canonical Knowledge Seeding** | Documentation repository is pre-seeded at compile time with canonical reference topics covering all architectural facets of incident response runbooks and RustSec scanning tools. |
| `IRDOC2` | **Relevance-Scored Search** | Bounded in-memory search ranking matching query tokens against titles (weight 10), summaries (weight 5), and section content (weight 1). |
| `IRDOC3` | **Bounded Resource Consumption (CWE-400)** | Search query length capped at 128 characters (`MAX_RUNBOOK_DOC_QUERY_LEN`), snippets capped at 200 bytes (`MAX_RUNBOOK_DOC_SNIPPET_LEN`), search results capped at 10 items (`MAX_RUNBOOK_DOC_SEARCH_RESULTS`). |
| `IRDOC4` | **Identifier Sanitization (CWE-22, CWE-20)** | Topic IDs checked against strict dot-separated alphanumeric and hyphen syntax, rejecting directory traversal (`..`), path separators (`/`, `\`), control characters, and zero-width/bidirectional unicode overrides (`U+200B..U+200F`, `U+202A..U+202E`, `U+FEFF`). |
| `IRDOC5` | **Comprehensive Domain Coverage** | Complete documentation across all supported incident categories, lifecycle state rules, confirmation gates, scanning substrates, security policy modes, observability telemetry, and recovery protocols. |

---

## 3. Fact vs. Assumption Separation

### 3.1 Facts
1. **Established Architecture**: Proven documentation repository architectures exist in `code/aiosh-rust/aiosh-core/src/compliance_doc.rs`, `threat_model_doc.rs`, `pep_doc.rs`, and `audit_chain_doc.rs`.
2. **Current Subsystem Scope**: The Incident Response Runbooks subsystem includes:
   - Data Model: `incident_runbook_data_model.rs` / `incident_runbook_data_model.py` (categories, phases, step specs).
   - Core Service: `incident_runbook_service.rs` / `incident_runbook_service.py` (session execution, step advancement).
   - CLI Surface: `sec_tools.rs` / `aiosh runbook` / `aiosh scan` (RustSec scanning tools).
   - FastMCP Surface: `incident_runbook_mcp.py` (`aios_runbook`, `aios_scan`).
   - Configuration: `runbook_config.rs` / `runbook_config.py` (4-level precedence ladder).
   - Security Policy: `incident_runbook_policy.rs` / `incident_runbook_policy.py` (enforcing/permissive/disabled).
   - Observability: `incident_runbook_observability.rs` / `incident_runbook_observability.py` (telemetry, ADR-0035 §AF-2).
3. **Canonical Playbooks**: The baseline catalog contains canonical playbooks:
   - `RB-IR-MALWARE-01`: Host Malware & Persistence Containment.
   - `RB-IR-ACCESS-01`: Unauthorized Account Access & Credential Revocation.

### 3.2 Assumptions
1. Autonomous agents triaging live security incidents benefit from queryable in-memory playbook reference data and diagnostic parameter guidelines.
2. Query validation capped at 128 characters and bounded snippet lengths guarantees deterministic sub-millisecond search latency with zero memory leak risk.

---

## 4. Unknowns & Decisions Needed

- **Decision D1 (Module Organization)**:
  - Implement Rust documentation service in `code/aiosh-rust/aiosh-core/src/incident_runbook_doc.rs`.
  - Implement Python documentation service in `code/aiosh-mcp/aiosh_mcp/incident_runbook_doc.py`.
- **Decision D2 (Categories Taxonomy)**:
  - Define `RunbookDocCategory`: `Architecture`, `DataModel`, `Lifecycle`, `SecurityTools`, `Policy`, `Observability`, `Recovery`.
- **Decision D3 (Canonical Topics)**:
  - Pre-seed 7 core reference topics:
    1. `runbook.arch.overview`: Architecture, NIST alignment, dual-gate dispatch.
    2. `runbook.datamodel.specs`: Runbook specification schema, step parameters, targets.
    3. `runbook.lifecycle.execution`: Session advancement, terminal states, confirmation gating.
    4. `runbook.tools.scanning`: RustSec tools (`net`, `files`, `web`) parameter bounds and safety.
    5. `runbook.config.precedence`: 4-level configuration hierarchy and path resolution.
    6. `runbook.policy.governance`: Policy modes, confirmation enforcement, port/depth limits.
    7. `runbook.observability.telemetry`: Point-in-time metrics, ADR-0035 §AF-2 honest audit rows.
- **Decision D4 (Error Taxonomy)**:
  - Error constants: `IRDOC_ERR_NOT_FOUND` and `IRDOC_ERR_QUERY_BOUNDS`.
