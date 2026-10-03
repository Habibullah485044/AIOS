# Research Document: Threat Model Documentation (T-02781)

- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Documentation
- **Focus**: In-Kernel Documentation Repository, Topic Catalog, and Full-Text Search
- **Bindings**: ADR-0035 §H-1, ADR-0036 §D-1

## 1. Executive Summary
The Threat Model Documentation subsystem provides an offline, self-contained, and air-gapped reference repository and search index for Threat Model Maintenance in AIOS. It enables kernel operators, security auditors, and autonomous agents to query STRIDE definitions, lifecycle state machine rules, configuration parameters, security policy gates, telemetry schemas, and recovery protocols locally without network dependencies or external documentation servers.

## 2. Invariants & Design Principles

| Invariant | Name | Description |
|:---|:---|:---|
| `THREATDOC1` | **Canonical Knowledge Seeding** | Documentation repository is pre-seeded at compile time with canonical reference topics covering all architectural facets. |
| `THREATDOC2` | **Relevance-Scored Search** | Bounded in-memory search ranking matching query tokens against titles (weight 10), summaries (weight 5), and body text (weight 1). |
| `THREATDOC3` | **Bounded Resource Consumption (CWE-400)** | Search query length capped at 128 characters (`MAX_THREAT_DOC_QUERY_LEN`), snippets capped at 200 bytes, results capped at 10 items. |
| `THREATDOC4` | **Identifier Sanitization (CWE-22, CWE-20)** | Topic IDs checked against strict alphanumeric and hyphen syntax, rejecting directory traversal (`..`), separators (`/`, `\`), and control codes. |
| `THREATDOC5` | **Comprehensive Domain Coverage** | Complete documentation across all 6 STRIDE categories, policy modes, observability metrics, and backup/restore workflows. |

## 3. Canonical Topic Index Plan
1. `threat.arch.stride`: STRIDE Methodology and Baseline Threat Architecture in AIOS.
2. `threat.lifecycle.states`: Threat Entry Data Model, State Machine (`Identified` $\to$ `Resolved`), and Invariants.
3. `threat.service.api`: Core Service Operations, Monotonic Risk Assessment, and Atomic Persistence.
4. `threat.config.env`: Configuration Parameters, Capacity Ceilings, and Environment Overrides.
5. `threat.policy.gates`: Security Policy Rules (`Enforcing`/`Permissive`), CWE Requirements, and Critical Guards.
6. `threat.observability.metrics`: Telemetry Metrics, STRIDE Distributions, and Audit Ring Correlation.
7. `threat.recovery.backup`: Atomic Catalog Backup, Corruption Recovery, and Rollback Procedures.

## 4. MCP Interface Design
- Tool: `aios.threat.doc`
  - `action: "list"`: Enumerate all topic IDs, titles, and categories.
  - `action: "get"`: Retrieve full topic structure and Markdown section contents by topic ID.
  - `action: "search"`: Search topics by query string with ranked snippets.

## 5. Next Steps
- `T-02782`: Specification document `SPEC-THREAT-MODEL-DOCUMENTATION.md`.
- `T-02783`: Scaffold `threat_model_doc.rs` in `aiosh-core`.
