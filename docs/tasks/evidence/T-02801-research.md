# Research Document: Compliance Mapping Data Model (T-02801)

- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Compliance Mapping / data model
- **Focus**: Standards Taxonomy, Framework Primitives, Control Definitions, and Mapping Schemas
- **Bindings**: ADR-0035 §C-1, ADR-0036 §P-2

## 1. Executive Summary
Compliance Mapping provides the formal bridge between the AIOS Security Kernel & PEP Fabric (capabilities, sandbox restrictions, audit ring, threat catalog) and external cybersecurity regulatory/compliance frameworks (NIST SP 800-53 Rev 5, SOC 2 Type II, ISO/IEC 27001:2022, CIS Controls v8, HIPAA, PCI DSS).
This research establishes the formal domain primitives, validation constraints, and serialization requirements for the Compliance Mapping data model (`compliance_data_model.rs`).

## 2. Authoritative Standards & Prior Art

| Framework | Authoritative Source | Primary Control Focus Areas in AIOS |
|:---|:---|:---|
| **NIST SP 800-53 Rev 5** | NIST Special Publication 800-53 | AC (Access Control), AU (Audit & Accountability), IA (Identification & Authentication), SC (System & Communications Protection), SI (System & Information Integrity) |
| **SOC 2 Type II** | AICPA Trust Services Criteria | Common Criteria CC6 (Logical and Physical Access), CC7 (System Operations), CC8 (Change Management) |
| **ISO/IEC 27001:2022** | ISO/IEC Standard | Annex A.5 (Organizational Controls), Annex A.8 (Technological Controls - Access, Logging) |
| **CIS Controls v8** | Center for Internet Security | Control 3 (Data Protection), Control 5 (Account Management), Control 6 (Access Control), Control 8 (Audit Log Management) |
| **HIPAA Security Rule** | 45 CFR Part 164 Subpart C | §164.312 Technical Safeguards (Access Control, Audit Controls, Integrity, Transmission Security) |
| **PCI DSS v4.0** | PCI Security Standards Council | Requirement 7 (Restrict Access), Requirement 8 (Identify Users), Requirement 10 (Log and Monitor) |

## 3. Data Model Invariants

- `COMPLY1` (**Canonical Identification**): Frameworks and control identifiers must follow strict alphanumeric, dash, and dot syntax. No control characters, whitespace, or path injection characters permitted.
- `COMPLY2` (**Substrate Binding Integrity**): Each compliance mapping must bind to a recognized AIOS substrate component (PEP gate, capability token, threat entry, or constitution rule).
- `COMPLY3` (**Status Provenance**): A status of `Compliant` requires at least one non-empty mitigation reference or enforcement gate.
- `COMPLY4` (**Resource Bounds**): Hard limits on identifiers (<= 64 chars), titles (<= 128 chars), descriptions (<= 2048 chars), tags count (<= 16), and catalog size (<= 1024 entries).
- `COMPLY5` (**Deterministic Canonical Baseline**): Built-in baseline mappings must exist out of the box for core PEP gates to NIST SP 800-53 and SOC 2.

## 4. Unknowns & Architectural Decisions
- **Decision 1**: Enums vs Open Strings for Frameworks: Use a strongly typed enum (`ComplianceFramework`) with `Custom(String)` fallback to permit enterprise extensions while keeping canonical frameworks compile-time verified.
- **Decision 2**: Persistence Format: Canonical JSON snapshots following `ThreatModelSnapshot` pattern (`ComplianceCatalogSnapshot`).
- **Decision 3**: Integration Target: Reusable by PEP policy evaluation, audit reporting, and MCP compliance tools.
