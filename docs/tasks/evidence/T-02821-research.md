# Research Document: Compliance Mapping CLI Surface (T-02821)

- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Compliance Mapping / CLI surface
- **Focus**: Command Grammar, Flags, Exit Codes, Output Formatting, and Audit Ring Emission
- **Bindings**: ADR-0036 §B-1, ADR-0035 §C-2

## 1. Executive Summary
The `aiosh compliance` command line interface exposes administrative, auditing, and operational commands for querying, registering, updating, and assessing regulatory compliance mappings in AIOS. This research evaluates the command grammar, exit codes, audit emission requirements, and terminal output sanitization standards across existing CLI subcommands (e.g., `aiosh threat`, `aiosh audit`, `aiosh grant`).

## 2. CLI Architecture & Grammar

```
aiosh compliance [SUBCOMMAND] [OPTIONS]

SUBCOMMANDS:
  list                List registered compliance mappings
                      Flags:
                        --framework <FW>        Filter by framework (nist, soc2, iso, cis, hipaa, pci)
                        --status <STATUS>       Filter by status (compliant, partially_compliant, non_compliant, not_applicable)
                        --json                  Output in JSON format
                        --path <PATH>           Path to compliance mapping store (default: docs/compliance_map.json)

  show <ID>           Show detailed compliance mapping specification
                      Flags:
                        --json                  Output in JSON format
                        --path <PATH>           Path to compliance store

  register            Register a new compliance mapping
                      Required Flags:
                        --id <ID>               Unique mapping identifier (e.g., MAP-NIST-AC3)
                        --control <CTRL>        Control identifier (e.g., AC-3, CC6.1)
                        --framework <FW>        Target framework
                        --target-type <TYPE>    Substrate target (pep_gate, capability_token, audit_ring, etc.)
                        --target-ref <REF>      Substrate target reference name
                        --mitigation <TEXT>     Mitigation summary or enforcement justification
                      Optional Flags:
                        --status <STATUS>       Status (default: non_compliant)
                        --threats <T1,T2...>    Comma-separated list of threat identifiers
                        --tags <TAG1,TAG2...>   Comma-separated list of tags
                        --path <PATH>           Path to compliance store

  status <ID> <STATUS> [--reason <REASON>]
                      Update mapping compliance status
                      Flags:
                        --path <PATH>           Path to compliance store

  assess              Calculate and display composite compliance evaluation report
                      Flags:
                        --framework <FW>        Optional scoped framework filter
                        --json                  Output assessment report in JSON format
                        --path <PATH>           Path to compliance store

  check-pep <GATE...> Verify PEP gate compliance coverage
                      Flags:
                        --json                  Output in JSON format
                        --path <PATH>           Path to compliance store

  init                Initialize compliance store with canonical standard baseline
                      Flags:
                        --path <PATH>           Path to compliance store
                        --force                 Overwrite existing store
```

## 3. Invariants & Rulesets

| Invariant | Name | Description |
|:---|:---|:---|
| `COMPLYCLI1` | **Audit Completeness** | Every invocation of `aiosh compliance` writes exactly one row into the audit ring via `classify_and_emit`. |
| `COMPLYCLI2` | **Path Traversal Hygiene** | Custom `--path` flags checked via `ComplianceService::validate_path` (CWE-22, CWE-59 rejection). |
| `COMPLYCLI3` | **Standardized Exit Codes** | `0` = Success, `1` = Domain validation failure, `2` = Usage syntax error, `3` = Storage / I/O error. |
| `COMPLYCLI4` | **Terminal Sanitization** | Dynamic output fields are sanitized with `sanitize_terminal` (CWE-150 / CWE-116). |
| `COMPLYCLI5` | **Zero Secret Disclosure** | Token patterns and credentials scrubbed from outputs. |

## 4. Unknowns & Decisions Needed
- **Decision 1**: Integrate into `code/aiosh-rust/aiosh-cli/src/main.rs` directly as `cmd_compliance`, adhering to the single-binary userspace pattern established in Phase 2.
- **Decision 2**: Aliases: register `compliance` and alias `comp`.
