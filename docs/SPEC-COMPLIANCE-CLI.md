# Specification: Compliance Mapping CLI Surface (SPEC-COMPLIANCE-CLI)

- **Status**: APPROVED
- **Date**: 2026-10-04
- **Scope**: Command-line interface syntax, argument parsing, exit codes, audit emission, and terminal formatting for `aiosh compliance`.

## 1. Subcommand Grammar

```
aiosh compliance [SUBCOMMAND] [OPTIONS]

SUBCOMMANDS:
  list                List registered compliance mappings
                      Flags:
                        --framework <FW>        Filter by framework (nist, soc2, iso, cis, hipaa, pci)
                        --status <STATUS>       Filter by status (compliant, partially_compliant, non_compliant, not_applicable)
                        --json                  Output in JSON format
                        --path <PATH>           Path to compliance store (default: docs/compliance_map.json)

  show <ID>           Show detailed compliance mapping specification
                      Flags:
                        --json                  Output in JSON format
                        --path <PATH>           Path to compliance store

  register            Register a new compliance mapping
                      Required Flags:
                        --id <ID>               Unique mapping ID (e.g. MAP-NIST-AC3)
                        --control <CTRL>        Control identifier (e.g. AC-3)
                        --framework <FW>        Framework name (nist, soc2, etc.)
                        --target-type <TYPE>    Substrate target type (pep_gate, capability_token, audit_ring, etc.)
                        --target-ref <REF>      Target reference string
                        --mitigation <TEXT>     Mitigation summary or justification
                      Optional Flags:
                        --status <STATUS>       Status (default: non_compliant)
                        --threats <T1,T2...>    Comma-separated list of threat IDs
                        --tags <TAG1,TAG2...>   Comma-separated list of tags
                        --path <PATH>           Path to compliance store

  status <ID> <STATUS>
                      Update mapping compliance status
                      Optional Flags:
                        --reason <REASON>       Justification for status change
                        --path <PATH>           Path to compliance store

  assess              Evaluate framework compliance posture
                      Flags:
                        --framework <FW>        Optional framework filter
                        --json                  Output in JSON format
                        --path <PATH>           Path to compliance store

  check-pep <GATE...> Verify PEP gate coverage
                      Flags:
                        --json                  Output in JSON format
                        --path <PATH>           Path to compliance store

  init                Initialize compliance store with canonical baseline
                      Flags:
                        --path <PATH>           Path to compliance store
                        --force                 Overwrite existing store
```

## 2. Invariants & Exit Codes

### 2.1 Exit Codes
- `0`: Success.
- `1`: Domain validation or operational failure (e.g. invalid status transition, ID already exists, entry not found).
- `2`: Syntax, argument error, or path hygiene rejection (`COMPLIANCESVC_ERR_PATH_TRAVERSAL`).
- `3`: Storage, deserialization, or I/O error (`COMPLIANCESVC_ERR_IO`, `COMPLIANCESVC_ERR_PARSE`).

### 2.2 Invariants
- `COMPLYCLI1` (**Audit Completeness**): Every invocation logs an audit record to the SQLite audit ring via `classify_and_emit`.
- `COMPLYCLI2` (**Path Traversal Hygiene**): `--path` validated by `ComplianceService::validate_path`.
- `COMPLYCLI3` (**Terminal Sanitization**): Dynamic strings sanitized against ANSI control characters.
- `COMPLYCLI4` (**Zero Secret Disclosure**): Credentials and private key material scrubbed from outputs.
- `COMPLYCLI5` (**Atomic Persistence**): State mutations write atomically using temp files.
