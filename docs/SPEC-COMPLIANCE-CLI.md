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

## 3. Usage Examples

### 3.1 Initialize Baseline Store
```bash
aiosh compliance init --path /path/to/compliance_map.json
```

### 3.2 List Mappings
```bash
aiosh compliance list --framework nist --status compliant --json
```

### 3.3 Register New Mapping
```bash
aiosh compliance register \
  --id MAP-NIST-AC3-EXEC \
  --control AC-3 \
  --framework nist \
  --target-type pep_gate \
  --target-ref pep_gate_exec \
  --mitigation "Enforces policy before process execution" \
  --status compliant \
  --tags access_control,pep
```

### 3.4 Assess Compliance Posture
```bash
aiosh compliance assess --framework nist --json
```

### 3.5 Check PEP Gate Coverage
```bash
aiosh compliance check-pep pep_gate_exec pep_gate_network --json
```

## 4. Constraints & Known Limitations
1. **Local File Substrate**: Persistence is backed by JSON stores up to 1 MiB (`MAX_COMPLIANCE_STORE_SIZE`); large-scale distributed deployments should synchronize via git or central configuration repositories.
2. **Framework Vocabulary**: Canonical frameworks are restricted to `nist`, `soc2`, `iso`, `cis`, `hipaa`, and `pci`. Custom frameworks require identifier prefixes.
3. **Audit Ring Dependency**: Commands record events via `classify_and_emit` to local SQLite WAL ring. In air-gapped environments without write access to local appdata, audit logs fall back to standard error.

## 5. Evidence & Traceability Links
- `T-02821`: [docs/tasks/evidence/T-02821-cli-surface-research.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02821-cli-surface-research.md)
- `T-02822`: [docs/tasks/evidence/T-02822-cli-surface-specification.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02822-cli-surface-specification.md)
- `T-02823`: [docs/tasks/evidence/T-02823-cli-surface-scaffold.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02823-cli-surface-scaffold.md)
- `T-02824`: [docs/tasks/evidence/T-02824-cli-surface-implementation.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02824-cli-surface-implementation.md)
- `T-02825`: [docs/tasks/evidence/T-02825-cli-surface-unit-test.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02825-cli-surface-unit-test.md)
- `T-02826`: [docs/tasks/evidence/T-02826-cli-surface-integration.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02826-cli-surface-integration.md)
- `T-02827`: [docs/tasks/evidence/T-02827-cli-surface-security-review.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02827-cli-surface-security-review.md)
- `T-02828`: [docs/tasks/evidence/T-02828-cli-surface-hardening.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02828-cli-surface-hardening.md)

