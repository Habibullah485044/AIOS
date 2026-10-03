# Specification: Threat Model Maintenance CLI Surface (SPEC-THREAT-MODEL-CLI)

- **Status**: SPECIFIED
- **Date**: 2026-10-03
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Maintenance CLI Surface
- **Binding**: ADR-0036 §B-1

## 1. Overview
The `aiosh threat` subcommand exposes administrative and operational capabilities for querying, registering, mitigating, and assessing threat models from the command line.

## 2. Invariants & Rulesets

| Invariant | Name | Description |
|---|---|---|
| `THREATCLI1` | **Audit Completeness** | Every execution of `aiosh threat` emits exactly one audit row into the append-only SQLite ring via `Ctx.emit(...)`. |
| `THREATCLI2` | **Path Traversal Hygiene** | Custom path flags (`--path`) are passed to `ThreatModelService::validate_path` rejecting relative traversal, UNC paths, and symlinks. |
| `THREATCLI3` | **Standardized Exit Codes** | `0` = Success, `1` = Domain validation failure, `2` = Usage syntax error, `3` = Storage / I/O error. |
| `THREATCLI4` | **Zero Secret Disclosure** | CLI output streams scrub private key blocks and sensitive token patterns. |
| `THREATCLI5` | **Atomic Persistence** | Catalog mutations write to temporary staging files before executing atomic rename. |

## 3. Subcommand Grammar & Synopsis

```
aiosh threat [SUBCOMMAND] [OPTIONS]

SUBCOMMANDS:
  list                List registered threat entries
                      Flags:
                        --status <STATUS>       Filter by status (Identified, UnderReview, Mitigated, Accepted, Resolved)
                        --severity <SEVERITY>   Filter by minimum severity (Low, Medium, High, Critical)
                        --category <CATEGORY>   Filter by STRIDE category
                        --json                  Output in JSON format
                        --path <PATH>           Path to threat model file (default: docs/threat_model.json)

  show <ID>           Show detailed threat specification
                      Flags:
                        --json                  Output in JSON format
                        --path <PATH>           Path to threat model file

  register            Register a new threat entry
                      Required Flags:
                        --id <ID>               Unique alphanumeric identifier
                        --title <TITLE>         Brief threat title (max 128 chars)
                        --desc <DESC>           Threat description (max 2048 chars)
                        --cat <CATEGORY>        STRIDE category
                        --sev <SEVERITY>        Threat severity (Low, Medium, High, Critical)
                        --component <COMP>      Target system component
                      Optional Flags:
                        --cwes <C1,C2,...>      Comma-separated list of CWE identifiers
                        --mitigations <M1,M2>   Comma-separated list of initial mitigations
                        --path <PATH>           Path to threat model file

  status <ID> <STATUS>
                      Transition threat lifecycle status
                      Flags:
                        --path <PATH>           Path to threat model file

  mitigate <ID> <TEXT>
                      Record a mitigation against a threat
                      Flags:
                        --path <PATH>           Path to threat model file

  assess              Calculate and display composite risk evaluation
                      Flags:
                        --json                  Output risk assessment in JSON format
                        --path <PATH>           Path to threat model file

  init                Initialize or reset threat catalog with canonical STRIDE baseline
                      Flags:
                        --path <PATH>           Path to threat model file
                        --force                 Overwrite existing catalog if present
```

## 4. Exit Codes
- `0`: Operation succeeded.
- `1`: Domain validation or constraint failure (e.g., duplicate ID, invalid state transition).
- `2`: Command line usage error (missing required arguments or invalid flag syntax).
- `3`: Filesystem I/O or JSON parsing error.
