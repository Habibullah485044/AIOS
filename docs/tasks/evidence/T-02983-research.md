# Research Document: Incident Response Runbooks & RustSec CLI Surface (T-02983)

- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Incident Response Runbooks & RustSec Tooling / CLI surface
- **Focus**: Command Grammar, Flags, Exit Codes, PEP Capability Gating, and Proof-of-Receipt Audit Ring Emission
- **Bindings**: NIST SP 800-61 Rev. 2, CISA Playbooks, ADR-0035 §C-2, ADR-0036 §B-1, PoR Invariant I-2

---

## 1. Executive Summary

This research establishes the CLI grammar, execution contracts, capability gating, and audit emission standards for the Incident Response Runbooks CLI (`aiosh runbook`) and the Rust-native Security Tooling Substrate (`aiosh scan`).

Following the AIOS Phase 2 single-binary userspace pattern (`code/aiosh-rust/aiosh-cli`), the CLI exposes:
1. Operational containment commands for incident response runbooks (`aiosh runbook`).
2. High-speed, sandboxed security scanning utilities powered by native Rust substrates (`aiosh scan net`, `aiosh scan files`, `aiosh scan web`), utilizing **RustScan**, **Ripgrep (`rg`)**, and **Feroxbuster** with embedded pure-Rust fallbacks.

---

## 2. Command Architecture & Grammar

### 2.1 Incident Response Runbooks: `aiosh runbook`
```
aiosh runbook [SUBCOMMAND] [OPTIONS]

SUBCOMMANDS:
  list                List registered incident response runbooks in catalog
                      Flags:
                        --category <CAT>        Filter by category (malware, access, exfiltration, dos, integrity)
                        --severity <SEV>        Filter by severity (critical, high, medium, low)
                        --json                  Output catalog in JSON format

  show <ID>           Inspect runbook definition and execution steps
                      Flags:
                        --json                  Output runbook spec in JSON format

  init                Generate baseline incident runbook catalog file
                      Flags:
                        --path <PATH>           Destination path
                        --force                 Overwrite existing catalog

  start <ID>          Initialize a new execution session for runbook <ID>
                      Flags:
                        --incident-id <INC_ID>  Associated incident identifier (e.g., INC-2026-001)
                        --param <KEY=VAL>       Execution parameters (repeatable, max 32)
                        --grant <TOKEN>         PEP capability grant token
                        --json                  Output initialized session in JSON format

  step <SESSION_ID>   Advance execution of current pending step
                      Flags:
                        --confirm               Provide explicit step confirmation if gated
                        --token <TOKEN>         Operator confirmation authorization token
                        --operator <OP_ID>      Operator identifier (default: current user)
                        --json                  Output updated session in JSON format

  confirm <SESSION_ID> Confirm gated high-risk step awaiting operator authorization
                      Flags:
                        --operator <OP_ID>      Operator identifier
                        --token <TOKEN>         Cryptographic confirmation token

  abort <SESSION_ID>  Immediately abort active runbook execution session
                      Flags:
                        --reason <REASON>       Operator cancellation reason

  status <SESSION_ID> Inspect execution state, step progress, and output logs
                      Flags:
                        --json                  Output session state in JSON format
```

### 2.2 RustSec Security Scanning Substrate: `aiosh scan`
```
aiosh scan [SUBCOMMAND] [TARGET] [OPTIONS]

SUBCOMMANDS:
  net <HOST_OR_CIDR>  Rapid non-blocking port scanning and open socket discovery
                      Substrate: RustScan (or embedded asynchronous TCP stream sweep)
                      Flags:
                        --ports <RANGE>         Port range or comma-separated list (default: top-100)
                        --timeout-s <SECS>      Watchdog timeout in seconds (default: 10s)
                        --grant <TOKEN>         PEP capability grant (`cap:net:scan`)
                        --json                  Output findings in structured JSON format

  files <DIR>         High-performance forensic log and secret pattern scanning
                      Substrate: Ripgrep (rg) (or embedded memory-mapped pattern regex)
                      Flags:
                        --pattern <REGEX>       Search pattern or IOC regex (required)
                        --max-depth <N>         Maximum directory recursion depth (default: 10)
                        --timeout-s <SECS>      Watchdog timeout in seconds (default: 30s)
                        --grant <TOKEN>         PEP capability grant (`cap:fs:search`)
                        --json                  Output matched findings in JSON format

  web <URL>           High-concurrency web directory and API endpoint audit
                      Substrate: Feroxbuster (or embedded lightweight HTTP endpoint prober)
                      Flags:
                        --wordlist <PATH>       Wordlist path for path probing (optional)
                        --depth <N>             Maximum recursion depth (default: 2)
                        --timeout-s <SECS>      Watchdog timeout in seconds (default: 30s)
                        --grant <TOKEN>         PEP capability grant (`cap:web:probe`)
                        --json                  Output discovered endpoints in JSON format
```

---

## 3. Invariants & Security Guarantees

| Invariant | Name | Description |
| :--- | :--- | :--- |
| `IRCLI1` | **Proof-of-Receipt Audit Completeness** | Every invocation of `aiosh runbook` and `aiosh scan` writes exactly one immutable receipt into the append-only audit ring (`AuditRing`). |
| `IRCLI2` | **PEP Capability Gate Enforcement** | Actions touching network (`cap:net:scan`), filesystem (`cap:fs:search`), web endpoints (`cap:web:probe`), or process execution (`cap:ir:exec`) require valid grant tokens evaluated through `pep.check`. |
| `IRCLI3` | **Safe Parameter Interpolation & Whitelist** | All CLI parameters are passed as explicit `argv` vectors (zero shell interpretation) and validated against positive whitelist (`^[a-zA-Z0-9_\-\.:/]+$`). Rejects shell metacharacters and path traversal `..`. |
| `IRCLI4` | **Standardized Exit Codes** | `0` = Success, `1` = Validation or domain failure, `2` = Usage syntax error, `3` = Watchdog timeout / IO failure. |
| `IRCLI5` | **Terminal Sanitization (CWE-150)** | Dynamic command outputs and error messages are scrubbed of ANSI control codes and escape sequences prior to display. |
| `IRCLI6` | **Zero Secret Disclosure** | Token strings, private paths, and credentials are scrubbed or masked in command outputs and audit details. |

---

## 4. Unknowns & Decisions Needed

1. **Decision 1 (Single Binary vs Plugin)**:
   - *Decision*: Integrate CLI commands directly in `code/aiosh-rust/aiosh-cli/src/main.rs` as `cmd_runbook` and `cmd_scan`.
2. **Decision 2 (Pure Rust Fallback)**:
   - *Decision*: While honoring external binaries (`rustscan`, `rg`, `feroxbuster`) if installed on `PATH`, the substrate must provide native Rust implementations so that `aiosh scan` operates out-of-the-box on modest systems without third-party dependencies.
3. **Decision 3 (Aliases)**:
   - Register `aiosh runbook` (alias `aiosh rb`) and `aiosh scan`.
