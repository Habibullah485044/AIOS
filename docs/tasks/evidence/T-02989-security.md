# Security Review: Incident Response Runbooks & RustSec CLI Surface (T-02989)

- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Incident Response Runbooks & RustSec Tooling / CLI surface
- **Task ID**: `T-02989`
- **Specification Document**: `docs/SPEC-INCIDENT-RUNBOOK-CLI.md`

## 1. Threat Modeling & Abuse Scenarios

| ID | Threat Vector | CWE | Attack Surface | Mitigation & Enforcement | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AS-01** | Command Injection | CWE-78 | `aiosh scan` and `aiosh runbook --param` | `validate_scan_target` rejects `;`, `|`, `&`, `\``, `$`. Zero shell invocations (`argv` vectors or native socket/file I/O only). | MITIGATED |
| **AS-02** | Path Traversal | CWE-22 | `aiosh scan files <DIR>`, `--path` | `validate_scan_target` rejects `..` sequences; early directory canonicalization. | MITIGATED |
| **AS-03** | Ambient Authority Bypass | PoR Invariant I-2 | `scan net`, `scan files`, `scan web` | Actions gate on PEP capability tokens (`cap:net:scan`, `cap:fs:search`, `cap:web:probe`, `cap:ir:exec`). Zero ambient authority. | MITIGATED |
| **AS-04** | Denial of Service | CWE-400 | Massive port ranges, deep filesystem trees | Execution watchdogs (`timeout_s`), port bounds (`MAX_SCAN_PORTS_COUNT`), match capping (1,000 matches max), max file size (10 MB). | MITIGATED |
| **AS-05** | Audit Evasion | CWE-778 | Unlogged scans or runbook step executions | Invariant `IRCLI-INV1`: Every invocation path writes an atomic row to the SQLite WAL `AuditRing` via `classify_and_emit`. | MITIGATED |

## 2. Proof-of-Restraint (PoR) Conformance Verification
- Invariant `I-2` (Redeem-Before-Act): State-changing runbook containment actions and network port sweeps cannot proceed without presenting and redeeming capability tokens (`cap:ir:exec`, `cap:net:scan`).
- Confirmed that failed attempts fail closed and write honest audit rows (`outcome: "failure"`) to the audit ring.

## 3. Hardening Recommendations for T-02990
1. **Target CIDR & Loopback Scoping**: In `scan_net`, restrict network sweeps to loopback / RFC 1918 private IPs unless an explicit external network grant is redeemed.
2. **Path Sanitization & Symlink Escape Prevention**: In `scan_files`, ignore broken or cyclical symlinks that attempt to traverse outside the designated search tree.
3. **ANSI Output Sanitization**: Ensure dynamic text fields in `cmd_runbook` and `cmd_scan` pass through `sanitize_terminal`.
