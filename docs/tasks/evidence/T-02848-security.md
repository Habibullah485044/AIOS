# Security Review: T-02848 — redeem-before-act gate: Security Review

## Task Information
- **Task ID**: `T-02848`
- **Subsystem**: `Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate`
- **Title**: `redeem-before-act gate: Security Review`
- **Status**: Completed

## 1. Standing Rule [PoR] Verification (Invariant I-2)
- **Standing Rule**: "If this component adds or changes any state-changing path, confirm it cannot execute without redeeming a capability token (PLAN.md invariant I-2) and record the check in the security evidence."
- **Audit Findings**:
  - All state-changing MCP tools (`pentest.*`, `aios_backup_create`, `aios_release_generate`, `aios_audit_rotate`) route through `_dispatch.dispatch(require_grant=True)`.
  - Gate #2.5 intercepts every tool execution that supplies a `grant_id` and executes atomic redemption before returning `ok: True`.
  - Any attempt to execute an irreversible tool without a grant token is refused with `"tool requires explicit PEP grant"`.
  - Any attempt to execute with an already-redeemed or expired token is refused with `"single-use grant already redeemed at ..."` or `"grant expired"`.
  - **Verdict**: Invariant I-2 is certified with ZERO bypass vectors.

## 2. Abuse Scenarios & Threat Analysis

### Abuse Scenario 1: Concurrent Replay / Race Condition
- **Attacker Goal**: Present the same single-use token simultaneously across multiple threads or processes to double-spend the capability.
- **Analysis**:
  - The redemption query:
    ```sql
    UPDATE pep_grants SET redeemed_at = ?
    WHERE grant_id = ? AND redeemed_at IS NULL AND revoked_at IS NULL
    ```
    relies on SQLite's serialized transaction model in WAL mode.
  - The first transaction to acquire the write lock updates the row (`cur.rowcount == 1`).
  - The second transaction sees `redeemed_at IS NOT NULL`, resulting in `cur.rowcount == 0`.
  - The second transaction is aborted with `ok: False`, writes a refusal audit row, and never executes the tool body.

### Abuse Scenario 2: Audit Ring Write Failure
- **Attacker Goal**: Force a disk-write failure during audit logging so that a tool executes without leaving an audit trail.
- **Analysis**:
  - The redemption logic wraps `write_audit_row()` in a try/except block.
  - If writing to `audit_ring` fails, the database update is rolled back (`redeemed_at = NULL`), and the function returns `ok: False`.
  - Dispatch refuses the request and aborts. The tool is never executed unlogged.

### Abuse Scenario 3: Target and Command Injection
- **Attacker Goal**: Pass maliciously formatted commands or shell metacharacters to bypass scope restrictions or trigger arbitrary code execution.
- **Analysis**:
  - Scope validation performs glob matching on `tool` and path/network matching on `target`.
  - Commands executed via `pentest` wrappers use safe list-based arguments or `shlex.quote()`.
  - Tool and command parameters are bounded to 8192 characters, preventing memory exhaustion or database buffer overflows.

## 3. Hardening Recommendations for T-02849
- Ensure timeout values on external child processes spawned by tool wrappers are strictly bounded.
- Ensure that if `dispatch()` returns `ok: False`, callers never fall back to default execution.
