# Specification: Proof of Restraint — Redeem-Before-Act Gate

## 1. Overview
The **Redeem-Before-Act Gate** guarantees **Invariant I-2** within the AIOS security kernel. Under this model, consequential actions (e.g. penetration testing commands, host file system alterations, reboot requests) cannot be invoked by an autonomous agent without redeeming an active, cryptographically tracked single-use capability token.

Crucially, token redemption occurs **prior to tool invocation**. The security kernel commits a `pep.capability.redeem` audit row into the append-only `audit_ring` before handing control over to the tool's child process or handler. If redemption fails (due to expiry, scope mismatch, or prior use), the execution path is completely blocked and a refusal audit row is logged.

## 2. Dispatch Pipeline Flow

```
[Agent Tool Call]
       │
       ▼
[Gate #1: Rule-pack Classifier] ──────── (refused) ──► Log Refusal & Abort
       │ (passed)
       ▼
[Gate #2: PEP Scope/Expiry Check] ───── (refused) ──► Log Refusal & Abort
       │ (passed)
       ▼
[Gate #2.5: Atomic Redeem Gate] ──────── (refused) ──► Log Refusal & Abort
       │ (atomically sets redeemed_at,
       │  commits pep.capability.redeem row)
       ▼
[Tool Execution] (e.g. pentest.nmap)
       │
       ▼
[Commit Result Row] (outcome=ok / error)
```

## 3. Usage Examples

### 3.1 Invoking a Gated Tool (Python MCP)
```python
from aiosh_mcp import pentest

# First invocation: succeeds, marks token redeemed, commits pep.capability.redeem
result1 = pentest.aios_pentest_nmap(target="127.0.0.1", grant_id="gr_abc123")
print("First call:", result1)

# Second invocation with same single-use token: fails at Gate #2.5
result2 = pentest.aios_pentest_nmap(target="127.0.0.1", grant_id="gr_abc123")
print("Second call:", result2)
# Output: {'ok': False, 'tool': 'pentest.nmap', 'reason': 'grant gr_abc123 already redeemed at ...'}
```

### 3.2 Dispatch Gate API (`aiosh_mcp._dispatch.dispatch`)
```python
from aiosh_mcp import _dispatch

verdict, row = _dispatch.dispatch(
    tool="pentest.nmap",
    command="nmap -sT 10.0.0.1",
    args={"target": "10.0.0.1"},
    target="10.0.0.1",
    grant_id="gr_abc123",
    require_grant=True,
)
if not verdict["ok"]:
    raise PermissionError(f"Gate blocked: {verdict['reason']}")
```

## 4. Known Constraints & Limitations
1. **Crash Attribution**: If a host machine experiences hardware power failure during the execution of a tool, the token remains marked as redeemed in SQLite WAL. This is by design: Proof of Restraint prioritizes fail-closed restraint over capability preservation.
2. **Multi-Process Concurrency**: Concurrency relies on SQLite WAL mode write serialization (`PRAGMA busy_timeout = 5000`). If write lock contention exceeds 5 seconds, redemption fails closed.

## 5. Associated Evidence Artifacts
- [Research Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02842-research.md)
- [Specification Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02843-spec.md)
- [Scaffold Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02844-redeem-before-act-gate-scaffold.md)
- [Implementation Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02845-redeem-before-act-gate-implementation.md)
- [Unit Test Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02846-redeem-before-act-gate-unit-test.md)
- [Integration Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02847-redeem-before-act-gate-integration.md)
- [Security Review Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02848-security.md)
- [Hardening Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02849-redeem-before-act-gate-hardening.md)
