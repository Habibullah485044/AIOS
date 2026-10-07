# Specification: Proof of Restraint — Capability Mint/Redeem Records

## 1. Overview & Purpose
This specification defines the cryptographic data model and runtime contracts for **Capability Mint & Redeem Records**, forming **Layer 1** of the AIOS **Proof of Restraint** architecture.

Traditional audit logs record what an agent *did*. Proof of Restraint enables proving what an agent *did not do* ("negative attestation"). The foundation of negative attestation is structural: an agent cannot invoke a sensitive capability without redeeming an ephemeral, expiring, single-use token. By recording grant issuance (`pep.capability.mint`) and atomic consumption (`pep.capability.redeem`) into the append-only hash-chained `audit_ring`, verifiers can mathematically prove that any minted capability that lacks a corresponding redeem event remained unexercised throughout its validity window.

## 2. Invariants
- **Invariant I-1 (Mint-to-Redeem 1:1 Parity)**:
  Every grant issuance writes a `pep.capability.mint` audit row. Every single-use grant invocation writes exactly one `pep.capability.redeem` audit row referencing the same `grant_token`.
- **Invariant I-2 (Atomic Single-Use Gate)**:
  A single-use grant cannot be redeemed more than once. Concurrent or subsequent redemption attempts are rejected by atomic database updates.
- **Fail-Closed Synchronization**:
  If the write to `audit_ring` fails during redemption, the in-database redemption state is rolled back to prevent desynchronization between grant state and audit evidence.

## 3. Data Schema & Contracts

### 3.1 SQLite WAL Schema (`pep_grants`)
```sql
CREATE TABLE IF NOT EXISTS pep_grants (
    grant_id          TEXT PRIMARY KEY,
    issued_at         TEXT NOT NULL,
    expires_at        TEXT NOT NULL,
    issued_to         TEXT NOT NULL,
    constitution_rev  TEXT NOT NULL,
    scope_json        TEXT NOT NULL,
    scope_hash        TEXT NOT NULL,
    revoked_at        TEXT,
    single_use        INTEGER NOT NULL DEFAULT 1,
    redeemed_at       TEXT
);
```

### 3.2 Audit Event Records

#### `pep.capability.mint`
Emitted when a capability grant is created by an operator or supervisor:
```json
{
  "ts": "2026-10-07T05:00:00.000Z",
  "actor": "user",
  "actor_id": "admin@aios",
  "tool": "pep.capability.mint",
  "command": "grant.mint",
  "args": {
    "grant_id": "gr_a1b2c3d4e5f67890",
    "single_use": true,
    "scope": {
      "tools": ["fs.write", "net.curl"],
      "paths": ["/var/data/prod"],
      "networks": ["192.168.1.0/24"]
    },
    "expires_at": "2026-10-07T06:00:00.000Z"
  },
  "outcome": "ok",
  "grant_token": "gr_a1b2c3d4e5f67890",
  "c_flags": { "c1": false, "c2": false, "c3": false, "c4": false }
}
```

#### `pep.capability.redeem`
Emitted immediately prior to tool execution by the PEP dispatch gate:
```json
{
  "ts": "2026-10-07T05:05:00.000Z",
  "actor": "agent",
  "actor_id": "agent:worker_42",
  "tool": "pep.capability.redeem",
  "command": "fs.write /var/data/prod/ledger.dat",
  "args": {
    "grant_id": "gr_a1b2c3d4e5f67890",
    "tool": "fs.write",
    "command": "fs.write /var/data/prod/ledger.dat"
  },
  "outcome": "ok",
  "grant_token": "gr_a1b2c3d4e5f67890",
  "c_flags": { "c1": false, "c2": false, "c3": false, "c4": false }
}
```

## 4. Usage & Examples

### 4.1 Programmatic (TypeScript)
```typescript
import { PepGrantManager } from "aiosh-cli/src/pep";
import { AuditRing } from "aiosh-cli/src/audit";

const ring = AuditRing.open();
const pep = PepGrantManager.open();

// Mint capability
const grant = pep.create({
  issued_to: "agent:scanner",
  constitution_rev: "rev_c0ffee",
  scope: { tools: ["pentest.nmap"] },
  ttl_seconds: 3600,
  single_use: true,
}, ring);

// Check capability status (unspent check)
const check = pep.check(grant.grant_id, "pentest.nmap");
if (!check.ok) throw new Error(check.reason);

// Redeem capability before executing tool
const redemption = pep.redeem(
  grant.grant_id,
  "agent:scanner",
  "pentest.nmap",
  "nmap -sT 10.0.0.1",
  ring
);
if (!redemption.ok) throw new Error(redemption.reason);
```

### 4.2 Cross-Substrate Verification (Python)
```python
from aiosh_mcp import audit_client

with audit_client.open_db("~/.aios/audit.db") as conn:
    report = audit_client.verify(conn)
    assert report["ok"], f"Audit ring verification failed: {report}"
    print(f"Verified {report['checked']} rows across hash chain")
```

## 5. Security Constraints & Honest Limitations
1. **Unanchored Chains Vulnerability**:
   Layer 1 ensures that any legitimate operation leaves an immutable record in `audit_ring`. However, without external anchoring (Layer 2), a malicious operator with root database access could delete rows and re-hash the SQLite database from genesis. Proof of Restraint requires Component 3 (Checkpoints & Anchors) to bind chain heads to external public keys.
2. **Crash Consistency**:
   In the event of an abrupt system power loss between `redeem()` database commit and tool execution termination, the token is recorded as redeemed even if the tool process was terminated by OS signal. This guarantees fail-closed restraint.

## 6. Associated Task Evidence Files
- [Research Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02832-research.md)
- [Specification Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02833-spec.md)
- [Scaffold Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02834-capability-mint-redeem-records-scaffold.md)
- [Implementation Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02835-capability-mint-redeem-records-implementation.md)
- [Unit Test Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02836-capability-mint-redeem-records-unit-test.md)
- [Integration Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02837-capability-mint-redeem-records-integration.md)
- [Security Review Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02838-capability-mint-redeem-records-security-review.md)
- [Hardening Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02839-capability-mint-redeem-records-hardening.md)
