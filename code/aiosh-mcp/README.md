# aiosh-mcp

AIOS Model Context Protocol server (Sprint 0). Five tools, stdio
transport, single source of audit truth shared with `aiosh-cli` via the
same SQLite WAL ring.

Implements **ADR-0035 §D-2** (MCP as the only tool-call protocol).

## Tools exposed

| Tool                  | Reads | Writes | Notes |
|-----------------------|-------|--------|-------|
| `aios.fs.read`        | ✓     |        | Refused without grant; path restricted to `/tmp` and `$HOME/.aios` |
| `aios.process.list`   | ✓     |        | /proc on Linux; `ps` fallback |
| `aios.audit.tail`     | ✓     |        | Tail N rows of the hash chain |
| `aios.audit.verify`   | ✓     |        | Walk chain, confirm hashes; `full=True` replays archived segments (Sprint 3) |
| `aios.audit.rotate`   |       | ✓     | Sprint 3: seal live rows into an archived checkpoint segment; **requires grant** (`audit.rotate` / `audit.*`) |
| `aios.audit.segments` | ✓     |        | Sprint 3: list archived rotation checkpoints |
| `aios.audit.seen`     | ✓     |        | Sprint 3: bloom-backed "was this row hash ever logged?" (`exact=True` confirms via archive scan) |
| `aios.pentest.nmap`   |       | ✓¹    | Real `nmap` if on PATH; otherwise "would-run" stub |
| `aios.service.validate` | ✓   |        | Validates service name syntax (SS1) or full `ServiceSpec` against invariants (SS1..SS5) |
| `aios.service.list`   | ✓     |        | Lists registered services with optional pattern, state, and startup mode filtering |
| `aios.service.get`    | ✓     |        | Retrieves detailed specification and runtime status of a service by canonical name |
| `aios.service.action` |       | ✓     | Executes lifecycle action (`start`, `stop`, `restart`, `reload`, `enable`, `disable`, `mask`, `unmask`) |
| `aios.service.order`  | ✓     |        | Computes topological startup sequence for a service and its dependency graph |
| `aios.service.config` | ✓     |        | Inspects Init & Service Supervision configuration parameters (SC1..SC7) |
| `aios.service.policy` | ✓     |        | Evaluates or inspects service security policies against specifications (SP1..SP6) |
| `aios.service.stats`  | ✓     |        | Inspects service observability metrics, inventory distributions, and health telemetry (SO1..SO6) |
| `aios.service.check`  | ✓     |        | Validates on-disk service store integrity and optionally performs non-destructive recovery (SR1..SR5) |
| `aios.session.validate` | ✓   |        | Validates session ID, username syntax (SB1, SB2) or full `UserSessionSpec` against invariants (SB1..SB5) |
| `aios.session.list`   | ✓     |        | Lists active/tracked user sessions with optional user, state, type, seat, limit filtering |
| `aios.session.get`    | ✓     |        | Retrieves runtime status and specification of a session by ID |
| `aios.session.action` |       | ✓     | Executes lifecycle action (`authenticate`, `activate`, `lock`, `unlock`, `terminate`) with seat arbitration |
| `aios.session.create` |       | ✓     | Atomically provisions a new user or agent session with validation and capacity enforcement |
| `aios.session.config` | ✓     |        | Inspects User Session Bootstrap configuration parameters and limits (SC1..SC7) |
| `aios.session.policy` | ✓     |        | Evaluates session specifications or stores against UserSessionSecurityPolicy (SSP1..SSP7) |
| `aios.session.stats`  | ✓     |        | Generates telemetry, metrics, and state distribution report (SSO1..SSO6) |
| `aios.session.check`  | ✓     | ✓¹    | Validates on-disk user session store integrity and optionally performs non-destructive recovery (SSR1..SSR5) |
| `aios.fs_layout.get`  | ✓     |       | Stored layout by `layout_id`, or a built-in preset by `profile` |
| `aios.fs_layout.list` | ✓     |       | Lists the store's layouts (default: the seeded built-in presets) |
| `aios.fs_layout.validate` | ✓ |       | Runs `FL1..FL6` over `spec`/`layout`; never reads the store |
| `aios.fs_layout.fstab` | ✓    |       | Renders `/etc/fstab` from `spec`/`profile` |
| `aios.fs_layout.probe` | ✓    |       | Evaluates a layout against `target_disk_bytes` (default 64 GiB) |
| `aios.fs_layout.diff` | ✓     |       | Differential comparison; reports `destructive` |
| `aios.fs_layout.register` |   | ✓     | Registers a layout profile — **requires grant + `store_path`** |
| `aios.fs_layout.set_active` | | ✓     | Moves the active-layout pointer — **requires grant + `store_path`** |
| `aios.fs_layout.remove` |     | ✓     | Deletes a non-active, non-built-in layout — **requires grant + `store_path`** |
| `aios.fs_layout.import_fstab` | | ✓   | Builds a layout from fstab text — **requires grant + `store_path`** |
| `aios_compliance`   | ✓     | ✓     | Compliance Mapping (NIST SP 800-53 / SOC 2 / ISO 27001 / CIS v8): reads never create or touch the store; `register` / `status` transitions / `init` are PEP-gated writes; one canonical-JSON store shared byte-for-byte with the Rust CLI `aiosh compliance --path`; 1 MiB cap on load **and** save |

¹ The pentest, service action, and recovery tools write an audit row through the same recorded dispatch helper; in Sprint 0 the row is written synchronously. Every `aios.fs_layout.*` call that reaches the gate writes exactly one hash-chained row too — on success, on a body refusal, and on a gate refusal alike (an unknown tool name is refused before the ring and leaves no row).

## Service Supervision Tools (`aios.service.*`)

The Init & Service Supervision tools provide programmatic control over platform services via standard MCP JSON-RPC 2.0:

### Copy-Pasteable Tool Call Examples

#### 1. Validate Service Name or Specification (`aios.service.validate`)
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "aios.service.validate",
    "arguments": {
      "name": "auditd.service"
    }
  }
}
```

#### 2. Query Services with Filters (`aios.service.list`)
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "aios.service.list",
    "arguments": {
      "state": "active",
      "pattern": "audit"
    }
  }
}
```

#### 3. Inspect Service Metadata & Status (`aios.service.get`)
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "aios.service.get",
    "arguments": {
      "name": "auditd.service"
    }
  }
}
```

#### 4. Execute Service Lifecycle Action (`aios.service.action`)
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "aios.service.action",
    "arguments": {
      "name": "auditd.service",
      "action": "restart"
    }
  }
}
```

#### 5. Compute Startup Dependency Sequence (`aios.service.order`)
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "aios.service.order",
    "arguments": {
      "name": "aios-securityd.service"
    }
  }
}
```

#### 6. Inspect Service Observability Metrics (`aios.service.stats`)
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "tools/call",
  "params": {
    "name": "aios.service.stats",
    "arguments": {}
  }
}
```

#### 7. Validate and Recover Service Store (`aios.service.check`)
```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "tools/call",
  "params": {
    "name": "aios.service.check",
    "arguments": {
      "store_path": "/var/lib/aios/services.json",
      "auto_recover": true
    }
  }
}
```

### User Session Bootstrap Tools

#### Validate Session Identifier, Username, or Specification (`aios.session.validate`)
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "aios.session.validate",
    "arguments": {
      "session_id": "sess-01"
    }
  }
}
```
Validate complete session specification against formal invariants (`SB1..SB5`):
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "aios.session.validate",
    "arguments": {
      "spec": {
        "session_id": "sess-01",
        "username": "kali",
        "uid": 1000,
        "gid": 1000,
        "session_type": "x11",
        "session_class": "user",
        "seat": "seat0",
        "vtnr": 7,
        "display": ":0",
        "remote_host": null,
        "environment": {
          "XDG_RUNTIME_DIR": "/run/user/1000",
          "DISPLAY": ":0"
        }
      }
    }
  }
}
```

#### Query Tracked Sessions (`aios.session.list`)
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "aios.session.list",
    "arguments": {
      "state": "active",
      "seat": "seat0"
    }
  }
}
```

#### Inspect Session Specification & Status (`aios.session.get`)
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "aios.session.get",
    "arguments": {
      "session_id": "greeter-seat0"
    }
  }
}
```

#### Execute Lifecycle Action (`aios.session.action`)
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "aios.session.action",
    "arguments": {
      "session_id": "sess-01",
      "action": "activate"
    }
  }
}
```

#### Provision Session (`aios.session.create`)
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "tools/call",
  "params": {
    "name": "aios.session.create",
    "arguments": {
      "spec": {
        "session_id": "sess-agent-01",
        "username": "aios-agent",
        "uid": 1001,
        "gid": 1001,
        "session_type": "ai_agent",
        "session_class": "agent",
        "seat": "seat0",
        "vtnr": null,
        "display": null,
        "remote_host": null,
        "environment": {
          "AIOS_AGENT_MODE": "autonomous",
          "AIOS_AGENT_ID": "agent-copilot"
        }
      },
      "store_path": "/tmp/.aios/sessions.json"
    }
  }
}
```

#### Validate or Recover Session Store (`aios.session.check`)
```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "tools/call",
  "params": {
    "name": "aios.session.check",
    "arguments": {
      "store_path": "/var/run/aios/sessions.json",
      "auto_recover": true
    }
  }
}
```

### CLI Command Examples (`aiosh session`)
- Validate session spec: `aiosh session validate --spec /path/to/spec.json --json`
- List active sessions: `aiosh session list --state active --seat seat0 --limit 50 --json`
- Show session status: `aiosh session show greeter-seat0 --json`
- Lock / Unlock session: `aiosh session action greeter-seat0 lock --json`
- Create session: `aiosh session create --id sess-agent-01 --user aios-agent --type agent --seat seat0 --json`
- Security policy: `aiosh session policy --policy /path/to/policy.json --store /path/to/store.json --json`
- Telemetry & observability: `aiosh session stats --policy /path/to/policy.json --store /path/to/store.json --json`
- Check store integrity: `aiosh session check [--store /path/to/store.json] [--json]`
- Auto-recover store with quarantine: `aiosh session check --fix [--store /path/to/store.json] [--json]`
- Recover shortcut: `aiosh session recover [--store /path/to/store.json] [--json]`

### User Session Constraints & Invariants (CS1..CS5, SB1..SB5)
- **Seat Mutual Exclusion (CS2)**: At most one session can hold `SessionScope::Foreground` on any physical/virtual seat (e.g. `seat0`). Activating a session automatically demotes prior foreground sessions on that seat to `SessionScope::Background`.
- **State Monotonicity & Two-Stage Teardown (CS1)**: Terminated sessions (`state == Terminated`) are immutable and permanent; any subsequent action fails with an explicit error envelope. Active and Locked sessions follow a two-stage termination path: `terminate` transitions to `Terminating` (process cleanup), and a subsequent `terminate` finalizes transition to `Terminated`.
- **Store & User Capacities (CS3, SB5)**: Maximum 32 active sessions per user (`MAX_SESSIONS_PER_USER`) and maximum 1,024 total tracked sessions in store (`MAX_TOTAL_SESSIONS`).
- **Lock State Invariant (CS5)**: `state == Locked` strictly matches `locked == true`; `state == Active` strictly matches `locked == false`. Touching activity resets `idle_seconds` to 0 but never unlocks a session.
- **Hardening Ceilings & Bounds**:
  - Request line ceiling: 1 MiB (`1,048,576` bytes) transport-level limit.
  - Specification payload ceiling: 1 MiB limit on inline JSON objects and strings in `validate` and `create`.
  - Query bounds: `limit` parameter in `aios.session.list` strictly enforced to $[1 \dots 10,000]$.
  - Path sanitization: `store_path` parameter strictly bounded to $\le 1024$ characters with zero control characters.
  - Session identifier: strictly validated against `SB1` ($[1 \dots 64]$ chars, alphanumeric start, no slashes or traversal tokens).
  - Atomic persistence: 10 MiB store limit (`MAX_SESSION_STORE_SIZE`), atomic rename via PID-isolated temporary files (`.tmp.<pid>.<nanos>`), and guaranteed tempfile cleanup on write/rename failure.

### Evidence & Implementation Artifacts
- **Research:** [`T-01431-mcp-api-surface-research.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01431-mcp-api-surface-research.md)
- **Specification:** [`T-01432-mcp-api-surface-specification.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01432-mcp-api-surface-specification.md)
- **Scaffold:** [`T-01433-mcp-api-surface-scaffold.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01433-mcp-api-surface-scaffold.md)
- **Implementation:** [`T-01434-mcp-api-surface-implementation.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01434-mcp-api-surface-implementation.md)
- **Unit Testing:** [`T-01435-mcp-api-surface-unit-test.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01435-mcp-api-surface-unit-test.md)
- **Integration:** [`T-01436-mcp-api-surface-integration.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01436-mcp-api-surface-integration.md)
- **Security Review:** [`T-01437-mcp-api-surface-security-review.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01437-mcp-api-surface-security-review.md)
- **Hardening:** [`T-01438-mcp-api-surface-hardening.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01438-mcp-api-surface-hardening.md)
- **Documentation:** [`T-01439-mcp-api-surface-documentation.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01439-mcp-api-surface-documentation.md)

### Recovery & Validation Evidence Artifacts (SSR1..SSR5)
- **Research:** [`T-01491-recovery-validation-research.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01491-recovery-validation-research.md)
- **Specification:** [`T-01492-recovery-validation-specification.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01492-recovery-validation-specification.md)
- **Scaffold:** [`T-01493-recovery-validation-scaffold.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01493-recovery-validation-scaffold.md)
- **Implementation:** [`T-01494-recovery-validation-implementation.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01494-recovery-validation-implementation.md)
- **Unit Testing:** [`T-01495-recovery-validation-unit-test.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01495-recovery-validation-unit-test.md)
- **Integration:** [`T-01496-recovery-validation-integration.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01496-recovery-validation-integration.md)
- **Security Review:** [`T-01497-recovery-validation-security-review.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01497-recovery-validation-security-review.md)
- **Hardening:** [`T-01498-recovery-validation-hardening.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01498-recovery-validation-hardening.md)
- **Documentation:** [`T-01499-recovery-validation-documentation.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-01499-recovery-validation-documentation.md)

### Constraints & Known Limitations
- **Name Format**: Service names are limited to 128 ASCII characters matching `^[a-zA-Z0-9][a-zA-Z0-9_\-\.]{0,126}\.service$`. Control characters are strictly rejected.
- **Masking Invariant**: A service in `masked` mode cannot be started or enabled. Active services must be stopped before they can be masked.
- **Persistence Boundary**: By default, tools operate on the active runtime store; passing `store_path` reads and atomically persists changes to the designated JSON file using PID-isolated temp files.
### User Session Bootstrap Tools

The User Session Bootstrap tools provide programmatic management, inspection, and security policy evaluation for interactive and autonomous AI agent sessions:

#### `aios.session.validate`
Validates session identifiers, user identity bounds, or full session specifications against invariants.

#### `aios.session.list`
Queries tracked user and agent sessions with optional filters (`session_type`, `state`, `username`, `seat`, `limit`).

#### `aios.session.get`
Retrieves detailed session status and specification by `session_id`.

#### `aios.session.action`
Executes lifecycle state transitions (`authenticate`, `activate`, `lock`, `unlock`, `terminate`) on a session. **PEP Gated**: Requires an explicit authorization grant (`require_grant: true`).

```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "tools/call",
  "params": {
    "name": "aios.session.action",
    "arguments": {
      "session_id": "sess-copilot-01",
      "action": "lock",
      "grant_id": "gr_eb284bdf79721da3"
    }
  }
}
```

#### `aios.session.create`
Bootstraps and initializes a new user or agent session specification. **PEP Gated**: Requires an explicit authorization grant (`require_grant: true`).

```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "tools/call",
  "params": {
    "name": "aios.session.create",
    "arguments": {
      "grant_id": "gr_eb284bdf79721da3",
      "spec": {
        "session_id": "sess-copilot-01",
        "username": "kali",
        "uid": 1000,
        "gid": 1000,
        "session_type": "ai_agent",
        "session_class": "agent",
        "seat": "seat0",
        "environment": {
          "AIOS_AGENT": "1"
        }
      }
    }
  }
}
```

#### `aios.session.config`
Inspects runtime session parameters, timeouts, and capacity ceilings.

#### `aios.session.policy`
Evaluates user session specifications or entire session stores against `UserSessionSecurityPolicy` (`SSP1..SSP7`):

```json
{
  "jsonrpc": "2.0",
  "id": 10,
  "method": "tools/call",
  "params": {
    "name": "aios.session.policy",
    "arguments": {
      "spec": {
        "session_id": "agent-eval-01",
        "username": "kali",
        "uid": 1000,
        "gid": 1000,
        "session_type": "ai_agent",
        "session_class": "agent",
        "seat": "seat0"
      }
    }
  }
}
```

#### `aios.session.stats`
Generates comprehensive observability telemetry and distribution metrics across tracked user and agent sessions (`SSO1..SSO6`):

```json
{
  "jsonrpc": "2.0",
  "id": 11,
  "method": "tools/call",
  "params": {
    "name": "aios.session.stats",
    "arguments": {
      "store_path": "/path/to/sessions.json"
    }
  }
}
```

## Filesystem Layout Tools (`aios.fs_layout.*`)

Ten tools over the `aiosh-core::fs_layout` subsystem: target-disk layout profiles (partitions, mount
points, FHS directories, `/etc/fstab`) validated against `FL1..FL6` / `CS1..CS5`. The six read-only
tools need no grant; the four **mutations** (`register`, `set_active`, `remove`, `import_fstab`) each
require a PEP grant **and** an explicit `store_path`, because no canonical default store exists yet.
An ungranted mutation is refused before the body runs, and the refusal names the gate.

`scope.paths` on the grant governs the paths a call touches — the store it writes and the `spec`/
`fstab` document it reads — and matching is canonical, so a deny entry holds against case, 8.3
short-name, trailing dot/space and device-spelling aliases of the same location.

Full tool reference, result-envelope contract, and the honest limitations: **§5 and §6 of
[`docs/filesystem_layout.md`](../../docs/filesystem_layout.md)**.

Requires `aiosh` and `aiosh-mcp` on `PATH` (see **Running** below) and `python3`.

```bash
# Isolate the demo's audit ring so a copy-pasted example never writes to your real one.
export AIOSH_HOME="$PWD/.aios-demo"; mkdir -p "$AIOSH_HOME" demo

# Mint a grant scoped to the demo directory. Use a named relative directory (not `.`) and keep
# ONE spelling frame for both the grant and the calls: mixing frames (or using an MSYS-style /tmp
# path on Windows) can refuse an in-scope call — see docs/filesystem_layout.md §6.20–§6.21.
GRANT=$(aiosh grant create --to agent:fs-layout-demo --tools 'aios.fs_layout.*' --allow demo \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["grant_id"])')

# Derive a spec from the canonical container preset.
aiosh layout show aios-container-minimal-v1 --json | python3 -c \
  'import json,sys; s=json.load(sys.stdin)["data"]; s["id"]="lab-vm-v1"; s["name"]="Lab VM"; print(json.dumps(s))' \
  > demo/layout.json

# requests.jsonl: one JSON-RPC object per line — list, register, probe, then a refusal.
cat > requests.jsonl <<EOF
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"aios.fs_layout.list","arguments":{"store_path":"demo/layouts.json"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"aios.fs_layout.register","arguments":{"spec":"demo/layout.json","store_path":"demo/layouts.json","grant_id":"$GRANT"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"aios.fs_layout.probe","arguments":{"layout_id":"lab-vm-v1","target_disk_bytes":214748364800,"store_path":"demo/layouts.json"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"aios.fs_layout.register","arguments":{"spec":"demo/layout.json","store_path":"demo/layouts.json"}}}
EOF
aiosh-mcp < requests.jsonl
```

Request 4 carries no `grant_id`, so it answers with the gate refusal rather than registering:
`{"ok":false,"gate":"pep","reason":"tool 'aios.fs_layout.register' requires explicit PEP grant",...}`
with `isError: true` — and no store write. Two further contracts are worth knowing before writing a
client: the rejected shape of a mutation is also explicit (`{"ok":false,"error":"cannot remove
active layout 'x'; switch active layout first"}`), and `"additionalProperties": false` in the schema
is advisory — an undeclared argument such as `"dry_run": true` is currently **ignored** rather than
refused, so a mutation it accompanies still happens.

## Running

```bash
cd code/aiosh-mcp
python -m aiosh_mcp.server
```

The server speaks MCP over stdio, so any MCP client (e.g. the
`mcp` CLI, Claude Desktop with this stdio server registered, an Ollama
tool bridge, or our own `aiosh-cli agent` once Sprint-1 lands) can call
the tools.

## Architecture references

- **ADR-0035 §D-2** — MCP is the only tool-call protocol.
- **ADR-0035 §D-4** — Constitution C-1..C-3 enforced at the tool gate.
- **AI_CONSTITUTION.md §1.4 C-1** — pentest tools require explicit grant.
- **AI_CONSTITUTION.md §1.4 C-3** — non-reversible effects (fs.write,
  pentest, shutdown) require granular consent.

## Sampling primitive

**Not exposed.** Per ADR-0035 §5, the deprecated MCP Sampling primitive
is hard-removed from our MCP manifest to eliminate the prompt-injection
vector that asks a server to insert reasoning into a tool response.

## Audit Chain Extensions MCP Tools

Audit Chain Extensions expose query, inspection, causal ancestry DAG traversal, and cryptographic signature verification over standard MCP JSON-RPC 2.0:

| Tool | Parameters | Description |
| :--- | :--- | :--- |
| `aios.audit.query` | `session_id`, `trace_id`, `actor`, `tool`, `parent_hash`, `limit` | Query and filter audit records by provenance and causal links |
| `aios.audit.inspect` | `hash` (required) | Inspect full event details and extensions by SHA-256 row hash |
| `aios.audit.ancestry` | `hash` (required), `depth` (opt, max 64) | Traverse causal DAG parent links to uncover event lineage |
| `aios.audit.sign_verify` | `hash` (required) | Verify Ed25519 digital signature attached to an audit event |

### Example Tool Invocation

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "aios.audit.inspect",
    "arguments": {
      "hash": "3a0b1c2d..."
    }
  }
}
```

**Constraints & Boundaries**:
- Query result limits are clamped between 1 and 1,000 rows (`MAX_QUERY_LIMIT = 1000`).
- Causal ancestry traversal depth is clamped between 1 and 64 levels (`MAX_LINEAGE_DEPTH = 64`) with cyclic graph loop protection.

## Compliance Mapping Tool (`aios_compliance`)

Tool-facing surface of the Compliance Mapping Core Service
([SPEC-COMPLIANCE-SERVICE](../../docs/SPEC-COMPLIANCE-SERVICE.md)).
A single `action` argument dispatches `list` / `show` / `register` /
`status` / `assess` / `check-pep` / `init` against one canonical-JSON
store (`AIOSH_COMPLIANCE_MAP_PATH`, default `$AIOSH_HOME/compliance_map.json`)
that both substrates operate on byte-for-byte: the Python tool surface
above and the Rust CLI (`aiosh compliance ... --path`) below.

### Copy-pasteable tool call examples

#### 1. Read — list mappings (no grant needed)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "aios_compliance",
    "arguments": { "action": "list" }
  }
}
```

Response payload (`content[0].text`, pretty-printed):

```json
{"ok": true, "action": "list", "count": 4,
 "mappings": [ /* the four canonical baseline mappings:
     MAP-NIST-AC3-PEP, MAP-NIST-AU2-RING, MAP-SOC2-CC61-PEP,
     MAP-CIS-CTRL6-PEP */ ], "audit_id": 1}
```

A missing store reads as the canonical baseline **without creating the
file** (reads never write).

#### 2. Write without a grant — refused at the PEP gate, fail-closed

Same request shape with:

```json
"arguments": {"action": "register", "id": "MAP-DOC-001",
  "control_id": "AC-2", "framework": "nist",
  "target_type": "pep_gate", "target_ref": "pep_enforce_gate",
  "status": "compliant", "mitigation_summary": "documented"}
```

returns exactly (captured live, 2026-10-08):

```json
{"ok": false, "tool": "aios.compliance", "audit_id": 1,
 "reason": "tool 'aios.compliance' requires explicit PEP grant",
 "gate": "pep", "policy_revision": "sprint-2-rule-pack-v1"}
```

No store file is created (fail-closed) and exactly one `refused` row
lands in the audit ring. The same call with a pre-minted PEP grant
(`grant_id`, scope `aios.compliance`, redeemed at most once) succeeds
and persists the store.

#### 3. Python direct call (identical envelopes)

```bash
PYTHONPATH=code/aiosh-mcp AIOSH_COMPLIANCE_MAP_PATH=/tmp/compliance_map.json \
  python3 -c "from aiosh_mcp import compliance; print(compliance.execute(action='assess', framework='nist')['report'])"
# {'total_mappings': 2, 'compliant_count': 2,
#  'partially_compliant_count': 0, 'non_compliant_count': 0,
#  'not_applicable_count': 0, 'compliance_percentage': 100.0, ...}
```

#### 4. Rust CLI — same store, other substrate

```bash
./code/aiosh-rust/target/debug/aiosh compliance init   --path /tmp/compliance_map.json
./code/aiosh-rust/target/debug/aiosh compliance list   --path /tmp/compliance_map.json --json
./code/aiosh-rust/target/debug/aiosh compliance assess --framework nist_sp_800_53_rev5 --json --path /tmp/compliance_map.json
# {"assessment":{"compliance_percentage":100.0,"compliant_count":2,
#  "gap_control_ids":[],...},"code":0}
```

#### 5. Observability & Metrics (`stats`) — read-only telemetry (no grant needed)

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "aios_compliance",
    "arguments": { "action": "stats" }
  }
}
```

Response payload (`content[0].text`, pretty-printed):

```json
{
  "ok": true,
  "action": "stats",
  "report": {
    "generated_at_utc": "2026-10-11T09:30:00+00:00",
    "total_mappings": 4,
    "mappings_by_framework": {
      "nist_sp_800_53_rev5": 2,
      "soc2_type2": 1,
      "cis_controls_v8": 1
    },
    "mappings_by_status": { "compliant": 4 },
    "mappings_by_target_type": { "pep_gate": 3, "audit_ring": 1 },
    "compliance_percentage": 100.0,
    "gap_control_count": 0,
    "policy_mode": "unconfigured",
    "capacity_utilization_percent": 0,
    "is_healthy": true,
    "recent_audit_events_count": 0
  },
  "audit_id": 5
}
```

Subcommands: `list|show|register|status|assess|check-pep|init|stats`
(`--framework F`, `--status S`, `--json`, `--path P`; `register`
additionally `--id --control --target-type --target-ref --mitigation`).

### Constraints & Boundaries (honest)

- **Audit honesty (ADR-0035 §F-2)**: every tool call that reaches the
  dispatch writes exactly one hash-chained audit row — `allowed`,
  `refused`, or the error outcome for domain exceptions — with the
  classifier verdict and policy revision attached.
- **Store cap 1 MiB, both directions** (T-02900): loads use a bounded
  read (closes the getsize→read TOCTOU); saves refuse a payload above
  the cap **before any file handle is created**, so a store that could
  never be re-loaded cannot be written (Python and Rust agree).
- **MCP surface is Python-only**: the Rust `aiosh-mcp` server does not
  expose `aios_compliance` — the Rust side of this feature is CLI-only.
  Cross-substrate parity is through the shared store and is
  integration-proven ([T-02898](../../docs/tasks/evidence/T-02898-mcp-api-surface-integration.md)).
- **Status transitions**: `can_transition` mirrors the Rust
  `_ => true` fallback — every transition is legal (test-pinned);
  transitioning to `compliant` requires a mitigation summary or an
  explicit reason.
- **Path rules**: store path must end in `.json`, ≤16 components;
  traversal (CWE-22) and symlinks (CWE-59) rejected.
- **Baseline fallback**: a missing store serves the four canonical
  baseline mappings read-only; only `init` / `register` create the file.

### Evidence & specs

- Service spec: [SPEC-COMPLIANCE-SERVICE](../../docs/SPEC-COMPLIANCE-SERVICE.md)
  (+ `SPEC-COMPLIANCE-CLI.md`, `SPEC-COMPLIANCE-DATA-MODEL.md`)
- Integration (wire + cross-substrate): [T-02898](../../docs/tasks/evidence/T-02898-mcp-api-surface-integration.md)
- Security review: [T-02899](../../docs/tasks/evidence/T-02899-mcp-api-surface-security-review.md)
- Hardening (caps/TOCTOU/auditable failure modes): [T-02900](../../docs/tasks/evidence/T-02900-mcp-api-surface-hardening.md)
- This documentation task: [T-02901](../../docs/tasks/evidence/T-02901-mcp-api-surface-documentation.md)

## MCP Server Core Wire API (`aios_mcp_api_*`)

Exposes wire-level JSON-RPC 2.0 routing and direct tool dispatch for Model Context Protocol clients.

### Tools Exposed
- `aios_mcp_api_ping`: Liveness check returning protocol version (`2025-06-18`).
- `aios_mcp_api_jsonrpc`: Executes raw JSON-RPC 2.0 messages (`initialize`, `ping`, `tools/list`, `tools/call`).

### Example Invocation
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "aios.fs.read",
    "arguments": {
      "path": "/tmp/example.txt"
    }
  }
}
```

### Constraints & Invariants
- `MAX_ARGUMENTS_SIZE = 1 MiB` strict payload ceiling.
- NUL bytes in argument keys/values rejected immediately with `-32602` (`ERR_INVALID_PARAMS`).
- Privileged tools (`aios.admin.*`) require capability grant tokens per Proof-of-Restraint Invariant I-2.

## MCP Server Core Configuration (`aios_mcp_config_*`)

Defines configuration parameters, resolution hierarchy, and validation invariants for the AI Control Plane MCP Server Core (T-03103..T-03112).

### Tools Exposed
- `aios_mcp_config_get`: Retrieves the active, resolved MCP Server Core configuration.
- `aios_mcp_config_validate`: Validates candidate configuration parameters against invariants `MCPCFG-INV1..MCPCFG-INV8` without disk side-effects.

### Resolution Hierarchy
Parameters are resolved in strict hierarchical order:
1. Explicit CLI arguments (`--store-path`, `--max-sessions`, etc.)
2. Environment variables (`AIOS_MCP_STORE_PATH`, `AIOS_MCP_MAX_SESSIONS`, `AIOS_MCP_IDLE_TIMEOUT`, `AIOS_MCP_EXECUTION_TIMEOUT`, `AIOS_MCP_MAX_ARGS_SIZE`, `AIOS_MCP_REQUIRE_ADMIN_GRANT`)
3. Configuration file (`--config` or `AIOS_MCP_CONFIG_PATH`, max 64 KiB)
4. Built-in secure defaults

### Copy-Pasteable Tool Call Examples

#### 1. Inspect Active Configuration (`aios_mcp_config_get`)
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "aios_mcp_config_get",
    "arguments": {}
  }
}
```

#### 2. Validate Candidate Configuration (`aios_mcp_config_validate`)
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "aios_mcp_config_validate",
    "arguments": {
      "candidate_config": {
        "store_path": ".aios/custom_store.json",
        "max_active_sessions": 32,
        "default_execution_timeout_seconds": 45
      }
    }
  }
}
```

### Constraints & Known Limitations
- `store_path` must not be empty, must not contain NUL bytes, and must not contain directory traversal sequences (`..`).
- Active sessions clamped to range `[1, 512]` (`MCPCFG-INV2`).
- Execution timeouts clamped to range `[1, 300]` seconds (`MCPCFG-INV4`).
- Configuration files are capped at 64 KiB (`MAX_CONFIG_FILE_BYTES`).
- State mutations require active administrative capability grants per PoR Invariant I-2.

### Evidence & Specifications
- Specification: [SPEC-MCP-SERVER-CORE-CONFIG](../../docs/SPEC-MCP-SERVER-CORE-CONFIG.md)
- Unit tests: [T-03107](../../docs/tasks/evidence/T-03107-configuration-unit-test.md)
- Integration: [T-03108](../../docs/tasks/evidence/T-03108-configuration-integration.md)
- Security review: [T-03109](../../docs/tasks/evidence/T-03109-configuration-security-review.md)
- Hardening: [T-03110](../../docs/tasks/evidence/T-03110-configuration-hardening.md)
- Documentation: [T-03111](../../docs/tasks/evidence/T-03111-configuration-documentation.md)

## MCP Server Core Automated Test Runner (`aios_mcp_test_run`)

Provides on-demand programmatic diagnostics, health assessment, and invariant compliance checks for the AI Control Plane MCP Server Core (T-03113..T-03122).

### Tools Exposed
- `aios_mcp_test_run`: Executes internal diagnostic test suites and returns a structured `McpTestSuiteReport` envelope.

### Supported Categories
- `data_model`: Validates data structures, content blocks, and envelope serialization.
- `api`: Validates JSON-RPC 2.0 ping, initialize, and method resolution.
- `service`: Validates tool registry bounds and session lifecycles.
- `config`: Validates multi-source resolution, traversal rejection, and bounds.
- `security`: Verifies PoR Invariant I-2 (`aios.admin.*` token gating) and NUL byte sanitization.
- *Default*: If `category` is omitted or empty, executes the complete test suite.

### Copy-Pasteable Tool Call Examples

#### 1. Run Complete Automated Test Battery
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "aios_mcp_test_run",
    "arguments": {}
  }
}
```

#### 2. Run Targeted Security Category Verification
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "aios_mcp_test_run",
    "arguments": {
      "category": "security"
    }
  }
}
```

### Constraints & Known Limitations
- `category` parameter is constrained to known whitelist names and capped at 64 characters.
- Diagnostic runs execute against transient, isolated in-memory test objects; they never mutate live production databases or configurations.
- Execution duration is bounded and errors are safely contained in the result report.

### Evidence & Specifications
- Specification: [SPEC-MCP-SERVER-CORE-TESTS](../../docs/SPEC-MCP-SERVER-CORE-TESTS.md)
- Unit tests: [T-03117](../../docs/tasks/evidence/T-03117-automated-tests-unit-test.md)
- Integration: [T-03118](../../docs/tasks/evidence/T-03118-automated-tests-integration.md)
- Security review: [T-03119](../../docs/tasks/evidence/T-03119-automated-tests-security-review.md)
- Hardening: [T-03120](../../docs/tasks/evidence/T-03120-automated-tests-hardening.md)
- Documentation: [T-03121](../../docs/tasks/evidence/T-03121-automated-tests-documentation.md)

---

## MCP Server Core Security Policy Subsystem (Phase 3)

The **MCP Server Core Security Policy Subsystem** enforces Policy Enforcement Point (PEP) gating and declarative authorization rules across all incoming MCP tool calls. It implements Proof-of-Restraint Invariant I-2 (`Zero Escalation`), strictly requiring capability tokens for state-changing or administrative actions.

### Exposed FastMCP Tools

1. **`aios_mcp_policy_evaluate`**: Evaluates policy rules against an incoming `(subject_role, tool_name, action_category, capability_token)` request.
2. **`aios_mcp_policy_status`**: Returns active policy engine status and rule definitions.

### Example Tool Invocations

#### 1. Evaluate Policy for Read-Only Action
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "aios_mcp_policy_evaluate",
    "arguments": {
      "subject_role": "agent:operator",
      "tool_name": "aios_mcp_config_get",
      "action_category": "read_only"
    }
  }
}
```

#### 2. Evaluate Policy for State-Changing Action with Capability Token
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "aios_mcp_policy_evaluate",
    "arguments": {
      "subject_role": "agent:operator",
      "tool_name": "aios_mcp_config_set",
      "action_category": "state_changing",
      "capability_token": "token:valid-12345"
    }
  }
}
```

#### 3. Inspect Active Policy Engine Rules
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "aios_mcp_policy_status",
    "arguments": {}
  }
}
```

### Constraints & Known Limitations
- State-changing and administrative tools strictly evaluate to `allowed = false` when capability tokens are missing or whitespace-only.
- Total rules are bounded to `MAX_RULES = 256` to prevent memory exhaustion.
- Embedded NUL bytes (`\x00`) in strings are rejected fail-closed.
- Reasons are truncated to 256 characters.

### Evidence & Specifications
- Specification: [SPEC-MCP-SERVER-CORE-POLICY](../../docs/SPEC-MCP-SERVER-CORE-POLICY.md)
- Research: [T-03123](../../docs/tasks/evidence/T-03123-security-policy-research.md)
- Spec Evidence: [T-03124](../../docs/tasks/evidence/T-03124-security-policy-specification.md)
- Scaffold: [T-03125](../../docs/tasks/evidence/T-03125-security-policy-scaffold.md)
- Implementation: [T-03126](../../docs/tasks/evidence/T-03126-security-policy-implementation.md)
- Unit tests: [T-03127](../../docs/tasks/evidence/T-03127-security-policy-unit-test.md)
- Integration: [T-03128](../../docs/tasks/evidence/T-03128-security-policy-integration.md)
- Security review: [T-03129](../../docs/tasks/evidence/T-03129-security-policy-security-review.md)
- Hardening: [T-03130](../../docs/tasks/evidence/T-03130-security-policy-hardening.md)
- Documentation: [T-03131](../../docs/tasks/evidence/T-03131-security-policy-documentation.md)

---

## MCP Server Core Observability Subsystem (Phase 3)

The **MCP Server Core Observability Subsystem** provides real-time health telemetry, request throughput tracking, error classification, and runtime status snapshots for the AI Control Plane MCP Server Core (T-03133..T-03142).

### Exposed FastMCP Tools

1. **`aios_mcp_observability_snapshot`**: Returns an aggregated `McpCoreMetricsSnapshot` containing server status, request counters, error rate percentages, and latency percentiles.

### Example Tool Invocation

#### Inspect Telemetry Snapshot (`aios_mcp_observability_snapshot`)
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "aios_mcp_observability_snapshot",
    "arguments": {}
  }
}
```

Response payload (`content[0].text`, pretty-printed):
```json
{
  "server_name": "aios-mcp-core",
  "timestamp_utc": "2026-10-18T21:30:00Z",
  "active_sessions": 1,
  "total_requests": 42,
  "successful_requests": 40,
  "failed_requests": 2,
  "error_rate_pct": 4.76,
  "average_latency_ms": 12.5,
  "health_status": "healthy"
}
```

### Constraints & Known Limitations
- Counter invariants strictly enforced: `total_requests == successful_requests + failed_requests`.
- Zero-division protection: `error_rate_pct` is safely computed as `0.0` when `total_requests == 0`.
- Telemetry text sanitization: Control characters (`\x00..\x1f`), NUL bytes, and zero-width spaces (`\u200b`, `\ufeff`) are stripped and strings truncated to safe maximum lengths.
- In-memory collection: Telemetry metrics are tracked in-process without unbounded disk growth.

### Evidence & Specifications
- Specification: [SPEC-MCP-SERVER-CORE-OBSERVABILITY](../../docs/SPEC-MCP-SERVER-CORE-OBSERVABILITY.md)
- Research: [T-03133](../../docs/tasks/evidence/T-03133-observability-research.md)
- Spec Evidence: [T-03134](../../docs/tasks/evidence/T-03134-observability-specification.md)
- Scaffold: [T-03135](../../docs/tasks/evidence/T-03135-observability-scaffold.md)
- Implementation: [T-03136](../../docs/tasks/evidence/T-03136-observability-implementation.md)
- Unit tests: [T-03137](../../docs/tasks/evidence/T-03137-observability-unit-test.md)
- Integration: [T-03138](../../docs/tasks/evidence/T-03138-observability-integration.md)
- Security review: [T-03139](../../docs/tasks/evidence/T-03139-observability-security-review.md)
- Hardening: [T-03140](../../docs/tasks/evidence/T-03140-observability-hardening.md)
- Documentation: [T-03141](../../docs/tasks/evidence/T-03141-observability-documentation.md)

## Tests

```bash
python tests/test_smoke.py
```

