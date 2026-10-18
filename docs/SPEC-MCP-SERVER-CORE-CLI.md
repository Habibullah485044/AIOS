# Specification: AI Control Plane MCP Server Core CLI Surface

**Document ID**: SPEC-MCP-SERVER-CORE-CLI  
**Lifecycle Target**: T-03083..T-03092 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / CLI surface)  
**Contract Reference**: ADR-0035 §AF-2, ADR-0037, RFC-MCP-CORE-CLI-001, PoR Invariant I-2  
**Status**: ACTIVE  

---

## 1. Overview & Architectural Role

The **MCP Server Core CLI Surface** (`aiosh mcp`) provides userspace and operational tooling to inspect, invoke, and monitor Model Context Protocol (MCP) tools and sessions within the AIOS environment.

The CLI interface links userspace commands directly with `McpServerCoreService` and the `AuditRing` audit trail, guaranteeing fail-closed capability verification and cryptographic proof-of-restraint logging.

Both Rust (`aiosh-core::mcp_server_core_cli` / `aiosh-cli`) and Python (`aiosh_mcp.mcp_server_core_cli`) runtimes implement this specification with cross-platform behavioral parity.

---

## 2. Command Architecture & Grammar

```
aiosh mcp [SUBCOMMAND] [OPTIONS]

SUBCOMMANDS:
  list                List registered tools in the MCP Server Core catalog
                      Flags:
                        --filter <GLOB>         Filter tools by name pattern
                        --json                  Output catalog in JSON format

  show <TOOL>         Inspect tool schema, parameters, and grant requirements
                      Flags:
                        --json                  Output tool definition in JSON format

  dispatch <TOOL>     Execute a tool call through the MCP Server Core service
                      Flags:
                        --args <JSON>           Tool arguments serialized as JSON (default: {})
                        --grant <TOKEN>         PEP capability grant token (mandatory for aios.admin.*)
                        --timeout <SECS>        Execution timeout in seconds (clamped [1, 300])
                        --json                  Output execution result in JSON format

  sessions            Inspect active MCP client sessions and manage lifecycle
                      Flags:
                        --prune <SECS>          Evict terminated sessions and sessions idle > SECS (0 = terminated only)
                        --json                  Output session catalog in JSON format

  ping                Ping MCP Server Core service health and active counters
                      Flags:
                        --json                  Output health status in JSON format
```

---

## 3. Invariants Certified

- **MCPCLI-INV1 (Deterministic Exit Code Mapping)**:
  - `0`: Success (`EXIT_SUCCESS`)
  - `1`: Tool/session not found or dispatch failure (`EXIT_FAILURE`)
  - `2`: Invalid command line usage, syntax error, or unparseable JSON argument (`EXIT_USAGE`)
  - `3`: Unauthorized; missing or denied capability grant for privileged tool (`EXIT_UNAUTHORIZED`)
  - `4`: Timeout; dispatch execution exceeded timeout boundary (`EXIT_TIMEOUT`)
- **MCPCLI-INV2 (Bounded Wire Payloads & Hardened Sanitization)**:
  Tool arguments passed via `--args` are validated against `MAX_ARGUMENTS_SIZE = 1 MiB`. Timeouts are clamped to `[1s, 300s]`. NUL byte rejection is enforced across all options, arguments, and subcommands.
- **MCPCLI-INV3 (Fail-Closed Capability Enforcement)**:
  Invocations of tools under the `aios.admin.*` namespace strictly require `--grant <token>`. Absence of a valid grant terminates before tool invocation with exit code 3.
- **MCPCLI-INV4 (ADR-0035 §AF-2 Result Envelope)**:
  When `--json` is specified, all outputs (successes and errors) return an ADR-0035 envelope (`status`, `ok`, `data`/`json_payload`, `error_code`, `error_message`).
- **MCPCLI-INV5 (Proof-of-Restraint Audit Emission)**:
  Every invocation of `aiosh mcp` emits an immutable audit event (`mcp.core.list`, `mcp.core.show`, `mcp.core.dispatch`, `mcp.core.sessions`, `mcp.core.ping`) into `audit.db` via `AuditRing`.

---

## 4. Usage Examples

```bash
# 1. Ping MCP Server Core health probe
aiosh mcp ping --json

# 2. List all registered MCP tools matching a filter
aiosh mcp list --filter "aios.fs.*" --json

# 3. Inspect a specific tool schema and parameter constraints
aiosh mcp show aios.fs.read --json

# 4. Dispatch a tool call with input payload
aiosh mcp dispatch aios.fs.read --args '{"path":"/tmp/sample.txt"}' --json

# 5. Dispatch a privileged tool call with explicit capability grant
aiosh mcp dispatch aios.admin.reboot --grant "gr_admin_token_123" --json

# 6. Enumerate and prune terminated / expired client sessions
aiosh mcp sessions --prune 60 --json
```

---

## 5. Constraints & Known Limitations

1. **Process Boundary**: The current CLI implementation executes against the local service registry in-process or daemon-backed. Networked transport endpoints (stdio / SSE / JSON-RPC over HTTP) are handled by the MCP/API Surface (`T-03093..T-03102`).
2. **Payload Size Limit**: Argument payloads passed on the command line are constrained to `MAX_ARGUMENTS_SIZE = 1 MiB` (`1,048,576 bytes`) to prevent buffer bloat.
3. **Execution Timeout Boundary**: Execution timeouts are bounded strictly to `[1, 300]` seconds.
4. **Grant Token Validation**: The CLI verifies token presence and delegates signature verification to PEP/Proof-of-Restraint gatekeeper; revocations are enforced at redemption time.

---

## 6. Lifecycle Evidence Links

- **T-03083 (Research)**: [`docs/tasks/evidence/T-03083-research.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03083-research.md)
- **T-03084 (Specification)**: [`docs/tasks/evidence/T-03084-spec.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03084-spec.md)
- **T-03085 (Scaffold)**: [`docs/tasks/evidence/T-03085-scaffold.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03085-scaffold.md)
- **T-03086 (Implementation)**: [`docs/tasks/evidence/T-03086-impl.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03086-impl.md)
- **T-03087 (Unit Test)**: [`docs/tasks/evidence/T-03087-unit-test.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03087-unit-test.md)
- **T-03088 (Integration)**: [`docs/tasks/evidence/T-03088-integration.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03088-integration.md)
- **T-03089 (Security Review)**: [`docs/tasks/evidence/T-03089-security.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03089-security.md)
- **T-03090 (Hardening)**: [`docs/tasks/evidence/T-03090-cli-surface-hardening.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03090-cli-surface-hardening.md)
- **T-03091 (Documentation)**: [`docs/tasks/evidence/T-03091-cli-surface-documentation.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03091-cli-surface-documentation.md)
