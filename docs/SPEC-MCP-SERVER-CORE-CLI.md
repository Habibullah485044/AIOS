# Specification: AI Control Plane MCP Server Core CLI Surface

**Document ID**: SPEC-MCP-SERVER-CORE-CLI  
**Lifecycle Target**: T-03083..T-03092 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / CLI surface)  
**Contract Reference**: ADR-0035 §AF-2, ADR-0037, RFC-MCP-CORE-CLI-001  
**Status**: ACTIVE  

---

## 1. Overview & Architectural Role

The **MCP Server Core CLI Surface** (`aiosh mcp`) provides userspace and operational tooling to inspect, invoke, and monitor Model Context Protocol tools and sessions within the AIOS environment.

The CLI interface links userspace commands directly with `McpServerCoreService` and the `AuditRing` audit trail, guaranteeing fail-closed capability verification and cryptographic proof-of-restraint logging.

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
- **MCPCLI-INV2 (Bounded Wire Payloads & Sanitization)**:
  Tool arguments passed via `--args` are validated against `MAX_ARGUMENTS_SIZE = 1 MiB`. Timeouts are clamped to `[1s, 300s]`. All output strings are sanitized against ANSI injection.
- **MCPCLI-INV3 (Fail-Closed Capability Enforcement)**:
  Invocations of tools under the `aios.admin.*` namespace strictly require `--grant <token>`. Absence of a grant terminates before tool invocation with exit code 3.
- **MCPCLI-INV4 (ADR-0035 §AF-2 Result Envelope)**:
  When `--json` is specified, all outputs return an ADR-0035 envelope (`status`, `ok`, `data`, `error_code`, `error_message`, `timestamp`).
- **MCPCLI-INV5 (Proof-of-Restraint Audit Emission)**:
  Every invocation of `aiosh mcp` emits an immutable audit event (`mcp.core.list`, `mcp.core.show`, `mcp.core.dispatch`, `mcp.core.sessions`, `mcp.core.ping`) into `audit.db` via `AuditRing`.

---

## 4. Usage Examples

```bash
# List all registered MCP tools
aiosh mcp list

# Inspect a specific tool's JSON schema
aiosh mcp show aios.fs.read --json

# Dispatch a tool call
aiosh mcp dispatch aios.fs.read --args '{"path":"/tmp/sample.txt"}' --json

# Dispatch a privileged tool call with capability token
aiosh mcp dispatch aios.admin.restart --grant "gr_admin_token_123" --json

# Inspect active client sessions and prune terminated ones
aiosh mcp sessions --prune 0 --json

# Check server health
aiosh mcp ping --json
```
