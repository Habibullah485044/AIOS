# Research Document: AI Control Plane MCP Server Core CLI Surface (T-03083)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / CLI surface
- **Focus**: Command Grammar, Flags, Exit Codes, Capability Gating, and Proof-of-Restraint Audit Ring Emission
- **Bindings**: ADR-0035 §AF-2, ADR-0037, JSON-RPC 2.0, PoR Invariant I-2

---

## 1. Executive Summary

This research establishes the command grammar, argument parsing contracts, exit code semantics, PEP capability gating, and audit emission standards for the **MCP Server Core CLI surface** (`aiosh mcp core` / `aiosh mcp`).

The MCP Server Core CLI provides operators and automated orchestrators with a native tool to inspect, invoke, and monitor Model Context Protocol tools and sessions directly from the shell without requiring a full external MCP client implementation.

The CLI interface exposes five primary capabilities:
1. **Tool Catalog Inspection** (`aiosh mcp list`): Query all registered MCP tools in the core service.
2. **Tool Definition Query** (`aiosh mcp show <tool-name>`): Retrieve schema, parameters, and authorization constraints for a specific tool.
3. **Bounded Tool Dispatch** (`aiosh mcp dispatch <tool-name>`): Dispatch invocations to registered tools with JSON arguments, capability grants, and bounded timeouts.
4. **Session Inspection & Eviction** (`aiosh mcp sessions`): List active client sessions, heartbeat times, and trigger pruning of idle or terminated sessions.
5. **Core Health Ping** (`aiosh mcp ping`): Quick non-destructive connectivity and status check.

---

## 2. Command Architecture & Grammar

```
aiosh mcp [SUBCOMMAND] [OPTIONS]

SUBCOMMANDS:
  list                List registered tools in the MCP Server Core catalog
                      Flags:
                        --filter <GLOB>         Filter tools by name glob/pattern
                        --json                  Output catalog in ADR-0035 envelope JSON format

  show <TOOL>         Inspect tool schema, parameters, and grant requirements
                      Flags:
                        --json                  Output tool definition in JSON format

  dispatch <TOOL>     Execute a tool call through the MCP Server Core service
                      Flags:
                        --args <JSON>           Tool arguments serialized as JSON (default: {})
                        --grant <TOKEN>         PEP capability grant token (mandatory for aios.admin.*)
                        --timeout <SECS>        Execution timeout in seconds (clamped [1, 300])
                        --json                  Output execution result in ADR-0035 envelope format

  sessions            Inspect active MCP client sessions and manage lifecycle
                      Flags:
                        --prune <SECS>          Evict terminated sessions and sessions idle > SECS (0 = terminated only)
                        --json                  Output session catalog in JSON format

  ping                Ping MCP Server Core service health and active counters
                      Flags:
                        --json                  Output health status in JSON format
```

---

## 3. Exit Code Taxonomy

| Exit Code | Constant / Meaning | Description |
| :--- | :--- | :--- |
| `0` | `EXIT_SUCCESS` | Command completed successfully, envelope returned `ok: true` |
| `1` | `EXIT_FAILURE` | Tool or session not found, or dispatch returned an error |
| `2` | `EXIT_USAGE` | Invalid CLI arguments, missing tool name, or malformed JSON payload |
| `3` | `EXIT_UNAUTHORIZED` | Capability grant missing or rejected by PEP for privileged administrative tool |
| `4` | `EXIT_TIMEOUT` | Tool execution exceeded clamped timeout boundary |

---

## 4. Capability Gating & Proof-of-Restraint (PoR) Emission

In conformance with **PoR Invariant I-2** and **ADR-0035 §AF-2**:
1. **Privileged Tool Execution**:
   Any invocation of tools in the `aios.admin.*` namespace (e.g., `aios.admin.restart`, `aios.admin.flush`) requires an explicit `--grant <TOKEN>`. Invoking without `--grant` fails closed with exit code `3` (`EXIT_UNAUTHORIZED`).
2. **Audit Ring Event Emission**:
   Every CLI command commits an immutable audit record to `audit.db` via `AuditRing`:
   - Event: `mcp.core.list`, `mcp.core.show`, `mcp.core.dispatch`, `mcp.core.sessions`, `mcp.core.ping`
   - Payload: records tool name, target session, operator identity, exit status, and grant token reference.

---

## 5. Substrate Implementation Strategy

- **Rust Userspace Binary**: `code/aiosh-rust/aiosh-cli/src/main.rs` (adds `mcp` subcommand handler).
- **Python Fabric / FastMCP**: `code/aiosh-mcp/aiosh_mcp/server.py` and `code/aiosh-mcp/aiosh_mcp/mcp_server_core_service.py` provide backend handlers.
- **Data Model & Service Parity**: Leverages `aiosh_core::mcp_server_core_service::McpServerCoreService` and `aiosh_core::mcp_server_core_data_model::*`.

---

## 6. Security Analysis & Abuse Cases

- **AC-1 (Argument Injection / Oversized JSON)**: Tool arguments passed via `--args` are validated against `MAX_ARGUMENTS_SIZE = 1 MiB` before parsing.
- **AC-2 (Privilege Escalation Bypass)**: Administrative tools are checked against namespace prefix and grant token validation before dispatch.
- **AC-3 (DoS via Infinite Timeout)**: Execution timeouts passed via `--timeout` are clamped strictly to `[1, 300]` seconds.
- **AC-4 (Session Table Exhaustion)**: `sessions --prune` provides a secure mechanism for operators to reclaim capacity without restarting the service.
