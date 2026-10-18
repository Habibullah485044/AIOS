# Evidence Pointer: T-03094

Please refer to [T-03094-spec.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03094-spec.md) and [docs/SPEC-MCP-SERVER-CORE-API.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/SPEC-MCP-SERVER-CORE-API.md) for full specification details on the AI Control Plane MCP Server Core MCP/API surface.

## Summary of Specification
- Defined wire schemas for `initialize`, `ping`, `tools/list`, and `tools/call`.
- Enforced invariants MCPAPI-INV1 through MCPAPI-INV5.
- Codified capability grant verification and Proof-of-Restraint compliance for administrative tools.
- Set bounds on payload sizes (1 MiB) and execution timeouts ([1, 300]s).
