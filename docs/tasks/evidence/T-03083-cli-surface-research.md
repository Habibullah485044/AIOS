# Evidence Pointer: T-03083

Please refer to [T-03083-research.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03083-research.md) for full research findings on the AI Control Plane MCP Server Core CLI surface (`aiosh mcp`).

## Summary of Findings
- Established command grammar: `aiosh mcp list`, `show`, `dispatch`, `sessions`, and `ping`.
- Mapped exit codes 0..4 (`SUCCESS`, `FAILURE`, `USAGE`, `UNAUTHORIZED`, `TIMEOUT`).
- Codified capability grant gating (`--grant`) on `aios.admin.*` tools in compliance with PoR Invariant I-2.
- Enforced ADR-0035 §AF-2 result envelope formatting and immutable audit ring row emission across all commands.
