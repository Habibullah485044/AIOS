# T-02893 — Compliance Mapping / MCP-API Surface: Research

**Status**: COMPLETE (2026-10-08)  
**Full evidence**: [T-02893-research.md](T-02893-research.md)

Research for the Compliance Mapping MCP/API surface. Facts collected from MCP spec 2025-06-18 / JSON-RPC 2.0 / MCP Python SDK (citations) and from the repo: existing `aios.*` MCP conventions (`_recorded_call` audit envelope, PEP grant gating), the Rust `ComplianceService`/`ComplianceMappingEntry` substrate (`docs/compliance_map.json` store, 6 frameworks, status state machine), and the `aiosh compliance` CLI. Four assumptions flagged; eight decisions queued for the Specification task (tool granularity, authority model, canonical store contract, error mapping, annotations, structured output, registry smoke, bounds parity). No code changed.
