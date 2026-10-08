# T-02895 — Compliance Mapping / MCP-API Surface: Scaffold

**Status**: COMPLETE (2026-10-08)  
**Full evidence**: [T-02895-scaffold.md](T-02895-scaffold.md)

Created `aiosh_mcp/compliance.py` (typed interfaces, loud-fail bodies, Rust-parity constants), wired the `aios.compliance` MCP tool in `server.py`, and added 10 test stubs (5 structural green, 5 behavioral loud-fail for T-02896). Imports/build clean; PoR battery 77/1 and conformance battery CONFORMANT after fixing an incidental fixture grant-expiry time-bomb (`2199-12-31T23:59:59Z`).
