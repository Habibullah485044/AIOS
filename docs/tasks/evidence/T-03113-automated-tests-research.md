# Research & Security Audit Evidence: AI Control Plane MCP Server Core Automated Tests (T-03113)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / automated tests
- **Target**: Comprehensive facts, constraints, testing taxonomy, and architectural decisions for automated tests
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MCP-SERVER-CORE-API

---

## 1. Facts, Constraints, and Prior Art

### 1.1 Established Facts (Authoritative)
1. **MCP Wire Standard**: Model Context Protocol specification pinned at `2025-06-18` per ADR-0035 §D-2. All wire interactions use JSON-RPC 2.0 framing over stdio transport.
2. **Error Codes**: Adheres to JSON-RPC 2.0 standard codes (`-32700` parse error, `-32600` invalid request, `-32601` method not found, `-32602` invalid params, `-32603` internal error) and AIOS custom extensions (`-32001` timeout, `-32002` unauthorized, `-32003` bounds exceeded).
3. **Dual-Substrate Architecture**:
   - Python substrate (`aiosh_mcp`): FastMCP runtime, API adapter, core service, configuration, and diagnostic tools.
   - Rust substrate (`aiosh-core`): High-performance core library implementation with byte-identical canonical JSON serialization, cryptographic audit chaining, and configuration validation.
4. **Proof-of-Restraint Enforcement**: Privileged tools (`aios.admin.*`) strictly require capability tokens; every consequential dispatch writes an immutable record to the SQLite WAL audit ring.

### 1.2 Identified Constraints
1. **Test Isolation**: All automated tests must execute in isolated temporary environments (`tmp_path`) to prevent polluting production `.aios/` stores.
2. **Determinism**: Automated tests must be 100% deterministic, avoiding network dependencies or external daemon reliance.
3. **Strict Bounds Checking**: Test suites must assert bounds violation behavior (e.g., payloads > 1 MiB, sessions > 512, timeouts > 300s).

---

## 2. Testing Taxonomy & Coverage Architecture

The automated test suite for MCP Server Core is structured into four distinct test layers:
1. **Layer 1: Unit Test Matrix**:
   - Pure function and schema validation for data models, API envelopes, and configuration invariants.
2. **Layer 2: Service & Dispatch Battery**:
   - Session lifecycle, registry limits, safe dispatch timeouts, and error handling.
3. **Layer 3: Wire & Protocol Integration**:
   - FastMCP tool invocation, JSON-RPC 2.0 request/response parsing, and stdio framing.
4. **Layer 4: Security & Fuzzing Battery**:
   - NUL byte injection, directory traversal (`..`), payload bomb / memory denial of service, and capability token bypass attempts.

---

## 3. Decisions & Implementation Roadmap

- **Decision 1**: Implement a unified automated test coordinator (`mcp_server_core_tests.py` and `mcp_server_core_tests.rs`) providing programmatic runners and test reporting.
- **Decision 2**: Ensure test reports adhere to standard JSON result envelopes for CI and automated auditing consumption.
- **Decision 3**: No external dependencies added; utilize `pytest` in Python and standard `cargo test` in Rust.
