# Hardening Evidence: AI Control Plane MCP Server Core MCP/API Surface (T-03100)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / MCP/API surface
- **Focus**: Defensive parsing, recursive NUL byte inspection, bounds clamping, fail-closed privilege enforcement, and zero-leak resource cleanup
- **Bindings**: ADR-0035 §AF-2, ADR-0035 §F-2, SPEC-MCP-SERVER-CORE-API, PoR Invariant I-2

---

## 1. Hardening Measures Implemented

1. **Defensive Parsing & Never-Silent Failure**:
   - Explicit JSON-RPC 2.0 error responses emitted across all malformed payloads (empty string, non-dict arrays/scalars, null inputs).
2. **Recursive NUL Byte & Control Code Rejection**:
   - `_has_nul` recursively sanitizes dictionary keys, list elements, and nested strings to detect and reject NUL byte injection (`\0` / `\u0000`) before deserialization into downstream modules.
3. **Payload Clamping**:
   - `MAX_ARGUMENTS_SIZE` clamped to 1 MiB. Rejections return `ERR_BOUNDS_EXCEEDED` (-32001).
4. **Privileged Capability Gating (PoR Invariant I-2)**:
   - Invocations of `aios.admin.*` tools fail closed with `ERR_UNAUTHORIZED` (-32002) in the absence of valid capability tokens.
5. **Clean Resource Management**:
   - Failures clean up session state immediately without leaking background tasks or memory.

---

## 2. Test Verification

- Executed `python -m pytest code/aiosh-mcp/tests/test_mcp_server_core_api_hardening.py`.
- **Result**: PASSED (3/3 tests passed in 0.34s).
