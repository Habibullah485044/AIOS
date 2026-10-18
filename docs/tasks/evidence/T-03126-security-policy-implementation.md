# Implementation Evidence: AI Control Plane MCP Server Core Security Policy (T-03126)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / security policy
- **Artifact**: `docs/tasks/evidence/T-03126-security-policy-implementation.md`
- **Key Code**:
  - `code/aiosh-mcp/aiosh_mcp/mcp_server_core_policy.py`
  - `code/aiosh-rust/aiosh-core/src/mcp_server_core_policy.rs`
  - `code/aiosh-mcp/tests/test_mcp_server_core_policy_impl.py`

---

## 1. Implementation Highlights

1. **Default Policy Rules Engine**:
   - Implemented `load_default_policy` populating 5 baseline rules in strict priority order (400 down to 100).
   - Explicit `DENY` for anonymous attempts to invoke `aios.admin.*`.
   - Invariant I-2 mandatory capability token gating for all `STATE_CHANGING` and `ADMINISTRATIVE` actions.
   - Default permit for `READ_ONLY` and `DIAGNOSTICS` tools.
2. **Audit Envelope Integration**:
   - `create_audit_entry()` formats standard event records for WAL audit ring consumption under `mcp.policy.evaluate`.
3. **Cross-Substrate Parity**:
   - Byte-identical evaluation semantics and priority resolution across Python and Rust substrates.

---

## 2. Test Verification

- Executed `test_mcp_server_core_policy_impl.py`:
  - Verified read-only tool allow without token.
  - Verified state-changing denied when token absent.
  - Verified state-changing allowed when valid token supplied.
  - Verified anonymous admin attempt strictly denied.
- Result: `1 passed in 0.32s`.
