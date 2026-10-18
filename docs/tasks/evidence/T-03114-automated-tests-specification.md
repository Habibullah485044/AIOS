# Specification & Security Audit Evidence: AI Control Plane MCP Server Core Automated Tests (T-03114)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / automated tests
- **Target**: Detailed contract specification, invariant rules (`MCPTEST-INV1..MCPTEST-INV6`), and report envelopes
- **Specification Document**: [SPEC-MCP-SERVER-CORE-TESTS.md](../../SPEC-MCP-SERVER-CORE-TESTS.md)

---

## 1. Specification Summary

The specification establishes a unified test runner and reporting engine for MCP Server Core:
1. **Core Invariants**:
   - `MCPTEST-INV1`: Temporary harness isolation with deterministic cleanup.
   - `MCPTEST-INV2`: Complete execution determinism without ambient network dependencies.
   - `MCPTEST-INV3`: Full 4-pillar coverage across Data Model, Wire API, Service Dispatch, and Configuration.
   - `MCPTEST-INV4`: Dedicated security fuzzing (traversal, NUL injection, bounds overflow, token verification).
   - `MCPTEST-INV5`: Standardized `McpTestSuiteReport` envelope.
   - `MCPTEST-INV6`: Cross-substrate behavioral equivalence between Python and Rust.

2. **Data Contracts**:
   - `McpTestCase`: Individual test case record with execution status, timing, and error details.
   - `McpTestSuiteReport`: Structured audit envelope reporting overall test health, duration, and case inventory.

---

## 2. Security Audit & Review

- **Security Verification**: Automated test runners run with strictly unprivileged mock contexts. Any administrative tests execute with simulated ephemeral grant tokens that are invalidated immediately after assertion.
- **Fail-Safe Envelope**: On assertion or unhandled test runner exception, the runner traps the error, records `passed=False`, and reports the error in `McpTestSuiteReport` without aborting the audit trail.
- **Proof-of-Restraint Alignment**: Invariant `MCPTEST-INV4` explicitly checks PoR Invariant I-2 compliance (refusal of `aios.admin.*` actions without grant tokens).
