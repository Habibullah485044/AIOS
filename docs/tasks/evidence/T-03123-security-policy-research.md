# Research & Security Audit Evidence: AI Control Plane MCP Server Core Security Policy (T-03123)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / security policy
- **Target**: Comprehensive facts, constraints, security policy architecture, and prior art for MCP Server Core Policy Enforcement
- **Bindings**: ADR-0035 §D-2, ADR-0035 §F-2, PoR Invariant I-2, ADR-0035 §AE-1

---

## 1. Facts, Constraints, and Prior Art

### 1.1 Established Facts (Authoritative)
1. **MCP Policy Scope**:
   - Model Context Protocol tools and resource endpoints expose system capabilities to AI agents.
   - MCP Server Core acts as a Policy Enforcement Point (PEP) ensuring all tool dispatches and resource reads adhere to declarative security policies.
2. **Policy Evaluation Model**:
   - Every tool call evaluates:
     - Principal identity & role (e.g., `anonymous`, `agent:read-only`, `agent:operator`, `admin`).
     - Action category (e.g., `read_only`, `diagnostics`, `state_changing`, `administrative`).
     - Target resource / scope (e.g., `.aios/`, system config, external process).
     - Capability token verification: Privileged/consequential actions (`state_changing`, `administrative`) strictly mandate an unexpired, cryptographically validated capability token (PoR Invariant I-2).
3. **Audit Ring Invariant**:
   - Any policy evaluation (both `ALLOW` and `DENY`) writes an immutable audit record to the SQLite WAL audit ring.
   - Fail-closed behavior by default: unrecognized actions or missing tokens evaluate to `DENY` and trigger an auditable security event (ADR-0035 §F-2).
4. **Dual-Substrate Implementation**:
   - Python substrate (`aiosh_mcp`): FastMCP policy decorator/filter and policy evaluator.
   - Rust substrate (`aiosh-core`): Constant-time evaluation, policy rule compiler, and canonical token validation.

### 1.2 Identified Constraints
1. **Zero Escalation (Invariant I-2)**: No tool call classified as `state_changing` or `administrative` may proceed without validating a capability token.
2. **Deterministic Evaluation**: Policy rules must be evaluated in strict priority order (DENY overrides ALLOW, explicit rule > default fallback).
3. **Bounded Overhead**: Policy evaluation must execute within $<1\text{ ms}$ to avoid adding latency to high-frequency MCP tool dispatches.
4. **Memory & Payload Limits**: Policy rules and metadata must be bounded (maximum 256 rules per policy engine, rule names $\le 64$ characters).

---

## 2. Policy Model Architecture

The security policy engine for MCP Server Core consists of:
1. **PolicyRule**:
   - `rule_id`: Unique identifier (e.g., `rule:deny-unauthenticated-admin`).
   - `role`: Target subject role or glob (`*`, `agent:*`, `admin`).
   - `tool_pattern`: Tool name pattern (e.g., `aios_mcp_*`, `aios.admin.*`).
   - `action`: Evaluation decision (`ALLOW`, `DENY`, `REQUIRE_CAPABILITY`).
   - `priority`: Integer priority (higher priority evaluated first).
2. **PolicyEngine**:
   - Compiles and evaluates rules against an incoming context `(subject, tool_name, arguments, capability_token)`.
   - Generates an immutable `PolicyDecision` envelope containing decision status, matching rule ID, and reason.
3. **PEP Integration Gate**:
   - Hooks into `aiosh_mcp.server` and `mcp_server_core_service.py` to intercept all dispatch calls before execution.

---

## 3. Decisions & Implementation Roadmap

- **Decision 1**: Implement `McpServerCorePolicyEngine` in `code/aiosh-mcp/aiosh_mcp/mcp_server_core_policy.py` and `code/aiosh-rust/aiosh-core/src/mcp_server_core_policy.rs`.
- **Decision 2**: Ensure strict default-deny when no rule matches an administrative tool, and require capability tokens for all consequential operations.
- **Decision 3**: No external dependencies required; utilize standard library in Python (`dataclasses`, `re`, `enum`) and Rust standard library (`serde`, `regex`).
