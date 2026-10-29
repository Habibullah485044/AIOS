# T-03275 Evidence: Agent Loop Hardening Core Service Scaffold

## Task Metadata
- Task ID: T-03275
- Title: Phase 3 — AI Control Plane (Pillar C Spine) / Agent Loop Hardening / core service: Scaffold
- Status: Completed
- Date: 2026-10-30

## Overview
Created module skeleton, error taxonomy, and interface definitions for the Agent Loop Hardening core service in `code/aiosh-mcp/aiosh_mcp/agent_loop_service.py`.

## Interfaces Created
1. `AgentLoopServiceError`: Typed exception with standard error code, sanitized error message (`mask_secrets`), and optional `loop_id`.
2. Error Codes: `LOOPSERV_ERR_NOT_FOUND`, `LOOPSERV_ERR_ALREADY_EXISTS`, `LOOPSERV_ERR_TERMINATED`, `LOOPSERV_ERR_UNAUTHORIZED`, `LOOPSERV_ERR_POLICY_REFUSED`, `LOOPSERV_ERR_TIMEOUT`, `LOOPSERV_ERR_CIRCUIT_BREAKER`.
3. `AgentLoopService`:
   - `start_loop(config, capability_token)`: Scaffold enforcing token presence and config bounds.
   - `advance_turn(...)`: Scaffold enforcing token presence and turn parameters.
   - `abort_loop(loop_id, reason, capability_token)`: Scaffold enforcing token presence.
   - `get_snapshot(loop_id)`: Read-only query returning `LoopSnapshot`.
   - `list_active_loops()`: Lists active non-terminated loops.
4. Exported `agent_loop_service` in `code/aiosh-mcp/aiosh_mcp/__init__.py`.

## Verification & Test Results
- Scaffold test: `code/aiosh-mcp/tests/test_agent_loop_core_service_scaffold.py`
- Command: `python -m pytest code/aiosh-mcp/tests/test_agent_loop_core_service_scaffold.py`
- Result: 3 passed in 0.52s.
