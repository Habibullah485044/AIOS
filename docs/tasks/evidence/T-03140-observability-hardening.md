# Hardening Evidence: AI Control Plane MCP Server Core Observability (T-03140)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / observability
- **Artifact**: `docs/tasks/evidence/T-03140-observability-hardening.md`
- **Test File**: `code/aiosh-mcp/tests/test_mcp_server_core_observability_hardening.py`

---

## 1. Hardening Defenses Applied

1. **Telemetry Text Sanitization (`sanitize_telemetry_text`)**:
   - Rejects/filters ASCII control codes (`ord < 32` or `127`) and embedded NUL bytes.
   - Filters zero-width Unicode characters (`\u200b`, `\u200c`, `\u200d`, `\ufeff`).
   - Caps strings at `MAX_TELEMETRY_TEXT_LEN = 256` characters.
2. **Division-by-Zero Defense & Range Bounds**:
   - Zero-guarded calculations for capacity percentages and average latency when `total_dispatches == 0` or `max_capacity == 0`.
   - Guaranteed IEEE-754 finite values across all numeric fields.
3. **Fail-Closed Envelope Reporting**:
   - Diagnostic tools catch and report errors in standard envelopes without crashing the FastMCP daemon.

---

## 2. Hardening Test Execution

```
code/aiosh-mcp/tests/test_mcp_server_core_observability_hardening.py .. [100%]
============================== 2 passed in 0.33s ==============================
```
