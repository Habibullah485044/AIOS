# Scaffold Evidence: T-02844 — redeem-before-act gate: Scaffold

## Task Information
- **Task ID**: `T-02844`
- **Subsystem**: `Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate`
- **Title**: `redeem-before-act gate: Scaffold`
- **Status**: Completed

## Scaffold Summary
1. Scaffolded typed function signature in `code/aiosh-mcp/aiosh_mcp/audit_client.py`:
   ```python
   def grant_redeem(
       conn: sqlite3.Connection,
       grant_id: str,
       actor: str = "agent",
       actor_id: str = "agent:mcp@aiosh-mcp",
       tool: str = "",
       command: str = "",
       args: dict[str, Any] | None = None,
       target: str | None = None,
   ) -> dict[str, Any]:
       """Proof of Restraint (Layer 1): atomically redeem single-use capability token before execution."""
       raise NotImplementedError("grant_redeem scaffold stub (T-02844)")
   ```
2. Verified clean module imports:
   - `from aiosh_mcp import audit_client` imports cleanly.
   - Calling `audit_client.grant_redeem()` fails loudly with `NotImplementedError` as required by the scaffold protocol.
3. Verified capability smoke test suite green:
   - `python code/aiosh-cli/tests/test_capability_cli_smoke.py` passed with 0 errors.
