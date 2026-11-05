# T-03361 Evidence: Agent Loop Hardening — recovery & validation Documentation

- Date: 2026-11-06
- Doc updated: [`docs/SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE.md` §5d](../../SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE.md), plus §6 (`LOOPREC_ERR_READ` wording, `LOOPREC_ERR_WRITE` added in T-03360) and §8 evidence links.

## What §5d now documents
- The **orphan rule** as shipped in T-03359: not live here, idle past `grace_s`, **and** past the run's own `total_timeout_ms` (clamped 5 s..1800 s) + 1 s.
- Validate: MCP `aios_agent_loop_validate(grace_s, verify_chain)` and CLI `validate-ring [--grace] [--chain] [--json]`. The 50 000-row window, the 10 s budget, opt-in chain check (`chain_ok: null` when unchecked), all problem kinds including `budget_invalid`, hashed grant ids.
- Recover: MCP `aios_agent_loop_recover` and CLI `recover --token-env`; the **exact** `aios.agent_loop.recover` scope (globs refused); the newest-row re-check under the write lock; a recovered run's process stops with `LOOPSERV_ERR_TERMINATED`; `LOOPREC_ERR_WRITE` with `data.recovered` partial results; the bounded lock wait, with the grant not consumed.
- A **copy-pasteable Python example** (crash, not yet orphaned, wait past timeout, orphaned, recover, validate with chain), and a JSON MCP tool call.
- **Limitations, stated:** recovery is bounded by the total timeout (no heartbeat); the 50 000-row window; full-chain cost; server-local liveness; a single-use recovery grant is consumed even with nothing to recover.

## Verification
The drift test executes every `python` block in the doc and validates every JSON tool call against the live schema:
```
python -m pytest tests/ -k "doc_drift or agent_loop_doc" -q
25 passed, 1411 deselected, 1 warning in 15.80s
```
Running the new example on its own printed `0`, `1`, `1`, `True`, matching the `# ->` comments in the doc.
