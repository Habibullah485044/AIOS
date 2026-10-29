# T-03269 Security Review: Agent Loop Hardening Data Model

## Scope & Target
- Target: `code/aiosh-mcp/aiosh_mcp/agent_loop_data_model.py`
- MCP Surface: `aios_agent_loop_status`, `aios_agent_loop_init`
- Standards: ADR-0035 §D-2, Proof-of-Restraint Invariant I-2, CWE-20, CWE-400, CWE-532

---

## Threat Matrix & Abuse Scenarios

| Scenario ID | Attack Vector | Risk | Mitigation | Status |
|-------------|---------------|------|------------|--------|
| SEC-LOOPDATA-01 | Identifier injection / ReDoS via `loop_id` (`../../`, shell meta, regex explosive) | High | `LOOP_ID_PATTERN` strictly restricts `loop_id` to `^[a-zA-Z0-9_\-]{8,64}$`, rejecting special characters, paths, spaces, and unbounded lengths. | Mitigated |
| SEC-LOOPDATA-02 | Unauthorized loop creation / memory starvation (DDoS) | High | Mutating path `aios_agent_loop_init` strictly enforces PoR Invariant I-2 requiring capability token redemption (`LOOPDATA_ERR_UNAUTHORIZED` fail-closed). | Mitigated |
| SEC-LOOPDATA-03 | Credential leakage in tool arguments or error traces | Critical | `mask_secrets` sanitizes all `tool_args_summary`, `error_message`, and `terminal_reason` strings before serialization, masking `sk-*`, `ghp_*`, and `Bearer *` patterns. | Mitigated |
| SEC-LOOPDATA-04 | Runaway execution / token exhaustion denial-of-wallet | High | `LOOPDATA-INV3` circuit breakers enforce upper limits on `max_iterations`, `max_total_tokens`, and `consecutive_failure_limit`, halting into `FAILED` state immediately upon threshold breach. | Mitigated |
| SEC-LOOPDATA-05 | Replay or out-of-order step injection | Medium | `LOOPDATA-INV1` asserts contiguous monotonic step indexing (`step[i].step_index == i`). Replays or skip-ahead indices raise `AssertionError` fail-closed. | Mitigated |
| SEC-LOOPDATA-06 | Negative token metric manipulation | Medium | `LOOPDATA-INV2` enforces strict token non-negativity and exact token conservation (`total_tokens_used == sum(steps.tokens_consumed)`). | Mitigated |

---

## Proof-of-Restraint (PoR) Verification (Invariant I-2)
- **State-Changing Paths**: `aios_agent_loop_init` modifies global in-memory loop registry and creates new FSM instances.
- **Capability Token Enforcement**: Verified that `aios_agent_loop_init` without `capability_token` fails immediately with `LOOPDATA_ERR_UNAUTHORIZED`.
- **Read-Only Paths**: `aios_agent_loop_status` inspects existing loop state without state mutations and consumes 0 capability tokens.

---

## Conclusion
The security review confirmed no open vulnerabilities or policy bypasses. The agent loop hardening data model satisfies all security constraints and Proof-of-Restraint invariants.
