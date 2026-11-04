# T-03323 Research: Agent Loop Hardening — security policy

- Date: 2026-11-05
- Scope: research only. **No code changed.**

## Facts (verified)
| # | Fact | Source |
|---|---|---|
| F1 | MCP dispatch applies **two** gates before any tool runs. Gate #1 is the Constitution C-1..C-4 classifier (`classifier.classify`): verdict `refused` blocks, with confidence >= 0.95. Gate #2 is the PEP grant. Each refusal row records `c_flags`, `policy_revision`, `classify_rule_ids`, `classify_evidence`, `classify_overall_verdict` and `classify_verdict_reason`. | `aiosh_mcp/_dispatch.py:107-200` |
| F2 | Agent-loop steps apply **only Gate #2** (grant scope, paths/networks, revocation). The classifier never runs, so a step the constitution would refuse (e.g. destructive, sovereignty or PI-scan rules) is recorded as `ok`. | `agent_loop_service._advance_locked`, `agent_loop_gate.tool_refusal` |
| F3 | Step audit rows hard-code `c_flags {c1..c3: false, c4: true}` and leave every `classify_*` column NULL. The ring therefore cannot show **which constitutional rules a step touched**, which breaks the cross-link invariant `_dispatch` documents ("the agent loop reads audit_id ... cross-link agent step N"). | `agent_loop_gate.py:153` |
| F4 | `aiosh grant create --max-irreversible N` stores `scope.max_irreversible` (TS `cli.ts:737`, Rust `main.rs:9187`, `pep.rs:792`). **No substrate enforces it.** Nothing in TS, Rust or Python reads it back. An operator setting a budget gets none. | repo-wide grep |
| F5 | "Irreversible" is already defined consistently: `audit_client.grant_check` (`pentest.*`, `fs.write*`, `system.reboot/shutdown`) and the classifier's C-3 flag. | `audit_client.py:415+`, `classifier.cFlagsFor` |
| F6 | `classify()` is pure and deterministic (rule pack `CLASSIFIER_REVISION = "sprint-2-rule-pack-v1"`). The TS mirror is kept in lockstep by `tests/test_classifier_smoke.py`. Reusing it adds no new policy source. | `classifier.py:1-25` |

## Upstream references
- ADR-0035 §D-4 (classifier before dispatch); `docs/SPEC-CONSTITUTION-CLASSIFIER.md` §4 (cross-language invariant)
- NIST SP 800-53 AC-6 (least privilege) and SI-10 (input validation) as framing for per-step policy: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- OWASP Top 10 for LLM Applications 2025, LLM06 "Excessive Agency" (agents need per-action policy, not just per-session grants): https://genai.owasp.org/llmrisk/llm062025-excessive-agency/

## Assumptions
- A1: Callers that pass `tool_args` give a representative target (`target`/`path`/`host`), as the scope check already assumes (T-03321 §7).
- A2: Applying the same classifier as dispatch costs well under 1 ms per step (it is pure regex/rule matching).

## Decisions needed (for T-03324)
- D1: Run `classifier.classify(tool, target, args)` on every loop step **before** the grant check. Verdict `refused` refuses the step,
  with reason `LOOPPOL_ERR_CONSTITUTION` and the rule ids. (Recommended: parity with dispatch Gate #1.)
- D2: Record the real `c_flags` and all `classify_*` fields on every step row, ok and refused alike. (Recommended: F3.)
- D3: Enforce `scope.max_irreversible` per bound grant. Count steps that are irreversible (F5 definition or C-3) and refuse once the
  budget is spent (`LOOPPOL_ERR_IRREVERSIBLE_BUDGET`). (Recommended: closes F4 for agent loops. Enforcing it in dispatch/TS/Rust is a separate cross-substrate change; to be listed as a follow-up.)
- D4: Policy checks must not be configurable off (consistent with LOCKED_KEYS), and must not change the documented error codes of existing paths.
