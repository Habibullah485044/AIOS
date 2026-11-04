# T-03324 Specification: Agent Loop Hardening — security policy

- Date: 2026-11-05
- Adopts T-03323 D1..D4. Error codes and field names are **AIOS-specific**. The classifier and its rule pack are reused unchanged.

## 1. Policy pipeline for `advance_turn` (order is normative)
Existing checks run first, unchanged: input caps, lookup, binding, terminated, total timeout. Then the step is evaluated, and the
first refusal wins:

| # | Gate | Refuses when | `error_message` prefix |
|---|---|---|---|
| P1 | Caller verdict | `policy_allowed=False` | `LOOPSERV_ERR_POLICY_REFUSED: ... caller policy verdict` (unchanged) |
| P2 | **Constitution classifier** (new) | `classifier.classify(tool, target, args).overall_verdict == "refused"` | `LOOPSERV_ERR_POLICY_REFUSED: LOOPPOL_ERR_CONSTITUTION: <verdict_reason>` |
| P3 | Grant scope | tools/paths/networks/revocation/expiry (T-03279, #421) | `LOOPSERV_ERR_POLICY_REFUSED: ...` (unchanged) |
| P4 | **Irreversible budget** (new) | the step is irreversible, and the bound grant's `scope.max_irreversible` is set and already used up by earlier **ok** irreversible steps of this loop | `LOOPSERV_ERR_POLICY_REFUSED: LOOPPOL_ERR_IRREVERSIBLE_BUDGET: used N of M` |

- `target` is the first string value of `tool_args[target|path|host]` (same rule as P3). `args` is `tool_args or {}`.
- A step with `tool_name=None` (a reasoning step) skips P2 and P4.
- **Irreversible** means: `tool` starts with `pentest.` or `fs.write`, or is `system.reboot`/`system.shutdown` (same set as
  `audit_client.grant_check`), **or** the classifier's C-3 flag is set.
- Refused steps never consume budget. `max_irreversible` absent means no limit; `0` means no irreversible step is allowed.

## 2. Audit row content (every step, ok or refused)
The `aios.agent_loop.step` row now carries the classifier result, exactly like `_dispatch` rows:
`c_flags` (real c1..c4), `policy_revision`, `classify_rule_ids`, `classify_evidence`, `classify_overall_verdict`,
`classify_verdict_reason`. The row args add `irreversible` (bool) and, when a budget exists, `irreversible_used`.
A reasoning step (no tool) records `classify_overall_verdict = "ok"` with all flags false except c4.

## 3. Interfaces
| Status | Item |
|---|---|
| Changed | `CapabilityGate.audit(..., classification: Optional[dict] = None)`, passed to the row columns |
| **New** | `CapabilityGate.irreversible_budget(grant_id) -> Optional[int]`, read from `scope.max_irreversible` (None if unset or the grant is unknown) |
| **New** | `agent_loop_policy.py`: `evaluate_step(tool, target, args) -> StepPolicy(classification, refused_reason, irreversible)` and `is_irreversible(tool, classification) -> bool` |
| Reused | `classifier.classify`, `CLASSIFIER_REVISION` |

## 4. Error cases
The documented error codes are unchanged. P2 and P4 surface as refused steps (`outcome="refused"`), not exceptions. A classifier
exception refuses the step (`LOOPPOL_ERR_CONSTITUTION: classifier unavailable`): fail closed, consistent with the gate.

## 5. Invariants
- LOOPPOL-INV1: no loop step is recorded `ok` if dispatch Gate #1 would refuse the same `(tool, target, args)`.
- LOOPPOL-INV2: every step row carries the classifier's real `c_flags` and `policy_revision`.
- LOOPPOL-INV3: per loop, `ok` irreversible steps <= `max_irreversible` whenever the grant sets it.
- LOOPPOL-INV4: none of P1..P4 can be disabled by configuration.
