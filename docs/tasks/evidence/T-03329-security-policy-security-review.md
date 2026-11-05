# T-03329 Security Review: Agent Loop Hardening — security policy

- Date: 2026-11-05
- Scope: the P1..P4 step pipeline (T-03326..T-03328): `agent_loop_policy.py`, `agent_loop_service._advance_locked`,
  `agent_loop_gate.tool_refusal/irreversible_budget`, and the reused `classifier.py`.
- Method: an **independent subagent review** (code only, not my conclusions), with every finding reproduced, plus my own review.
  The independent review found every bypass below; I had found none of them.
- Key nuance: the service does not run tools; the caller runs the tool after an `ok`. So the policy is only as good as its view of the
  real `(tool_name, tool_args)`.

## Findings
| # | Sev | Bypass (reproduced as `ok`) | Fix (this task) |
|---|---|---|---|
| 1 | **High** | **Target smuggling.** Only the first of `target/path/host` was checked: `{"target":"10.0.0.5","host":"8.8.8.8"}`, a list `{"target":["8.8.8.8"]}`, other keys (`hosts`, `file`, `dest`), or no target at all skipped the paths/networks scope. | `extract_targets` collects **every** string under 21 target-like keys (lists included) and rejects non-string values. The gate checks all of them. A grant with a paths/networks scope and **no checkable target fails closed**. |
| 2 | Med | **Case/Unicode evasion of host rules** (`SHODAN.IO`, full-width letters). | The classifier input is normalised (NFKC, casefold, invisible characters removed, trailing dot stripped), per target, keeping the worst verdict. |
| 3 | **High** | **Tool-name aliasing:** `fs.Write` (verdict ok, not irreversible); bare `pentest` (covered by the `pentest.*` glob but not counted irreversible and not network-checked). | Tool names must be **lowercase** (service, MCP schema, CLI). Bare family names (`pentest`, `process`, `shell`) count as irreversible; bare `pentest`/`network` are network-checked. |
| 4 | Med | **Budget dodged** by tools the rule pack does not flag C-3 (`process.run` with `/bin/rm`, `sh -c`, `DROP TABLE`). | `process.*` and `shell.*` count as irreversible by name (P4). The classifier rule gaps themselves (`bin` basename, case-insensitive SQL) are **not fixed here**: the rule pack is cross-substrate (TS lockstep, `CLASSIFIER_REVISION`), so they are a follow-up. |
| 5 | Med | **R-11 prompt-injection evasion**: nested dicts, keys, zero-width/NBSP/word-joiner, full-width. | The classifier also sees a flattened text of every key and nested string, in two normalisations (invisible characters removed, and invisible characters turned into spaces). |
| 6 | Med | **Hidden args in evidence**: a `cookie=` prefix masked the rest of the args; refused rows had no args. | Every step row (ok **and** refused) carries `tool_args_sha256`, a SHA-256 of the canonical **unmasked** args, so evidence can be matched to what ran. Refused rows also keep the masked `tool_args`. |
| 7 | Med (design) | **Budget multiplied** by a multi-use grant: N loops gave N x `max_irreversible`. | The budget is counted **per grant from the ring** (`irreversible_used`), so it holds across loops, processes and restarts. |

## Regression tests (`tests/test_agent_loop_policy_security.py`, 22 cases)
**Against the pre-fix code: 20 failed, 2 passed.** The 2 that passed were the in-scope control and the original case-only injection, both fine before.
Covered: 5 network and 3 path smuggling shapes; in-scope multi-target still ok; 8 injection variants; uppercase tool rejected; bare
`pentest` under budget 0 and out of network; `process.run` budget; args digest on ok and refused rows; multi-use grant across loops plus a fresh service.

## Residual / follow-ups (honest)
- Classifier rule pack (Python + TS, revision bump): `bin` basename, case-insensitive matching inside the rule pack, recursive arg walk at dispatch. These fixes apply to the **agent-loop** path only; `_dispatch` still calls the raw classifier.
- Budget check-then-write is not atomic across processes: two processes could each take the last unit at once. The in-process lock serialises one service.
- The policy can only judge what the caller declares. A caller that runs something other than the evaluated `(tool, args)` is outside this layer; the args digest makes that detectable afterwards.
- `--max-irreversible` is still unenforced on the dispatch, TS and Rust paths (T-03323 F4).

## PoR standing rule
No state-changing path was added. Every fix narrows what is allowed, and each refusal still writes exactly one step row.
