# T-03373 Research: Tool Registry & Taxonomy — core service

- Date: 2026-11-06
- Question: how should the read-only catalog (data-model epic, T-03363..T-03372) become a *service* that enforcement
  can consult, and what must stay true while callers migrate?
- Method: read the current call sites and measured coverage against the live server. **No code was changed.**
  Builds on [T-03363-research.md](T-03363-research.md) (external MCP facts E1–E6 are not repeated here).

## A. Facts (verified in this repository today)
### A1. Where tool decisions are made
| Decision | Call site | Inputs |
|---|---|---|
| grant required / irreversible / tool scope / path or network target | `_dispatch.dispatch` → `audit_client.grant_check` (`_dispatch.py:15`, `:177`) | tool name, target, grant |
| "this read-only tool still needs a grant" | `_dispatch.dispatch(require_grant=True)`: a per-call flag set by the wrapper (e.g. `server.aios_fs_read`) | the caller's own knowledge |
| agent-loop step: irreversible budget, scope, targets | `agent_loop_policy.evaluate_step` / `is_irreversible` (`agent_loop_policy.py:107-158`), `agent_loop_gate.tool_refusal` (`agent_loop_gate.py:97-132`) | tool name, args, classifier C-3 |
| constitution flags | `classifier.classify` (R-01..R-11) | tool name, target, args |
| tool glob in grants | `audit_client.tool_glob_match`, also used by the agent-loop gate (`agent_loop_gate.py:115`) | grant `scope.tools` |

So **two production gates** (dispatch and the agent-loop gate) make the irreversible and scope decisions, using **three** name rules.

### A2. Coverage
- The live server serves **69** MCP tools. The catalog resolves **17**; **52 are uncovered**.
- The audit (canonical) names actually written by the Python code are about **21 literals**. Most frequent first: `aios.task` ×6,
  `aios.fs.read` ×4, `audit.rotate`, `aios.release.generate`, `aios.backup.create`, `pentest.nmap`, `aios.process.list`, `aios.audit.*`, `aios.scan`,
  `aios.runbook`, `aios.restraint.{prove,verify}`, `aios.compliance`, `aios.anchor.{create,verify}`, `aios.agent_loop.config`,
  `pep.capability.redeem`. Pentest names are also built dynamically through `pentest._audit_tool_name`.
- Several uncovered MCP tools have **no audit name of their own**. They are pure read surfaces (`aios_agent_loop_snapshot`,
  `aios_mcp_core_status`, `model_backend_list`, …), so the catalog needs entries keyed by canonical names that do not appear in audit
  rows yet.
- `aios.backup.create` and `aios.release.generate` are served **twice**: under their dotted names and under `aios_backup_create` /
  `aios_release_generate`. One catalog entry with two aliases covers both.

### A3. Constraints that cannot move
- **PoR I-2 / I-3:** consequential actions need a redeemed grant and exactly one audit row. A registry service must not add a second
  audit row per call, and must not let any call through that is refused today.
- The data-model validator already guarantees an entry is **never weaker** than the irreversible name rules (T-03369 #3). It does **not**
  guarantee agreement on scope: offline pentest tools are path-scoped in the catalog, but `grant_check` applies `scope.networks`
  when set (T-03369 #2).
- The catalog is code and immutable. No runtime registration path may be added (TOOLREG-INV5).

## B. Options for the service
| # | Option | Risk |
|---|---|---|
| S1 | **Shadow mode:** compute the catalog's decision next to the legacy one, compare, and report disagreements (metrics/log). Enforcement unchanged. | none to safety; no benefit until enforced |
| S2 | **Stricter-of-both:** enforce `legacy OR catalog` for "grant required" and "irreversible". For scope, check **both** applicable scopes when they disagree. | can refuse calls that pass today, e.g. a `pentest.tshark` capture path under a networks-only grant. That is the safe direction, but it changes behaviour |
| S3 | Replace the legacy rules with the catalog | removes the three-way drift, but one catalog mistake becomes an enforcement hole. Only acceptable after S1 shows zero disagreement and coverage is complete |

## C. Assumptions (not verified)
- Disagreements are rare in practice. Only the two offline pentest tools disagree for the 20 registered entries. Unregistered names fall back to the
  fail-closed profile, which is *stricter* than the legacy rules for every non-pentest name (it requires a grant). Under S2 that would refuse
  every unregistered read-only tool called without a grant, so **coverage must come before S2**.
- A per-process service object (built once from the immutable catalog) is enough; there is no cross-process state.

## D. Decisions needed before implementation
| # | Decision | Recommendation |
|---|---|---|
| D1 | Rollout | **S1 (shadow) in this epic**, with S2 behind an explicit opt-in setting that defaults off. S3 belongs to a later epic, once coverage is 100 % and shadow shows no disagreement. |
| D2 | API | `ToolRegistryService.decide(tool, target, classification=None) -> ToolDecision` returns `canonical`, `registered`, `requires_grant`, `irreversible` (catalog floor ∪ name rules ∪ C-3), `scope_kind`, and a `disagreements` list against the legacy rules. Pure, with no I/O. |
| D3 | Where the comparison runs | `_dispatch.dispatch` and the agent-loop policy call `decide()` and attach disagreements to a structured log line (masked). **Not** a new audit row (I-3). |
| D4 | Coverage | Add catalog entries for every served MCP tool and every literal audit name (A2) in this epic. The integration test turns "tracked" into "failed" once it reaches 100 %. |
| D5 | Unknown names in shadow mode | Report them as `unregistered`; never refuse on that alone while S1 is active. |
| D6 | Observability | Per-process counters: decisions, disagreements by kind, unregistered names (bounded, hashed). |
