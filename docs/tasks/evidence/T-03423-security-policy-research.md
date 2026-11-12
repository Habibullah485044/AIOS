# T-03423 Research: Tool Registry & Taxonomy — security policy

- Date: 2026-11-13
- Question: what *policy* does the tool registry enforce today, and where is it decided? What is missing before the registry can
  be trusted as a policy source, and not only an advisory catalog?
- Method: read the decision path (`tool_registry_service.py`, `_dispatch.py`, `agent_loop_policy.py`, `tool_registry_data_model.py`),
  the operator doc (`docs/SPEC-TOOL-REGISTRY-DATA-MODEL.md` §6b, §7) and the prior specs, plus two probes against the live catalog.
  **No code was changed.**

## A. Facts (verified)
| # | Fact | Source |
|---|---|---|
| F1 | The registry is consulted in exactly **two** enforcement places: dispatch Gate #2 (`_registry_require_grant`, before `grant_check`), and the agent-loop step policy (`_registry_irreversible`). The Rust PEP and the TS CLI do not read the catalog. | `_dispatch.py:110-128,202`; `agent_loop_policy.py:164-178`; doc §7 |
| F2 | **Shadow** (the default) changes nothing. It only reports disagreements: once per distinct case on stderr, plus counters in `aios_tool_registry_stats`. **Strict** can only add (OR): a grant requirement in dispatch, and irreversibility in the agent loop. | `tool_registry_service.py:204-209`; TOOLSVC-INV2/INV5 |
| F3 | `enforcement()` also returns `scope_kinds`, but **no consumer reads it**. Scope checks stay with the legacy name rule (`pentest.`/`network.` → network, else path). | grep `scope_kinds` in `aiosh_mcp/`: only the registry's own API/CLI; doc §6b |
| F4 | An unregistered name gets `unknown_profile()`: destructive, irreversible, **requires a grant**, open world. A malformed name also gets a synthetic per-name canonical. So in strict mode an unregistered tool needs a grant; it is never denied outright. | `tool_registry_data_model.py:283-296` |
| F5 | If the registry fails during a call, both consumers fail closed **when strict was asked for** (grant required / step irreversible), and fall back to legacy otherwise. The two copies of this logic differ: dispatch logs once through a module global, the agent loop through `_warn_once`. | `_dispatch.py:119-128`; `agent_loop_policy.py:171-178` |
| F6 | **A strict-mode refusal is not attributable.** When strict adds the grant requirement and none is given, the audit row reads `tool 'X' requires explicit PEP grant`, exactly as when the call site itself required it. Nothing in the row records the registry, its mode or which catalog decided. | `_dispatch.py:205-227` |
| F7 | The catalog has **no revision identifier**. There is `SCHEMA_VERSION = 1` (export format), but no digest of the security fields. A reader of an old audit row cannot tell which policy was in force. Dispatch rows do carry the *classifier's* `policy_revision`. | grep `revision` in registry modules; `_dispatch.py:222` |
| F8 | Policy is not configurable: the locked config keys (`catalog`, `entries`, `irreversible_names`, …) reject a whole file (TOOLREGCONF-INV2). | doc §6e |
| F9 | Probe, catalog vs legacy by canonical name (73 entries). Strict adds a grant requirement to **19** entries, irreversibility to **2** (`aios.backup.create`, `aios.release.generate`), and a different scope to **3** (`aios.scan`, `pentest.aircrack-ng`, `pentest.tshark`). The catalog is weaker than legacy for **0** entries. | probe below |
| F10 | Several of the 19 already pass their own `require_grant=True` at the call site (`aios.fs.read`, `aios.backup.create`, `aios.release.generate`, `audit.rotate`). For those, strict changes nothing at dispatch. | `server.py:142-144,225,259,302` |

Probe (from `code/aiosh-mcp`, `AIOSH_HOME` set to a fresh temporary directory):
```
entries 73
strict adds grant: 19  [aios.agent_loop.{abort,complete,init,recover,start,step}, aios.anchor.create, aios.backup.create, aios.fs.read,
                        aios.mcp.core.dispatch, aios.mcp.recovery.repair, aios.model.{complete,endpoint.register,recover_config},
                        aios.release.generate, audit.rotate, model_backend.{complete,register}, pep.capability.redeem]
strict adds irreversible: 2 ['aios.backup.create', 'aios.release.generate']
scope differs: ['aios.scan', 'pentest.aircrack-ng', 'pentest.tshark']
catalog weaker than legacy: []
```

## B. Upstream references
- **MCP specification, Tools (2025-06-18), §Tool annotations:** annotations are hints, and clients must treat them as untrusted unless the
  server is trusted. Enforcement must therefore stay server-side (as TOOLREG-INV4 / TOOLAPI-INV3 already require).
  https://modelcontextprotocol.io/specification/2025-06-18/server/tools
- **OWASP Top 10 for LLM Applications 2025, LLM06 Excessive Agency:** grant per action and require human approval for high-impact
  actions. This supports a per-tool catalog policy over per-session trust. https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
- **NIST SP 800-53 Rev. 5, AC-3 (access enforcement), AC-6 (least privilege), AU-3 (content of audit records):** AU-3 asks that a record
  show the outcome and enough to establish what happened. F6/F7 fall short of that for strict-mode refusals.
  https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- Repo: ADR-0035 §A F-2 (one audit row per MCP call, `docs/capability_model.md:332`); PoR invariant I-2 (redeem before act).

## C. Assumptions (not verified)
- A1: Operators read refusal reasons in the audit ring, so a reason that names the registry is enough attribution, with no new column.
- A2 (now checked): five Python tests match `requires explicit PEP grant` as a substring, so appending text keeps them green. One,
  `test_task_service_smoke.py:219`, compares the whole string, but it runs in shadow mode, where D1 adds nothing. The TS (`pep.ts`,
  `pentest.ts`) and Rust (`dispatch.rs`, `pep.rs`, `release.rs`) substrates build their own strings and are unaffected.
- A3: Hashing the security fields of 73 entries once per process costs microseconds.

## D. Unknowns
- U1: Whether the Rust and TS substrates should adopt the catalog. That needs `export_json()` consumers there; it is out of this epic, as in doc §7.
- U2: Whether strict should ever enforce the catalog scope (F3). For `pentest.tshark` the catalog says path while legacy says network, so
  enforcing both could refuse calls that work today in strict mode.

## E. Decisions needed (for T-03424)
- **D1 Attribution (recommended).** When strict mode is what made a grant necessary, the refusal reason says so:
  `… requires explicit PEP grant (tool registry strict, catalog <rev>)`. No schema change, no new audit row (F-2 holds). Closes F6.
- **D2 Catalog revision (recommended).** Define `policy_revision()` = a short SHA-256 over the canonical JSON of each entry's security fields
  (effect, irreversible, requires_grant, scope_kind, open_world), sorted by name. Show it in `aios_tool_registry_stats` and in D1 reasons. Closes F7.
- **D3 One policy point (recommended).** Move the two copies of the strict and fail-closed logic (F5) into one pure function in a new
  `tool_registry_policy.py`. Both consumers call it, so they cannot drift apart. Behaviour stays identical: OR-only, fail closed when strict was intended.
- **D4 Unregistered tools (recommended: keep).** Keep grant-required, not deny (F4): a grant is an explicit human decision, and denial
  would break legacy tools that are not catalogued yet. Record it as policy, not accident.
- **D5 Scope (recommended: defer).** Do not enforce `scope_kinds` in this epic (U2). Keep it documented as a limitation.
- **D6** The policy stays unconfigurable (F8). Error codes for existing paths are unchanged, and the new reason text is appended, never replaced.

## Security audit (standing rule)
- Research only: no code, config or policy changed. The probes read the in-memory catalog with a throwaway `AIOSH_HOME`.
- Findings F6/F7 (strict-mode refusals not attributable, no catalog revision) are audit-quality gaps, not bypasses. Strict still only tightens.
- PoR (I-2): no state-changing path touched. **No bypass.**
