# T-03380 Evidence: Tool Registry & Taxonomy — core service Hardening

- Date: 2026-11-06
- Scope: making the service's decisions trustworthy enough for strict mode. The research named coverage as the precondition
  (T-03373 D4), and the T-03379 review hardened the runtime paths (report flood, fail-closed mode, stdout safety).
  This task closes the coverage gap and makes it permanent.

## Coverage: 17 → 69 of 69 served tools
- The catalog grows from 20 to **71 entries**: every served MCP tool, plus the literal audit name `pep.capability.redeem`.
  Each entry was classified from the tool's own code and description:
  - grant-required where the tool calls `_dispatch(require_grant=True)` or takes a capability token: release, backup, anchor
    create, MCP core dispatch/repair, model complete/register/recover;
  - path scope where it takes a path: backup, MCP recovery, model config;
  - open world where it calls external hosts: model completions and health, `aios.scan`.
- **Multi-action tools** (`aios.task`, `aios.compliance`, `aios.runbook`, `aios.scan`) take their *effect* from their most consequential
  action, and their *requires_grant* is the action-independent minimum, because their own gates require grants per action
  (e.g. `server.aios_task`: `requires_grant = action not in _TASK_READ_ONLY`). Classifying them grant-required would make strict mode
  refuse their read actions.
- The integration test changes from **tracking** uncovered tools to **failing** on any served tool without an entry
  (`test_every_served_tool_has_a_catalog_entry`).

## Effect on shadow-mode noise (service `decide` over the catalog's canonical names)
| | before (T-03376) | after |
|---|---|---|
| `unregistered` over served MCP names | 52 | **0** |
| canonical names that disagree | 9 of 20 | 22 of 71 |

All 22 remaining disagreements are explained and expected:
- **`grant` ×19:** tools that enforce a grant or token themselves, which `grant_check`'s generic name rule does not model. In
  dispatch they agree whenever the caller passes `require_grant=True`, as the real wrappers do.
- **`scope` ×3:**
  - `pentest.tshark` and `pentest.aircrack-ng` are offline and path-scoped (T-03369);
  - `aios.scan` is network-scoped (its `net` action) where the name rule says path.

  All three are listed explicitly in `KNOWN_SCOPE_DISAGREEMENTS`.

## Tests
```
$ python -m pytest tests/ -k tool_registry -q
286 passed, 1437 deselected, 1 warning in 21.66s
```
- The data-model drift tests (never weaker than the name rules, network rule, annotations, TS parity) now run over **71** entries.
- The security tests that used `aios.task` as an "always-disagreeing" name now use an unregistered name.
- The operator doc (§6/§7) reports 71 entries and complete coverage, and replaces "partial coverage" with the per-action
  limitation. The doc drift test passes.

Error envelope and cleanup: unchanged and covered by T-03379 (no I/O; explicit `TOOLREG_ERR_UNAVAILABLE`; fail-closed strict).
