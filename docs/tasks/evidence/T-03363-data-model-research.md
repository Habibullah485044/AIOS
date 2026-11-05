# T-03363 Research: Tool Registry & Taxonomy — data model

- Date: 2026-11-06
- Scope: what exists today for describing, naming and classifying tools across the three substrates
  (Python `code/aiosh-mcp`, TypeScript `code/aiosh-cli`, Rust `code/aiosh-rust`), and what the MCP specification says.
- Method: a read-only explorer mapped the code. I re-read every claim marked **(verified)** myself.
  External facts come from the MCP specification pages cited below. **No code was changed.**

## A. External facts (authoritative sources)
| # | Fact | Source |
|---|---|---|
| E1 | A Tool has `name`, optional `title`, `description`, `inputSchema`, optional `outputSchema`, optional `annotations`. | MCP 2025-06-18, Server › Tools › Data Types (https://modelcontextprotocol.io/specification/2025-06-18/server/tools) |
| E2 | `ToolAnnotations` = `title`, `readOnlyHint` (default **false**), `destructiveHint` (default **true**, meaningful only when not read-only), `idempotentHint` (default **false**), `openWorldHint` (default **true**). All are **hints**. | MCP 2025-06-18 schema reference, `ToolAnnotations` (https://modelcontextprotocol.io/specification/2025-06-18/schema) |
| E3 | "clients **MUST** consider tool annotations to be untrusted unless they come from trusted servers"; the schema says clients should never make tool-use decisions on annotations from untrusted servers. | E1, E2 |
| E4 | Servers **MUST** validate tool inputs, implement access controls, rate-limit invocations and sanitise outputs. | E1, Security Considerations |
| E5 | `listChanged` capability + `notifications/tools/list_changed` when the tool list changes; `tools/list` is paginated. | E1 |
| E6 | Newer spec (2025-11-25) adds tool-name guidance: **SHOULD** be 1–128 chars, case-sensitive, only `A-Z a-z 0-9 _ - .`, unique within a server. It also adds optional `icons` and `execution.taskSupport` (`forbidden` default / `optional` / `required`), and says an `inputSchema` defaults to JSON Schema 2020-12 and must not be `null`. | https://modelcontextprotocol.io/specification/2025-11-25/server/tools |

Implication: annotations are presentation hints for *clients*. AIOS's own enforcement (PEP, classifier, budget) must come from a server-side, trusted taxonomy, never from annotations a client or a third-party server supplies.

## B. Facts about this repository
### B1. Tool registration and naming
- Python serves about **67** MCP tools from `FastMCP("aiosh-mcp")` (`aiosh_mcp/server.py:49`). Fifteen are defined there with `@mcp.tool()`; the rest come from `register_*` functions wired at `server.py:868–934`. *(count inferred from decorators, not from a live `tools/list`)*
- **Four MCP naming styles**:
  - `aios_fs_read` (function names)
  - explicit `aios_agent_loop_*`
  - **dotted** MCP names `aios.release.generate` / `aios.backup.create` (`release.py:186,225`). These duplicate `aios_release_generate` / `aios_backup_create` in `server.py:218,252`.
  - un-prefixed `model_backend_*` (`model_backend_adapters_api.py:362-384`).
- **Audit/grant ("canonical") names are a different, also inconsistent, namespace**: `aios.fs.read`, `aios.agent_loop.step`, `aios.runbook`, `audit.rotate` (no `aios.`), `pentest.nmap` (no `aios.`).
- **The only MCP↔canonical map is partial (verified):** `agent_bridge.py:36-47` `CANONICAL_TO_MCP` covers 9 tools, mirrored by TS `SUPPORTED_TOOLS` (`aiosh-cli/src/agent.ts:97-101`).
- Rust builds a hand-written JSON manifest with dotted MCP names (`aiosh-rust/aiosh-mcp/src/main.rs:116+`).

### B2. Existing registry structures
- `McpToolDefinition{name, description, input_schema}` in Python (`mcp_server_core_data_model.py:160-182`) and Rust (`aiosh-core/src/mcp_server_core_data_model.rs:239-243`).
  - Bounds: name ≤ 64 matching `^[a-zA-Z0-9_.\-]+$`, description ≤ 1024, schema ≤ 64 KiB, at most 256 tools.
- `McpServerCoreService` keeps an in-memory dict registry (`mcp_server_core_service.py:63-87`). **Verified: no production code registers tools into it.** The only `register_tool(` call is the self-test at `mcp_server_core_tests.py:188`, so its `list_tools` serves an empty catalog. It is not persisted.
- **No registry anywhere has fields for category, risk, reversibility, network/path scoping, owner or annotations.** No SQL table describes tools; the tables are `pep_grants`, `audit_ring` and the retention segments.
- TS has a type-only `ToolClass = "fs.read"|"fs.write"|"process"|"audit"|"pentest"|"network"|"gui"|"system"` (`aiosh-cli/src/types.ts:18-19`).
- MCP `ToolAnnotations` are applied only to the 12 `aios_agent_loop_*` tools (`agent_loop_mcp.py:66-85`). That is about 12 of 67.

### B3. Classification is decided from the name, in at least 8 places
| Place | Rule |
|---|---|
| `audit_client.grant_check` (`audit_client.py:436-440`, 474) | irreversible: `pentest.*`, `fs.write*`, `system.reboot`, `system.shutdown`; network-scoped: `pentest.`/`network.` |
| `agent_loop_policy` (`agent_loop_policy.py:22-23`, 114-116) | adds `process.`, `shell.`; bare `pentest`; classifier C-3 |
| `agent_loop_gate.tool_refusal` (`agent_loop_gate.py:121`) | network test incl. bare names |
| `audit_client.cFlagsFor` (`audit_client.py:556-571`) | hard-coded C-1..C-4 |
| Classifier rule pack R-01..R-11 (`classifier.py:82-212`; TS mirror `constitution.ts`) | `pentest.*`→C-1, `gui.*`/`system.*`→C-2, `fs.write*`→C-2/C-3, `process.run` argv rules |
| TS `pep.ts:34-44,71-76`, `pentest.ts:89-103` | glob + irreversible set (inline copy in pentest.ts) |
| Rust `pep.rs:471-515` `is_irreversible` | larger set (`aios.backup.*`, `aios.release.*`, `session.*`, …) |
| `mcp_server_core_policy.py:26-30, 217-262` | read_only/diagnostics/state_changing/administrative, **category supplied by the caller** |

### B4. Disagreements between those places (verified where marked)
1. **Rust `tool_glob_match` has no dot boundary (verified, `pep.rs:17-30`).** `strip_suffix(".*")` then `starts_with(prefix)`, so a grant for `aios.fs.*` covers `aios.fs_layout.delete`, and `git.*` covers `github.x`. Python and TS were fixed in #421. **Security bug, fixed as a separate fix PR (not part of this research task).**
2. **TS `PepStore.check` never checks `scope.networks` (verified, `pep.ts:248-256`).** It checks only paths. Python (`audit_client.py:473-481`) and Rust (`pep.rs:749-756`) do. **Security gap; separate fix.**
3. **Classifier `x.*` rule match has no dot boundary (verified, `classifier.py:239-243`).** `pentest.*` also fires on `pentesting.foo`. This direction is over-classification, which fails safe, but it is inconsistent.
4. **Rust treats four `pentest.*` discovery tools as reversible (verified, `pep.rs:473-482`).** They are irreversible in Python and TS, so the same grant gives different budget outcomes per substrate.
5. `process.`/`shell.` are irreversible only in the agent-loop policy.
6. Prefix rules are written for un-prefixed names (`fs.write`, `system.*`) while most audit names carry `aios.`. A future `aios.fs.write` would not be classified irreversible by name. *(inferred from the rule text)*

### B5. Grant scope format
`GrantScope {tools: string[]; networks?: string[]; paths?: {allow?, deny?}; max_irreversible?: number}`:
- TS: `aiosh-cli/src/types.ts:78-86`
- Rust: `aiosh-core/src/types.rs:143-153`
- Python: `pep_grants.scope_json`, matching rules in `audit_client.py:354-417`

**No JSON Schema file exists** for grants, scopes or tools.

### B6. Docs
- There is no `docs/adr/` directory. ADR-0035/0037 are cited by specs, but the files are not in this repo.
- `SPEC-MCP-SERVER-CORE-DATA-MODEL.md` covers bounds and envelopes; its "taxonomy" section is an error-code table.
- `pep_decision_engine.md:952-962` and `capability_model.md` have per-subsystem tool tables in prose only.

## C. Assumptions (not verified)
- That the ~67 Python tools are all served by `python -m aiosh_mcp.server`. Counted from decorators; a live `tools/list` will confirm it in the scaffold task.
- That one canonical dotted name per tool is wanted, with MCP names as aliases. This is the pattern `agent_bridge.py` already uses.
- That a Python-first data model, with a JSON export the TS/Rust substrates can read, fits the project. Recent epics were Python-first.

## D. Unknowns and decisions needed before implementation
| # | Decision | Options | Recommendation |
|---|---|---|---|
| D1 | Canonical identity | MCP name vs dotted canonical name | Dotted canonical name (what grants and audit rows use) as the key; MCP names as a list of aliases. One entry per operation, so the duplicated release/backup tools collapse. |
| D2 | Taxonomy fields | a minimal set vs everything | `category` (closed enum, aligned with TS `ToolClass` plus `agent_loop`/`model_backend`/`admin`), `effect` (`read_only`/`additive`/`destructive`), `irreversible` (bool, single source for budgets), `scope_kind` (`none`/`path`/`network`), `open_world` (bool), `constitution` hint flags. MCP annotations are *derived* from these, never the other way round (E3). |
| D3 | Source of truth | code-declared entries vs DB table vs JSON file | A code-declared, frozen Python catalog with a deterministic JSON export (no runtime mutation, so it cannot be poisoned through MCP). Persistence is not needed: the catalog is code. |
| D4 | Unknown tools | allow / treat as maximally risky | **Fail closed:** an unregistered name is treated as `irreversible=True`, `scope_kind` by prefix, `effect=destructive`. |
| D5 | Relation to the eight existing name rules | replace now vs consult in parallel | Data model first, with drift tests that assert each existing rule agrees with the catalog for every registered tool. Migrating callers is a later task in this epic. |
| D6 | Name validation | 64 (current `MAX_TOOL_NAME_LEN`) vs 128 (E6) | Keep 64 and the existing regex, which is stricter than E6, and add the case-sensitivity and uniqueness rules from E6. |
| D7 | Substrate disagreements B4.4 / B4.5 | which side is right | The data model must record **one** answer. Recommendation: the stricter answer (irreversible) until a reviewed decision says otherwise. |

## E. Follow-ups found during research (outside this task)
- Rust `tool_glob_match` dot boundary (B4.1). Security; fix PR next.
- TS `PepStore.check` network scope (B4.2). Security; fix PR next.
- `pentest.py:30` docstring names the MCP tools `pentest_*`; they are `aios_pentest_*`.
