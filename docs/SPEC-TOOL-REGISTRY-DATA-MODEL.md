# Tool Registry & Taxonomy — data model

- Module: `code/aiosh-mcp/aiosh_mcp/tool_registry_data_model.py`
- Lifecycle: T-03363..T-03372 (Phase 3 — AI Control Plane / Tool Registry & Taxonomy / data model)
- Status: shipped. Read-only. **No enforcement path uses it yet.** Callers migrate in later epics.

## 1. What it is
One trusted, server-side description per tool:
- the **canonical** dotted name used in PEP grants and audit rows (`pentest.nmap`, `aios.agent_loop.step`);
- the **MCP names** clients call (`aios_pentest_nmap`, `aios_agent_loop_advance`);
- the tool's **taxonomy**: what kind of thing it does, and whether it is irreversible or scoped by path or network.

Before this, the same facts were scattered across at least eight name-based rules in three languages, and they
disagreed (research: [T-03363](tasks/evidence/T-03363-research.md)).

MCP `ToolAnnotations` are **derived** from an entry and never read. Per MCP 2025-06-18, annotations are untrusted hints, so
enforcement must come from a server-side source like this one.

## 2. Taxonomy
| Field | Meaning |
|---|---|
| `canonical` | lower-case dotted name, ≤ 64 chars, `^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)*$` |
| `mcp_names` | ≤ 8 aliases, each ≤ 64 chars of `A-Z a-z 0-9 _ . -` |
| `category` | `fs.read`, `fs.write`, `process`, `audit`, `pentest`, `network`, `gui`, `system`, `agent_loop`, `model_backend`, `mcp_core`, `service`, `admin` |
| `effect` | `read_only`, `additive`, `destructive` |
| `irreversible` | counts against a grant's `max_irreversible` |
| `scope_kind` | `none`, `path`, `network`: which grant scope applies to its targets |
| `open_world` | talks to external hosts |
| `requires_grant` | a PEP grant is needed even for a user-issued call |
| `idempotent` | repeating the call has no further effect (meaningless for `read_only`) |

**Consistency rules** (TOOLREG-INV1): an entry that breaks one cannot be constructed.
1. `read_only` ⇒ not irreversible, not idempotent.
2. irreversible ⇒ requires a grant and is not `read_only`.
3. network scope ⇒ open world.
4. `pentest` ⇒ irreversible and path- or network-scoped. Offline tools such as `tshark -r` and `aircrack-ng` read a file, so they are path-scoped.
5. `fs.write` and `system` categories ⇒ irreversible.
6. `network` category ⇒ network scope.
7. **Never weaker than today's name rules:** a name that `audit_client.grant_check` or `agent_loop_policy` treats as
   irreversible (`pentest.*`, `fs.write*`, `process.*`, `shell.*`, `system.reboot`, `system.shutdown`, case-insensitive) must be
   irreversible and require a grant.

**Names** (TOOLREG-INV2) are unique across the catalog after NFKC, case-folding, and treating `.`, `_` and `-` as one separator. An
alias may fold onto its own canonical name (`aios_fs_read` ~ `aios.fs.read`); any other collision is rejected.

## 3. Lookups
| Call | Behaviour |
|---|---|
| `get(canonical)` | the entry or `None`; canonical names only |
| `resolve(name)` | exact canonical **or** MCP name, else `None`; exact `str` only |
| `profile(name)` | `resolve(name)` or the **fail-closed unknown profile**; never raises |
| `require(name)` | the entry, else `TOOLREG_ERR_UNKNOWN` |
| `annotations(name)` | MCP `ToolAnnotations` derived from the entry |
| `export_json()` | deterministic JSON (`schema_version: 1`) for other substrates |

**Unknown tools fail closed** (TOOLREG-INV3): an unregistered name is treated as destructive, irreversible, grant-required and
open-world. It is network-scoped if its name is `pentest`/`network` or starts with `pentest.`/`network.` (case-insensitive), else
path-scoped. A malformed name gets a distinct synthetic canonical name `unregistered.<sha256[:16]>`, so the raw name is never
echoed and one grant cannot cover several malformed names. Names with that prefix cannot be registered.

The catalog is immutable (TOOLREG-INV5): frozen entries, a read-only name map, and no add/remove methods. No MCP or CLI tool can change
it; it is code, reviewed through PRs.

## 4. Use it

Python (copy-pasteable; the doc test runs it):
```python
from aiosh_mcp.tool_registry_data_model import default_catalog

catalog = default_catalog()
nmap = catalog.resolve("aios_pentest_nmap")              # MCP alias -> entry
print(nmap.canonical, nmap.irreversible, nmap.scope_kind.value)
# -> pentest.nmap True network
unknown = catalog.profile("pentest.newthing")            # unregistered: fail closed
print(unknown.irreversible, unknown.requires_grant, unknown.scope_kind.value)
# -> True True network
print(catalog.annotations("aios_fs_read").readOnlyHint)
# -> True
```

MCP (read-only, no token):
```json
{"name": "aios_tool_registry_get", "arguments": {"name": "aios_pentest_nmap"}}
```
```json
{"name": "aios_tool_registry_list", "arguments": {"category": "pentest"}}
```
`aios_tool_registry_get` returns `{"ok": true, "data": {"registered": true|false, "entry": {...}}}`.

## 5. Errors
| Code | When |
|---|---|
| `TOOLREG_ERR_INVALID_NAME` | a canonical or MCP name fails its rule, a title has control or bidi characters, or a reserved `unregistered.` name is registered |
| `TOOLREG_ERR_INCONSISTENT` | a consistency rule (§2) fails, a field has the wrong type, or a catalog item is not a `ToolEntry` |
| `TOOLREG_ERR_DUPLICATE` | a name collision (§2), or the same entry listed twice |
| `TOOLREG_ERR_BOUNDS` | > 8 aliases, title not 1..64 chars, or > 512 entries |
| `TOOLREG_ERR_UNKNOWN` | `require` / `annotations` on an unregistered name |
| `TOOLREG_ERR_UNAVAILABLE` | the catalog failed to build. The two MCP tools answer with this instead of taking the server down; `get` still returns the fail-closed profile |

Errors are `ToolRegistryError(code, message)`. Messages echo names only with control and bidi characters stripped, truncated to 80 chars.

## 6. Coverage and drift checks
- The default catalog has **73 entries** and covers **every one of the 71 served MCP tools** plus every literal audit name
  (T-03380). The integration test **fails** if a served tool has no entry. Multi-action tools (`aios.task`,
  `aios.compliance`, `aios.runbook`, `aios.scan`) are classified by their most consequential action for `effect`. Their
  `requires_grant` is the action-independent minimum, because their own gates require grants per action.
- Permanent tests (CI suite #35 `tool_registry`) assert, for every entry, agreement with `audit_client.grant_check`, `agent_loop_policy`,
  the network-name rule and TS `isIrreversible`. The one listed exception: `pentest.tshark` / `pentest.aircrack-ng` are
  path-scoped here, while `grant_check`'s name rule would apply `scope.networks` to them; `aios.scan` is network-scoped
  here, while the name rule treats it as path-scoped.

## 6b. Core service: shadow and strict decisions (T-03373..T-03382)
Module `code/aiosh-mcp/aiosh_mcp/tool_registry_service.py`. `ToolRegistryService.decide(tool, target, classification,
require_grant)` returns a `ToolDecision`:
- `canonical`, `registered`;
- `requires_grant`: catalog **or** legacy rule **or** caller flag;
- `irreversible`: catalog **or** name rules **or** classifier C-3;
- `scope_kinds`: the legacy scope, plus the catalog scope when they differ;
- `disagreements`: a sorted subset of `unregistered`, `grant`, `irreversible`, `scope`.

It is pure: no I/O, no audit rows, never raises.

It runs inside both production gates:
- `_dispatch.dispatch`, before the PEP grant gate;
- `agent_loop_policy.evaluate_step`, for the irreversible budget.

| `AIOSH_TOOL_REGISTRY_MODE` | Behaviour |
|---|---|
| unset or empty (default) | **shadow**: enforcement unchanged. Each distinct disagreement is logged once to stderr as a masked JSON line `{"event": "tool_registry.disagreement", ...}`, at most 32 lines per process |
| `strict` (any case or width) | dispatch also requires a grant when the catalog says so; the agent loop also counts a step irreversible when the catalog says so. **Only ever tightens.** |
| anything else (e.g. `strct`) | treated as **strict** (fail closed), with one warning naming the value |

If the registry cannot be built, shadow falls back to the legacy rules. If strict was asked for, the gates fail closed instead:
grant required, step irreversible.

```python
from aiosh_mcp.tool_registry_service import ToolRegistryService

svc = ToolRegistryService(mode="shadow")
d = svc.decide("pentest.tshark", "/tmp/capture.pcap")
print(d.canonical, d.requires_grant, d.irreversible, [s.value for s in d.scope_kinds], list(d.disagreements))
# -> pentest.tshark True True ['network', 'path'] ['scope']
print(svc.enforcement(d))
# -> {}
print(ToolRegistryService(mode="strict").decide("aios.unknown.tool").requires_grant)
# -> True
```

Turn strict on for a server (opt-in):
```bash
AIOSH_TOOL_REGISTRY_MODE=strict python -m aiosh_mcp.server
```

| Code | When |
|---|---|
| `TOOLSVC_ERR_MODE` | an explicit invalid `mode=` argument (a programming error; the env path fails closed instead) |

Service limitations:
- **Strict tightens two things only:** the grant requirement in `dispatch()` and irreversibility in the agent loop. `scope_kinds` is
  reported, not enforced.
- **Not every surface goes through the service.** About 45 MCP tools never pass through `dispatch()` (agent-loop, model-backend and MCP-core
  tools), so strict cannot tighten them. They rely on their own token gates.
- **The mode is fixed at first use** in a process, like the rest of the process configuration.
- Expect strict to refuse calls that pass today. Examples: unregistered tool names, and grant-free calls to tools the catalog marks
  grant-required.

## 6c. Operator CLI: `aiosh-tool-registry` (T-03383..T-03392)
`python -m aiosh_mcp.tool_registry_cli` is always available. The console script `aiosh-tool-registry` appears after
`pip install -e code/aiosh-mcp`. The CLI is read-only: no DB, no audit rows, no network. Its only write is `export --out`.

Run from `code/aiosh-mcp` (the doc test executes every command below and checks the exit code in the comment):
```bash
python -m aiosh_mcp.tool_registry_cli get aios_pentest_nmap          # exit 0: canonical pentest.nmap, irreversible
python -m aiosh_mcp.tool_registry_cli check aios.fs.read nope.tool   # exit 1: one name is not registered
python -m aiosh_mcp.tool_registry_cli decide pentest.tshark --json   # exit 0: scope_kinds network+path, target_checked false
python -m aiosh_mcp.tool_registry_cli list --category pentest        # exit 0
python -m aiosh_mcp.tool_registry_cli export                         # exit 0: canonical JSON on stdout
python -m aiosh_mcp.tool_registry_cli --help                         # exit 0
```

| Subcommand | Does | Exit |
|---|---|---|
| `list [--category C]` | every registered tool (or one category) | 0 |
| `get <name>` | one tool by canonical or MCP name. Unregistered names get the fail-closed profile | 0, or **1** if unregistered |
| `decide <name> [--require-grant] [--mode shadow\|strict]` | the core service's decision (§6b). `--target` is accepted, but decisions are per name (`target_checked: false`) | 0 |
| `export [--out FILE]` | canonical JSON on stdout, or written atomically to FILE (temp file + rename; directories, symlinks and devices refused; ≤ 4 MiB) | 0, or 1 on I/O error |
| `check <name>…` | 1..256 names; for scripts and CI | 0 if all registered, else **1** |

Every subcommand takes `--json` for a machine envelope `{"ok", "subcommand", "data", "error_code", "error"}`.
Exit codes: `0` ok, `1` negative result or I/O error, `2` usage, `130` interrupted.
Human output is ASCII: control, bidi and non-ASCII characters are shown escaped (`\u6f22`), never raw.
Errors go to stderr, so `export > catalog.json` never writes an error into the file. A closed pipe (`| head`) stops quietly.

| Code | When |
|---|---|
| `TOOLCLI_ERR_USAGE` | bad arguments, a NUL byte, > 256 names, a name > 256 chars, an empty `--out` (exit 2) |
| `TOOLCLI_ERR_IO` | `export --out` cannot write, the target is not a regular file, or the export exceeds 4 MiB (exit 1) |
| `TOOLCLI_ERR_UNAVAILABLE` | the catalog failed to build (exit 1) |
| `TOOLCLI_ERR_INTERRUPTED` | Ctrl-C (exit 130); nothing is left behind |

CLI limitations:
- **`export --out` replaces the file:**
  - on Windows the new file gets default ACLs, and explicit ACEs on the old file are not kept;
  - on POSIX the old file's mode is kept;
  - any writable regular file you name is replaced, as with `> file`.
- **`stats` is not available from the CLI.** Server counters live in the server process.
- **No TS `aiosh tools` command yet.** TS can read `export` output.

## 6d. MCP API: decide, stats and catalog-driven annotations (T-03393..T-03402)
Two more read-only MCP tools (no token):
- `aios_tool_registry_decide(name, require_grant=false)` returns the core service's decision for a call to `name`, with
  `target_checked: false`. It uses **its own** counters, so callers cannot inflate or probe the server's dispatch telemetry.
- `aios_tool_registry_stats()` returns this server's dispatch and agent-loop registry counters: mode, decisions, disagreements by kind,
  unregistered decisions with per-process keyed hashes and never names, and the logged/suppressed disagreement lines.

```json
{"name": "aios_tool_registry_decide", "arguments": {"name": "aios_pentest_nmap"}}
```
```json
{"name": "aios_tool_registry_stats", "arguments": {}}
```

**Annotations for every served tool.** At startup, after all registrations, `apply_catalog_annotations` gives each served tool MCP
`ToolAnnotations` derived from its catalog entry. Before this only 14 of 69 tools had any. Clients may skip confirmation prompts for
`readOnlyHint=true` tools, so the pass **only ever makes a tool look more careful**:
- `readOnlyHint=true` is set only if **all** of the following hold:
  - the entry is `read_only`;
  - it requires no grant;
  - its category is one of `audit`, `agent_loop`, `mcp_core`, `model_backend`, `fs.read`, `service`;
  - its `scope_kind` is `none`;
  - its input schema has **no grant/token argument** (`grant_id`, `caller_grant_id`, `capability_token`, `token`, `*_grant_id`) and **no
    path argument** (`path`, `file`, `dir`, `*_path`, …);
  - an existing annotation does not say otherwise (an explicit `false`, or a destructive or non-idempotent claim).
- `destructiveHint` and `openWorldHint` stay `true` if either side says so (an omitted hint counts as MCP's default, `true`).
  `idempotentHint` is claimed only if both sides claim it.
- An annotation that is already equivalent is left untouched (the agent-loop module's own annotations).
- A broken catalog changes nothing. A tool whose schema cannot be read gets no read-only hint. One failing tool is left as it was, and
  the pass continues.

Result on the live server: all **71** tools are annotated, and **35** are advertised read-only. Each of the 35 was verified read-only by
reading its code and probing it (T-03399).

API limitations:
- **Annotations are hints for clients.** Server enforcement (PEP grants, the classifier, the irreversible budget) is unaffected either way.
- **Follow-ups (outside the registry):** confine the path arguments of `aios_mcp_recovery_check`, `aios_model_validate_config` and
  `aios_restraint_prove` to `$AIOSH_HOME`, and bound the segment scans of `aios_audit_verify(full)` / `aios_audit_seen(exact)`.
  Until then those tools are deliberately *not* advertised read-only.
- The TS and Rust MCP manifests are not annotated from the catalog.

## 6e. Configuration (T-03403..T-03412)
Module `code/aiosh-mcp/aiosh_mcp/tool_registry_config.py`. It is resolved **once per process** (when the server first needs it) and read by every
consumer. Resolving never raises, writes nothing, and writes no audit row.

| Key | Default | Bounds | Env |
|---|---|---|---|
| `mode` | `shadow` | `shadow` \| `strict` | `AIOSH_TOOL_REGISTRY_MODE` |
| `report_max_lines` | 32 | 1..1000 | `AIOSH_TOOL_REGISTRY_REPORT_MAX_LINES` |
| `unregistered_samples` | 50 | 0..200 | `AIOSH_TOOL_REGISTRY_UNREGISTERED_SAMPLES` |

**Config file:** the path in `AIOSH_TOOL_REGISTRY_CONFIG`, else `$AIOSH_HOME/tool_registry_config.json` if present (never the working
directory). The file must be a JSON object, at most 64 KiB, UTF-8 (a BOM is fine), a regular file, with no duplicate keys. UNC, `\\?\`,
`\??\` and device paths (`CON`, `NUL`, `COM1`, …) are refused.

```json
{"mode": "strict", "report_max_lines": 64, "unregistered_samples": 100}
```

**Precedence:**
- **Numbers:** argument → env → file → default, then clamped to bounds. A clamp is reported.
- **Mode: strictest wins.** If any source says `strict`, or anything unrecognised, the mode is strict. A file cannot downgrade an env `strict`, and
  vice versa.
- **A config you asked for but which cannot be used counts as strict.** That covers an unreadable, rejected or oversize file, and a missing or refused env path. Its
  numbers fall back to defaults. Configuration can raise enforcement, never silently lower it.

**Locked keys:** security policy is not configurable by any channel. These keys reject the whole file: `catalog`, `entries`,
`read_only_hint_categories`, `grant_params`, `path_params`, `irreversible_names`, `irreversible_prefixes`.

**Seeing it:** problems are printed **once** on stderr at start-up, with the count, the resulting mode and the error lines.
`aios_tool_registry_stats` shows the values, the source of each, and the error **codes**.

| Code | When |
|---|---|
| `TOOLREGCONF_ERR_IO` | file unreadable, missing (env path), not a regular file, refused by path rules, or default location unavailable |
| `TOOLREGCONF_ERR_FILE_SIZE` | file over 64 KiB |
| `TOOLREGCONF_ERR_PARSE` | not valid JSON, not an object, duplicate keys, or a value of the wrong type |
| `TOOLREGCONF_ERR_UNKNOWN_KEY` | a key that is not in the table above |
| `TOOLREGCONF_ERR_LOCKED` | a locked key |
| `TOOLREGCONF_ERR_BOUNDS` | a number out of bounds (clamped) |
| `TOOLREGCONF_ERR_ENV` | an env value is not an integer (that key is ignored) |

Configuration limitations:
- Changes take effect on the **next server start**. There is no reload.
- `unregistered_samples=0` is allowed. It only turns off the hashed samples; the counters remain.
- Windows file ACLs on the config file are not checked. Protect `$AIOSH_HOME` like the audit DB it sits beside.

## 7. Known limitations
- **Advisory by default.** The PEP, the agent-loop policy and dispatch still decide with their own name rules. The core service (§6b)
  compares the catalog with them in shadow mode, and can only tighten them in opt-in strict mode.
- **Per-name, not per-call.** `irreversible` is a floor. A call can still be irreversible by the classifier's C-3 flag (for example one
  `aios.agent_loop.step`); per-call classification can only add to it.
- **Per-name, not per-action** for multi-action tools (see §6).
- **Annotations are not yet applied** to the served pentest and core tools. Only the registry's own tools use catalog-derived annotations.
- **In-process immutability is by convention.** Python code in the same process can still mutate objects with `object.__setattr__` or `gc` tricks.
  There is no external route.
- **Substrates:** TS and Rust do not read `export_json()` yet. Rust's `is_irreversible` still treats four pentest discovery tools as
  reversible (research B4.4).

## 8. Evidence
[research](tasks/evidence/T-03363-research.md), [spec](tasks/evidence/T-03364-spec.md),
[scaffold](tasks/evidence/T-03365-tool-registry-data-model-scaffold.md),
[implementation](tasks/evidence/T-03366-tool-registry-data-model-implementation.md),
[unit](tasks/evidence/T-03367-tool-registry-data-model-unit-test.md),
[integration](tasks/evidence/T-03368-tool-registry-data-model-integration.md),
[security](tasks/evidence/T-03369-security.md), [hardening](tasks/evidence/T-03370-tool-registry-data-model-hardening.md)

Core service: [research](tasks/evidence/T-03373-research.md), [spec](tasks/evidence/T-03374-spec.md),
[scaffold](tasks/evidence/T-03375-tool-registry-core-service-scaffold.md),
[implementation](tasks/evidence/T-03376-tool-registry-core-service-implementation.md),
[unit](tasks/evidence/T-03377-tool-registry-core-service-unit-test.md),
[integration](tasks/evidence/T-03378-tool-registry-core-service-integration.md),
[security](tasks/evidence/T-03379-security.md), [hardening](tasks/evidence/T-03380-tool-registry-core-service-hardening.md)

CLI: [research](tasks/evidence/T-03383-research.md), [spec](tasks/evidence/T-03384-spec.md),
[scaffold](tasks/evidence/T-03385-tool-registry-cli-scaffold.md),
[implementation](tasks/evidence/T-03386-tool-registry-cli-implementation.md),
[unit](tasks/evidence/T-03387-tool-registry-cli-unit-test.md),
[integration](tasks/evidence/T-03388-tool-registry-cli-integration.md),
[security](tasks/evidence/T-03389-security.md), [hardening](tasks/evidence/T-03390-tool-registry-cli-hardening.md)

API: [research](tasks/evidence/T-03393-research.md), [spec](tasks/evidence/T-03394-spec.md),
[scaffold](tasks/evidence/T-03395-tool-registry-api-scaffold.md),
[implementation](tasks/evidence/T-03396-tool-registry-api-implementation.md),
[unit](tasks/evidence/T-03397-tool-registry-api-unit-test.md),
[integration](tasks/evidence/T-03398-tool-registry-api-integration.md),
[security](tasks/evidence/T-03399-security.md), [hardening](tasks/evidence/T-03400-tool-registry-api-hardening.md)

Configuration: [research](tasks/evidence/T-03403-research.md), [spec](tasks/evidence/T-03404-spec.md),
[scaffold](tasks/evidence/T-03405-tool-registry-config-scaffold.md),
[implementation](tasks/evidence/T-03406-tool-registry-config-implementation.md),
[unit](tasks/evidence/T-03407-tool-registry-config-unit-test.md),
[integration](tasks/evidence/T-03408-tool-registry-config-integration.md),
[security](tasks/evidence/T-03409-security.md), [hardening](tasks/evidence/T-03410-tool-registry-config-hardening.md)
