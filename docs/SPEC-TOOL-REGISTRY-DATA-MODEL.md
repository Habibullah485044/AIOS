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
