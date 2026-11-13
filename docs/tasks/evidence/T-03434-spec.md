# T-03434 Specification: Tool Registry & Taxonomy — observability

- Date: 2026-11-13
- Research: [T-03433-research.md](T-03433-research.md) (facts F1–F10, decisions D1–D6)
- Status: all six recommended decisions are adopted. U1 is answered with counter + log and no new rows. U2 is
  answered by deriving the counters in the policy layer. U3 is answered with no CLI ring metrics.
- "AIOS-specific" marks names this project defines. Nothing here claims to be an upstream API. OpenTelemetry and SRE
  vocabulary is used as naming guidance only.

## 1. Components
| Component | New / reused | Role |
|---|---|---|
| `tool_registry_policy` | reused, extended | Per-surface policy counters (D1) |
| `capability_redeem` | reused, extended | Redeem/refusal counters, refusal classes, masked log event (D2) |
| `tool_registry_observability` | **new module (AIOS-specific)** | Ring-derived metrics (D3) and `health()` (D4) |
| `aios_tool_registry_stats` | reused MCP tool, extended output | Adds `policy`, `capability`, `health` (D5) |
| `aios_tool_registry_metrics` | **new MCP tool (AIOS-specific)**, read-only | Ring metrics for a bounded window (D5) |
| `audit_client.grant_redeem` / `audit_ring` | reused, unchanged | The durable source for D3 |
| `aiosh-tool-registry` CLI | unchanged | Stays DB-free (§6c of the operator doc) |

## 2. Contract

### 2.1 `tool_registry_policy.policy_stats() -> dict` (new)
```
{"surfaces": {"dispatch":   {"evaluations": int, "registry_added_grant": int, "registry_added_irreversible": int,
                             "failures": {"<ExceptionType>": int, ...}},
              "agent_loop": {...same keys...}}}
```
- `evaluate()` increments `evaluations` once per call, after the surface check. A `ValueError` for a bad surface counts
  nothing.
- `registry_added_grant` counts verdicts with `registry_added_grant` true. `registry_added_irreversible` counts verdicts
  where `irreversible` is true and `legacy_irreversible` was false.
- `failures` is keyed by exception type name, with at most `MAX_FAILURE_TYPES` = 16 keys; further types go to `"other"`.
  The once-per-surface stderr line (T-03426) is unchanged.
- `preview()` counts nothing (it stays pure, T-03428).
- `reset_process_state()` also zeroes these counters.

### 2.2 `capability_redeem` (extended)
- `REFUSAL_CLASSES = ("missing", "malformed", "unknown_or_revoked", "expired", "already_redeemed", "scope",
  "unavailable", "other")`.
- `classify_refusal(reason: str) -> str` maps the gate's own reason strings to a class:

  | Reason text | Class |
  |---|---|
  | "capability token required" | `missing` |
  | "malformed", or "exceeds maximum allowed length" | `malformed` |
  | "unknown or revoked grant" | `unknown_or_revoked` |
  | "expired" | `expired` |
  | "already redeemed" | `already_redeemed` |
  | "not in grant scope", or "blocked by grant scope" | `scope` |
  | "unavailable", or "audit ring write failed" | `unavailable` |
  | anything else | `other` |

- `capability_stats() -> {"redeemed": {tool: int}, "refused": {tool: {class: int}}, "refused_total": int}`. Tool keys
  are limited to the canonical names passed by the six gated call sites; any other tool string is counted as `"other"`.
- Each refusal emits **one** log record on logger `aiosh_mcp.capability` at WARNING:
  ```
  capability refused {"event": "capability.refused", "tool": "<canonical>", "class": "<class>", "token": "<hash>"}
  ```
  - `<hash>` is `blake2b(token, key=<per-process random 16 bytes>, digest_size=6)` hex. It is stable within a process
    (it correlates repeats) and useless across processes.
  - `""` stands for a missing or non-string token.
  - The reason text is **never** logged; it can echo the token.
  - The module adds no handlers (the library rule). Without app configuration, Python's last-resort handler prints
    WARNING records to **stderr**.
- On success the existing `pep.capability.redeem` audit row gains `"tool": <canonical>` inside its `args`. This adds
  no column and no row.
- `reset_stats()` is for tests.

### 2.3 `tool_registry_observability` (new)
- Constants: `DEFAULT_WINDOW = 10_000`, `MAX_WINDOW = 100_000`, `DEFAULT_QUERY_DEADLINE_S = 10.0`, and
  `HEALTH_STATES = ("ok", "degraded", "failing")`. These are the agent-loop values (F9).
- `ring_metrics(db_path=None, window=DEFAULT_WINDOW, deadline_s=DEFAULT_QUERY_DEADLINE_S) -> dict`:
  ```
  {"window": int, "rows_scanned": int, "db": "present" | "absent",
   "registry_refusals": {"strict": int, "unavailable": int, "by_tool": {tool: int}},
   "capability_redeemed": {"total": int, "by_tool": {tool: int}}}
  ```
  - It opens `file:<path>?mode=ro` (it cannot write) and scans the newest `window` rows of `audit_ring`.
  - A row counts as a registry refusal when `outcome = "refused"` and `outcome_detail` contains
    `(tool registry strict, catalog ` (strict) or `(tool registry unavailable, strict: fail closed)` (unavailable).
  - A row counts as a capability redemption when `tool = "pep.capability.redeem"`. Its `by_tool` comes from
    `args.tool`, or `"unknown"` for rows written before T-03436.
  - `by_tool` maps hold at most 64 keys; the rest go to `"other"`.
  - A progress handler enforces `deadline_s`.
- `health(stats: dict) -> str`:
  - `failing` if the catalog or service is unavailable (`stats` carries an error), or any strict-mode policy failure
    has occurred (`policy.surfaces.*.failures` non-empty while the mode is strict);
  - `degraded` if `config_errors` is non-empty, any shadow-mode policy failure has occurred, or `reports.suppressed > 0`;
  - otherwise `ok`.

### 2.4 MCP surfaces
- `aios_tool_registry_stats()` keeps its existing keys and adds:
  - `policy`: §2.1;
  - `capability`: §2.2;
  - `health`: §2.3.

  The fixed-key test is updated in the same PR.
- `aios_tool_registry_metrics(window: int = 10000)` returns `{"ok": true, "data": ring_metrics(...)}`.
  - It is read-only: catalog entry `aios.tool_registry.metrics` (`read_only`, no grant, scope `none`), needs no token,
    and goes through the same catalog-derived annotation pass as every tool.

## 3. Error cases
| Case | Result |
|---|---|
| `window` < 1 or > `MAX_WINDOW`, or not an int | `{"ok": false, "error_code": "TOOLOBS_ERR_WINDOW"}`; no DB access |
| Audit DB file absent | `ok: true`, `db: "absent"`, all counts 0 (a fresh host is healthy, not an error) |
| DB unreadable, schema missing, locked past 5 s, or deadline exceeded | `{"ok": false, "error_code": "TOOLOBS_ERR_READ", "error": "<ExceptionType>"}` (type only, no path or message) |
| A counter update raises | Swallowed: observability never changes a verdict or blocks a call |
| Logging raises (a broken handler) | Swallowed by `logging` (`raiseExceptions` aside); the refusal stands |

## 4. Persistence and audit effects
- **No new tables, columns or audit rows.** The only durable change is the extra `args.tool` key on the existing
  `pep.capability.redeem` row (§2.2).
- Counters are in-process, reset at restart and by `reset_process_state()` / `reset_stats()`. They never go to disk.
- Ring reads are read-only (`mode=ro`). The metrics tool cannot create the DB, because an absent file is reported as
  `absent` and not opened.
- Log records go to the `logging` system (stderr by default), **never stdout**, which is the MCP JSON-RPC channel.

## 5. Invariants (AIOS-specific)
- **TOOLOBS-INV1 Side channel only:** no counter, log or metric read changes a policy verdict, a gate decision or a
  return value.
- **TOOLOBS-INV2 No secrets:** a token is never logged or returned in clear. Only the per-process keyed hash is. A
  refusal reason is never logged.
- **TOOLOBS-INV3 Bounded:** every map has a fixed key cap (16 failure types, 64 tools, 8 refusal classes). The ring
  window is ≤ 100 000 rows, and a deadline bounds each query.
- **TOOLOBS-INV4 Read-only ring:** metrics open the DB with `mode=ro` and never create it.
- **TOOLOBS-INV5 No stdout:** nothing in these components writes to stdout.
- **TOOLOBS-INV6 No new rows:** the number of audit rows written per call is unchanged.

## 6. Acceptance tests (to be written in T-03437/T-03438)
- **Happy path:**
  - a strict refusal increments `registry_added_grant`, and `ring_metrics` reports it by tool;
  - a redeemed grant increments `redeemed[tool]`, and the ring counts it with `args.tool`;
  - `health` is `ok` on a clean host.
- **Failure path:**
  - for each refusal class, one counter increment and exactly one WARNING record with the hashed token;
  - the token text is absent from every record and output;
  - an absent DB gives `db: "absent"`; a locked DB or a deadline gives `TOOLOBS_ERR_READ`; a bad window gives
    `TOOLOBS_ERR_WINDOW`;
  - a strict-mode policy failure gives `health == "failing"`.
- **Audit effects:** rows per call are unchanged (INV6); the DB file is not created by the metrics tool (INV4).
- **Bounds:** 100 distinct failure types collapse to ≤ 16 + `other`; 1 000 distinct tool strings to ≤ 64 + `other`.

## Security audit (standing rule)
- **No code changes** in this task (specification only).
- **The design reduces risk:**
  - it makes forged-token attempts visible (they were invisible, research F6) without letting an unauthenticated
    caller grow the audit ring (no new rows);
  - tokens appear only as per-process keyed hashes;
  - reason strings, which can echo the token, are never logged.
- **DoS:** every new structure is capped, and ring reads are windowed, deadline-bound and read-only.
- **New tool:** `aios_tool_registry_metrics` is read-only and token-free, like `aios_tool_registry_stats`. Its output
  is aggregate counts plus tool names (public catalog data), with no grant ids and no paths.
- **PoR (I-2):** no state-changing path is added or changed. The redemption logic is untouched apart from one extra
  `args` key. **No bypass.**
