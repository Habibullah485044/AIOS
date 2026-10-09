# Research: Compliance Mapping — Configuration (T-02903)

## Task Metadata
- **Task ID**: T-02903
- **Title**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / configuration: Research
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Status**: Completed
- **Date**: 2026-10-08
- **Artifact Path**: `docs/tasks/evidence/T-02903-configuration-research.md`
- **Depends on**: T-02902 (MCP/API surface — Verification & Evidence)

## 1. Executive Summary

This research establishes facts, constraints, and prior art for **configuring** the Compliance
Mapping subsystem (the sub-epic starting at `T-02903`). The headline finding: Compliance Mapping
is the **only** subsystem in `aiosh-core` with no `*_config.rs` module while 27 sibling
subsystems have one, and its two substrates currently disagree about where the store lives —
the Python surface honours `AIOSH_COMPLIANCE_MAP_PATH`, the Rust CLI does not read it at all.
Configuration today is therefore *implicit* (one env var + one `--path` flag + two hardcoded
constants), and the README documents a default path that neither substrate implements.

No code is changed by this task; §6 lists the decisions required before `T-02904` (Specification).

## 2. Established Facts vs Assumptions

### 2.1 Established Facts (verified in this checkout, with locations)

**F-1 — Compliance Mapping has no config module; 27 siblings do.**
`code/aiosh-rust/aiosh-core/src/` contains `compliance_data_model.rs` and `compliance_service.rs`
only. A `*_config.rs` module exists for: `audit_chain`, `base_image`, `capability`, `ci`,
`distro`, `doc_index`, `evidence`, `handoff`, `hardware`, `kernel_module`, `ledger`, `network`,
`package`, `pep`, `pep_grant`, `privilege`, `release`, `repo_health`, `sandbox`, `secret`,
`secrets`, `service`, `session`, `system_update`, `threat_model`, `toolchain`, `triage` (27).
On the Python side the only config loader is `aiosh_mcp/release_config.py`; `aiosh_mcp/compliance.py`
has none.

**F-2 — The entire current configuration surface is two constants, one env var, one flag.**

| Knob | Python (`aiosh_mcp/compliance.py`) | Rust (`aiosh-core/src/compliance_service.rs`, `aiosh-cli/src/main.rs`) |
|------|------------------------------------|------------------------------------------------------------------------|
| Default store path | `DEFAULT_STORE_PATH = "docs/compliance_map.json"` (line 33) | `DEFAULT_COMPLIANCE_MAP_PATH = "docs/compliance_map.json"` (line 13) |
| Path override | `AIOSH_COMPLIANCE_MAP_PATH` via `store_path()` (lines 229-231) | **not read**; only `--path` flag (`main.rs` `cmd_compliance`, ~line 19446) |
| Store size cap | `MAX_COMPLIANCE_STORE_SIZE = 1024 * 1024` (line 34), enforced on load **and** save | same constant re-exported (`lib.rs:558`) |
| Entry capacity | `MAX_COMPLIANCE_ENTRIES_CAPACITY = 1024` (line 42) | parity via shared constants |
| String bounds | ID ≤ 64, title ≤ 128, desc ≤ 2048, notes ≤ 2048, threats ≤ 16, tags ≤ 16 (lines 36-41) | identical validation order (`ComplianceMappingEntry::new`) |

**F-3 — The Rust CLI does not honour `AIOSH_COMPLIANCE_MAP_PATH`.**
Verified: zero occurrences of that identifier under `code/aiosh-rust/aiosh-core/src` and
`code/aiosh-rust/aiosh-cli/src` (`rust_hits=0`). `cmd_compliance` resolves
`parse_flag(rest, "--path")` and otherwise falls straight back to
`DEFAULT_COMPLIANCE_MAP_PATH`. Consequence: setting the env var moves *only* the Python/MCP
store; the same operator running `aiosh compliance list` reads a different file.

**F-4 — The MCP tool exposes no path parameter at all.**
`aios_compliance(action, id, framework, status, control_id, target_type, target_ref,
threat_ids, mitigation_summary, tags, reason, gate_id, grant_id)` — there is no `path`
argument, so an MCP caller can only reach a non-default store through the process environment.
(The Rust CLI takes `--path`; the MCP surface cannot express the same thing.)

**F-5 — README documents a default path that no substrate implements.**
`code/aiosh-mcp/README.md:575` states the store is
"`AIOSH_COMPLIANCE_MAP_PATH`, default `$AIOSH_HOME/compliance_map.json`". Both substrates
actually default to the **repo-relative** `docs/compliance_map.json` (F-2). The README's own
example block (lines 634, 644-646) passes `--path` explicitly and so never exercises the
disagreement. Additionally `docs/compliance_map.json` does not exist in this checkout — the
default store is created only by `compliance init`.

**F-6 — Prior art for a config module is mature and consistent.**
Every sibling config module follows the same shape: strongly-typed struct deriving
`Serialize/Deserialize`, `#[serde(default)]` on fields, a `Default` impl carrying the real
defaults, hard `MIN_..`/`MAX_..` bounds validated in a `validate()`/`from_*` path, a byte cap on
the reader, and a `from_env()` cascade. Real cap constants found:
`audit_chain_config.rs:35 MAX_CONFIG_FILE_BYTES = 64 * 1024` (64 KiB, enforced at
`audit_chain_config.rs:104-105`), `capability_config.rs:11 MAX_CONFIG_BYTES = 64 * 1024`,
`doc_index_config.rs:10 MAX_CONFIG_BYTES = 64 * 1024 // 64 KiB`, and the per-domain data caps
(e.g. `base_image_config.rs:32` 10 GiB artifact / 10 MiB file read bound at lines 119-123;
`audit_chain_config.rs:85` `max_extensions_bytes` bounded to `[1024, 1_048_576]`).

**F-7 — `from_env()` precedence precedent (exact, `threat_model_config.rs:136-158`).**
1. If `AIOS_THREAT_MODEL_CONFIG` is set and passes hygiene (non-empty, no `..`, no control
   chars, `len <= 1024`) → `load_from_path(custom).unwrap_or_default()`; **invalid value falls
   back to defaults, never panics**.
2. Else if `DEFAULT_THREAT_CONFIG_PATH` exists → `load_from_path(...).unwrap_or_default()`.
3. Else → `Self::default()`.
4. Then independent env overrides apply on top (`AIOS_THREAT_MODEL_PATH` for the store,
   `AIOS_THREAT_CAPACITY` for capacity, range-checked before assignment).

**F-8 — Default config-path convention is *not* uniform across the repo.**
Three coexisting conventions, all real: `docs/*_config.json` (`doc_index_config.rs:11`,
`repo_health_config.rs:11`), `.aios/*_config.json` (`privilege_config.rs:11`,
`secret_config.rs:9`), `config/*.config.json` (`evidence_config.rs:12`). The `config/` directory
in this checkout holds `distro.json`, `evidence.config.json`, `toolchain.json` — no compliance
file. The Python `release_config.py` resolves `$AIOSH_RELEASE_CONFIG` → `config/release.json`
→ hardcoded `_DEFAULTS`, and bounds `_MAX_FILE_SIZE`/`_MIN_FILE_SIZE` before use.

**F-9 — Path hygiene for the compliance store is already specified and enforced on both
substrates.** `compliance.py:206-224 validate_path` and `ComplianceService::validate_path`
(`compliance_service.rs:~80`) agree: reject empty, reject `..`, require a `.json` final
component, reject symlinks (`os.path.lexists and os.path.islink`), error code
`COMPLIANCESVC_ERR_PATH_TRAVERSAL`.

### 2.2 Assumptions (not yet verified — each needs a decision or a test)

- **A-1** — Operators will want to relocate the store per deployment (CI, container, multi-tenant
  host). *Status: plausible but **not evidenced** by any existing issue/doc in this repo; the
  only current driver is F-3/F-5 (the two substrates disagree).*
- **A-2** — Capacity (`1024` entries) and string bounds should be operator-tunable rather than
  compile-time constants. *Status: assumption; no sibling exposes entry-count as a config field
  except via domain-specific `max_*` fields (`threat_model` capacity, `base_image`
  artifact size).*
- **A-3** — A `compliance_config.json` should exist as a *file*, not just env vars. *Status:
  assumption; three precedent conventions exist (F-8) and **they disagree**, so this cannot be
  settled without a decision (D-2).*
- **A-4** — Config reads must not be PEP-gated (reads are ungated today) while a config
  *mutation* would be a state change. *Status: assumption; follows the documented compliance
  contract (reads never touch the store; `register`/`status`/`init` are PEP-gated writes) but no
  config-mutation path exists yet to confirm it against.*

## 3. Prior Art & Authoritative Sources

### 3.1 External sources (each checked against its primary document for this task)

1. **NIST SP 800-53 Rev. 5, CM-6 "Configuration Settings"** — "Establish and document
   configuration settings for components employed within the system that reflect the most
   restrictive mode consistent with operational …". Verified title/statement against the
   published control (csrc.nist.gov SP 800-53 r5 upd1; csf.tools CM-6 r5 rendering).
   Relevance: configuration values must be *documented and bounded*, which is exactly what a
   typed config module with declared `MIN_`/`MAX_` gives.
2. **CWE-15 — External Control of System or Configuration Setting** (MITRE,
   `cwe.mitre.org/data/definitions/15.html`) — "Allowing external control of system settings can
   disrupt service or cause an application to behave in unexpected, and potentially malicious
   ways." Verified title/summary. Relevance: **this is the governing risk for F-3** — an env var
   that silently relocates security-relevant state is CWE-15 territory unless the value is
   validated and the override is observable.
3. **CWE-22 / CWE-59 (path traversal / symlink following)** — already the stated basis of
   `validate_path` in both substrates (F-9); any config-supplied path must pass the same gate.

### 3.2 Internal prior art

4. **`threat_model_config.rs`** — the closest analogue (configures a JSON store: path + capacity
   + caps + audit toggles). Its `from_env()` (F-7) is the template to copy, including the
   "invalid env value → defaults, never panic" rule.
5. **`doc_index_config.rs` / `repo_health_config.rs`** — nearest-neighbour default paths
   (`docs/*_config.json`), which is also where the compliance **store** already lives
   (`docs/compliance_map.json`), making `docs/` the path of least surprise.
6. **`aiosh_mcp/release_config.py`** — the Python-side loader precedent (env → file → defaults,
   with numeric bounds checked before acceptance).
7. **T-02741 `configuration-research.md`** — sibling research doc for Threat Model; used for
   structure only. **Its ADR citations did not verify** — see F-10.

### 3.3 Citation-integrity finding (recorded honestly)

**F-10 — The precedent research doc cites ADR clauses that do not exist in those ADRs.**
`docs/tasks/evidence/T-02741-configuration-research.md` §3 attributes to
"ADR-0035 §D-2" the rule *"Kernel and service configuration files must be deterministic,
auditable, and subject to strict size caps (maximum 64 KiB for config files)"*, and to
"ADR-0036 §B-1" the rule *"configuration files must reside within approved system directories
(`.aios/` …), rejecting relative directory traversal escapes"*.

Verified against the primary documents:
- `mostimportanAIfolder/ADR-0035-aios-s-rank-agent-architecture.md` — §D-2 is titled *"MCP is
  the **only** tool-call protocol inside the kernel surface"* (line 43). §D headings run D-1…
  D-6 only; **none** discuss configuration files. A repo-wide grep for "deterministic,
  auditable" / "configuration files must" returns nothing.
- `mostimportanAIfolder/ADR-0036-audit-ring-retention.md` — structure is
  `1. Context`, `2. Decision` (`D-1`…`D-5`), `3. Consequences`. **There is no §B-1** and the
  document contains no configuration-path rule (grep for "config|traversal|approved system
  director" → no matches).

The *substance* of both claims is nonetheless real and independently verified in code: the 64 KiB
config cap exists as `MAX_CONFIG_FILE_BYTES`/`MAX_CONFIG_BYTES` in three config modules (F-6) and
the traversal/symlink rejection exists as `validate_path` (F-9). So the rules are true; the
**attribution** is wrong. This task cites the code locations and the external controls instead,
and flags the mis-citation as a doc-debt item (D-7).

## 4. Configuration Surface: What Exists, What Is Missing

**Exists (implicit):** default path constant ×2, one env var (Python-only), one CLI flag
(Rust-only), one 1 MiB store cap, one 1024-entry capacity, per-field string bounds, path hygiene.

**Missing relative to sibling subsystems:**
- no `compliance_config.rs` / `compliance_config.py`;
- no config file (so no documented, reviewable, versioned configuration — CM-6's core ask);
- no cross-substrate agreement on override precedence (F-3);
- no way for an MCP caller to select the store (F-4);
- no `from_env()`-style hygiene validation on `AIOSH_COMPLIANCE_MAP_PATH` itself: today
  `store_path()` returns the raw env string, and only `validate_path()` later rejects it — so a
  bad value surfaces as an error at *use* time rather than a bounded fallback at *load* time
  (divergent from the `threat_model` precedent in F-7).

## 5. Security & Robustness Considerations (CWE mapping)

- **CWE-15** — env-controlled store location: must be hygiene-checked and observable in the
  audit/config view, not silently applied (drives D-3).
- **CWE-22 / CWE-59** — any config-supplied path must re-enter `validate_path`; config load must
  not become a second, weaker path gate.
- **CWE-400** — the config reader needs its own byte cap (64 KiB precedent, F-6) *independent of*
  the 1 MiB store cap, so a malicious config cannot pre-allocate or oversized-read.
- **Fail-closed vs fail-open** — malformed config must never panic (precedent:
  `unwrap_or_default()`), but a *rejected* config must still leave an honest, auditable outcome
  rather than silently reverting to defaults in a security-relevant field. Which fields may fall
  back and which must hard-fail is a decision (D-5).

## 6. Unknowns & Decisions Needed Before Implementation (T-02904+)

| # | Decision | Options | Recommended | Why it blocks work |
|---|----------|---------|-------------|--------------------|
| **D-1** | Cross-substrate override precedence: should Rust read `AIOSH_COMPLIANCE_MAP_PATH`? | (a) Rust learns the env var, both fall back to `docs/compliance_map.json`; (b) Python drops it, only `--path` configures; (c) introduce a config file both read | **(a) then migrate to (c)** | F-3 means the two substrates can silently disagree about which store is authoritative — the worst outcome for a compliance artifact |
| **D-2** | Config file location convention | `docs/compliance_config.json` · `.aios/compliance_config.json` · `config/compliance.config.json` | **`docs/compliance_config.json`** | F-8 shows three live conventions; the compliance store already lives in `docs/`, so the config beside it keeps one subsystem in one place |
| **D-3** | Is the store path a *documented config field* or an *operator env override*? | config field only · env only · field + env with env winning | **field + env, env wins (validated)** | Matches F-7 precedent and satisfies CWE-15 observability |
| **D-4** | Which knobs are configurable? | path only · path + entry capacity · path + capacity + all string bounds + audit toggles | **path + entry capacity + audit toggles** (leave string bounds compiled) | A-2; string bounds are contract-level (parity-tested) and changing them per-host breaks cross-substrate equality |
| **D-5** | Failure policy per field on malformed config | all → defaults · path → default, capacity → clamp, audit toggles → fail-closed | **mixed: inert fields default; security-relevant fields fail closed with an auditable error** | §5 fail-open/fail-open tension; needs an explicit rule before the loader is written |
| **D-6** | Config file byte cap | 64 KiB (repo precedent) vs 1 MiB (store cap) | **64 KiB** | F-6: three config modules already use it |
| **D-7** | Fix the mis-citations in `T-02741-configuration-research.md` (F-10)? | fix now · defer to a doc task · leave | **defer to a doc-debt task** | Out of scope for a no-code-change research task, but must not be silently propagated |
| **D-8** | Does a config mutation require a capability grant + audit row? | yes (treat as write) · no | **yes** | A-4; consistent with `register`/`status`/`init` being PEP-gated |
| **D-9** | Does `compliance init` write the config file too, or only the store? | both · store only | **store only; config file is created by an explicit config action** | Keeps `init`'s current one-row contract intact |

**Explicitly unknown (not decidable from this repo alone):**
- whether any operator actually needs >1024 compliance mappings (drives D-4's capacity knob);
- whether deployment environments will ship the config file or set env vars (drives D-3 weighting);
- intended multi-tenant story (one store per tenant vs one shared) — no evidence either way.

## 7. Task Acceptance Check

- [x] Evidence file exists and separates facts (§2.1) from assumptions (§2.2).
- [x] No code changed — this commit touches only this file (verified: `git status` shows docs
      only).
- [x] Decisions needed are listed explicitly (§6, D-1…D-9 + the unknowns).
- [x] Citations verified against primary sources, including a correction of a prior doc's
      mis-citation (F-10).
