# Security Audit — `code/aiosh-rust/aiosh-cli/src/main.rs` (21,065 lines)

Status: IN PROGRESS — line-by-line read. Machine sweep (40 vuln patterns) done on all lines.
Read coverage: lines 1–5574 verbatim. Findings below.

## Machine sweep results (whole file)
- `unsafe`: 0 | `Command::new`/subprocess: 0 | shell (`sh -c`, `/bin/sh`): 0
- `std::env::set_var/remove_var`: 0 | `md5/sha1/rand/thread_rng`: 0 | `chmod/set_permissions/0o777`: 0
- `panic!/unreachable!/todo!`: 0 | `.unwrap()/.expect(`: 84 | `fs::remove*`: 33 | path ops: 24 | secret-looking lines: 222 | temp paths: 30

## Findings (F1–F10: lines 1–5574; F11–F24: lines 5575–21,065)

### F1 — Audit DB falls back to world-writable `/tmp` (line 29–36) — HIGH (multi-user hosts)
`ai_home()` = `$AIOSH_HOME`, else `$HOME/.aios`, else **`/tmp`**; `db_path()` = `{home}/audit.db`.
If HOME is unset (cron/systemd/su edge cases), the tamper-evident audit ring is opened at the
predictable path `/tmp/audit.db`. Pre-planted symlink or file => audit log injection/destruction or
arbitrary-file overwrite by whoever owns the link (CWE-377/59). Fix: refuse to run without a
real home, or use `$XDG_RUNTIME_DIR`, O_NOFOLLOW+O_EXCL semantics.

### F2 — `expect()` panics on I/O paths (48–57, 110 `expect("audit write")`) — MEDIUM (DoS/availability)
`open_context()` panics on open/prepare; `emit()` panics on audit write. A corrupt/unwritable DB or
hostile `--store`/env path aborts the whole CLI (exit 101) with no structured error envelope.
Panics are fail-closed for audit (good) but ungraceful and unreachable-by-design per their own
T-00038 hardening note. Also `ok_out()` L164 uses `.unwrap()` on serde serialization.

### F3 — Audit actor identity taken from attacker-controllable env (line 70–74) — LOW (audit spoofing)
`actor_id = user:{USER}@{HOSTNAME}`. Any local caller can set USER/HOSTNAME to forge the audit
actor. Cosmetic for a CLI, but this row is the trust anchor of the audit ring.

### F4 — Terminal escape sanitization applied inconsistently (CWE-150) — MEDIUM
`sanitize_terminal` / `sanitize_terminal_output` (150–162) correctly replace control chars with
U+FFFD — but they are used **only** in the `fs_layout` command family. Raw untrusted fields from
store/config files are printed unsanitized elsewhere, e.g.
- `cmd_distro` `p.name`, `p.justification`, `v.violations.join("; ")`
- `cmd_image` `manifest.kernel.cmdline`, `plan.stages[].description/command_template`
- `cmd_service` `svc.description`, `spec.exec_start`, policy `prohibited_*.join(", ")`
- `cmd_session` seat/display/username, `cmd_package` `pkg.description`
Per their own threat model (agent-written/shared stores, imported fstab), a hostile store injects
ESC sequences into operator terminals (clipboard/title hijack, log forgery). JSON output is safe
(serde escapes). Fix: route all human-readable output through `sanitize_terminal`.

### F5 — Inconsistent path/argument validation across command families — MEDIUM
Good: `service/session/package/layout` validate `--store` (≤1024, no control chars), names
(≤64/≤128, no control), filter patterns (≤256), limits (1..10_000), inline/file payloads (1 MiB).
Missing: `cmd_distro` / `cmd_image` `--store` and `--config` paths go straight to
`Path::new(...)` with no length/control-char check (cmd_distro ~255, cmd_image ~613, 749, 764).
Same for `--spec`/`--policy` in several families (validated only where a helper exists).

### F6 — Unbounded `read_to_string` (memory DoS) — MEDIUM
`session policy --spec` (~line 3155) calls `std::fs::read_to_string(spec_input)` with **no size
cap**, unlike its sibling readers (1 MiB caps) and unlike `fs_layout` which uses
`read_bounded_text_file` (bounded, rejects FIFOs/devices — the correct pattern, with a comment
explaining the FIFO//dev/zero hang risk). Feeding a 10 GB file or `/dev/zero`-like path here
exhausts memory or hangs.

### F7 — Metadata size check is check-then-use (TOCTOU) — LOW
The 1 MiB guards use `fs::metadata()` then `read_to_string()`; file can grow in between (local
attacker). `fs_layout` path avoids this via `read_bounded_text_file`.

### F8 — State-changing commands report success when persistence fails — MEDIUM (integrity)
`session action` (~3055) and `session create` (~3115): `save_to_path` failure only prints
`Warning: failed to persist...` yet the command exits 0 and writes a **success** audit row.
Contrast `cmd_service action`, which correctly returns 1 with `PERSIST_FAILED`.
Audit ring then contains a success row for a change that was lost (evidence integrity).

### F9 — Audit rows misuse `target` field for error codes — LOW (audit integrity)
`service stats` / `session stats` (~2600, ~3260) pass `Some("INVALID_ARGUMENT")`,
`Some("LOAD_STORE_FAILED")`, `Some("POLICY_RESOLUTION_FAILED")` as the row's **target**.
Query/forensics filtering by target is polluted; looks like log-structure abuse.

### F10 — `--spec`/`--fstab` "file or inline" ambiguity — LOW
Arg is treated as a file if `Path::exists()`, else as inline content (service ~1120, session
~2620, package ~5390, layout ~3540). Local TOCTOU + surprising behavior: an inline JSON string
that happens to match a existing file path gets read from disk instead.

## Positive controls observed
- `main()` lossy-converts non-UTF-8 argv instead of panicking (T-00038 hardening) — good.
- No `unsafe`, no subprocess/shell, no crypto, no env mutation in this file.
- fs_layout uses a genuinely hardened bounded reader (rejects FIFO/char devices, size-capped).
- Consistent `{code, data, error}` JSON envelope; serde escapes control chars in JSON output.

### F11 — `evidence scan` out-of-bounds slice panic (line ~7817) — LOW (DoS)
`&r["sha256"].as_str().unwrap_or("")[..8]` — if `as_str()` ever yields a string shorter than
8 bytes this panics (byte index out of range). The sibling code in `cmd_secrets` correctly
guards with `if f.fingerprint.len() >= 8`. Fix: use `.get(..8).unwrap_or(..)`.

### F12 — Predictable `/tmp` default for CI results (line ~7900) — MEDIUM (multi-user)
`cmd_ci` defaults `--file` to `$AIOSH_CI_RESULTS` or **`/tmp/aiosh-ci-results.json`**, then
parses it and feeds `triage ingest`. Fixed name in a world-writable dir: another user can
pre-plant that file (or symlink it at a victim's umask) => forged CI pass/fail state and
forged regression triage records. Same class as F1.

### F13 — Widespread `.expect()` panics across audit/agent paths — MEDIUM (DoS)
Additional instances beyond F2: `cmd_status` ("verify"), `cmd_audit_tail` ("tail"),
`cmd_audit_verify` ("verify", "verify_full"), `cmd_audit_segments` ("segments"),
`cmd_audit_seen` ("seen"), `cmd_grant_create` ("grant create"), `cmd_grant_list`
("grant list"), `cmd_grant_revoke` ("revoke"), `cmd_agent` (`pep.get(...).expect("grant get")`),
`cmd_classify` (serde `unwrap`). Any unexpected DB/service error aborts with exit 101 and no
structured `{code,data,error}` envelope — a caller parsing JSON output sees a crash, and the
audit row for the attempted operation is never written (an attacker who can corrupt the store
can suppress audit records for subsequent commands).

### F14 — `aiosh run` sandbox policy silently falls back to defaults — LOW
`parse_policy` = `SandboxPolicy::from_json(..).unwrap_or_default()` (line ~8440). If the
constructed policy ever fails to parse, `unwrap_or_default()` substitutes whatever
`SandboxPolicy::default()` is — with no error surfaced. Fail-open policy construction.
(Constructor is internal today, so exploitable only if defaults loosen.)
Note: `cmd_run` itself is otherwise well built — no shell, argv array passed to
`sandbox_exec`, `no_new_privs` + seccomp denylist of privileged syscalls, execute allowlist.

### F15 — `cmd_agent` attacker-influenced URL and prompt handling — LOW
`--ollama-url` is passed to the agent loop verbatim (SSRF-style: local user can point the
agent at any URL — expected for a CLI, but worth an allowlist/scheme check: `file://` or
`http://169.254.169.254` style targets depend on core's client). `max_steps` correctly
clamped to 1..32. Prompt truncated to 256 chars in the audit row (good — no log bloat).

### F16 — Path argument validation inconsistent (summary of the pattern)
Validated (≤1024, no control chars): `--store` in service/session/package/layout/kernel_module;
`--proc-modules`; `--config`/`--policy` in service/session/package stats+config.
NOT validated: `--store` in distro/image/handoff/triage, `--config` in handoff/triage/repo/doc/
secrets/toolchain/evidence `--manifest`, `--backup-dir`, `--target-path` (backup), `--file`
(CI), `--repo`. These reach `Path::new` directly. Control chars in a path can corrupt terminal
logs when echoed back (the error messages print the path); length is only bounded by argv.

### F17 — `handoff` silently swallows store-recovery warnings (line ~6135) — LOW
`let (mut store, _recovery_warning) = load_or_recover_with_config(..)` — if the handoff store
was corrupt and auto-recovered, the operator is never told (all other families surface this).

## Positive controls observed (updated)
- kernel_module family consistently wraps every untrusted string in `sanitize_terminal` — the
  model the other families should follow.
- `aiosh run`: no shell, argv-array exec, seccomp denylist, no_new_privs, exec allowlist.
- `cmd_secrets`: fingerprints truncated only after a length guard; snippets are `redacted_snippet`.
- `cmd_task`: strict argv grammar (`--` delimiter, 4096-byte text cap, <=16 evidence items),
  every outcome audited including refusals (ADR-0035 F-2).

### F18 — Secret vault & privilege store silently reset on corrupt load — HIGH (data loss / authz state)
`cmd_secret` (line ~17460) and `cmd_privilege` (line ~17040) both do
`SecretService::load_from_path(store_path).unwrap_or_default()` / `PrivilegeService::load_from_path(..).unwrap_or_default()`.
If the vault/privilege file is corrupted or unreadable, the CLI proceeds with an **empty in-memory
store** and reports normal operation. Consequences:
- `secret store` afterwards succeeds and `save_to_path` **overwrites the corrupt vault with a
  single-entry store — every other secret is silently destroyed** (no backup, no warning).
- `secret get` reports `NOT_FOUND` for secrets that still exist on disk → operator may rotate
  credentials that were never compromised, or wrongly conclude a leak.
- privilege contexts/elevation history are silently dropped.
Contrast: `secret observability`/`secret recovery` in the SAME command correctly propagate
load errors. Fix: treat load failure as fatal (like `cmd_service` does with `LOAD_STORE_FAILED`).
Verified against core: `SecretService::load_from_path` returns `Result` (secret_service.rs:366)
— it is the CLI's `unwrap_or_default()` that swallows it.

### F19 — Security-relevant mutations report success when persistence fails — HIGH (integrity)
Pattern `let _ = service.save_to_path(...)` (save error discarded, exit 0, success audit row):
- `secret rotate` (~17740): rotation "succeeds" but old payload remains on disk → **the secret
  was never actually rotated**; operator/automation believes it was.
- `secret revoke` (~17790): revoked secret remains live on disk.
- `pep rule-remove` (~15640), `pep grant revoke` (~16340), `pep grant sweep` (~16390),
  `pep grant issue` (~16540), `pep grant attenuate` (~16680), `capability prune` (~15480),
  `privilege elevate/drop/revoke` (~17420-17500), `update check/apply/confirm/rollback`
  (`let _ = service.save_state_to_dir`), `capability` saves on issue/attenuate/revoke are
  handled correctly (they return 1) — the inconsistency is the problem.
- `session action` / `session create` (~2990, ~3115): save failure prints only a `Warning`
  yet exits 0 with a success audit row (see F8).
Fix: for any command that changes authorization state, a failed save MUST return non-zero and
emit a `failure` audit row (the `cmd_service action` `PERSIST_FAILED` path is the template).

### F20 — Over-broad default grant scope (least-privilege violation) — MEDIUM
`aiosh pep grant issue --scope-type filesystem` with no `--scope-path` (line ~16570):
`path: scope_path_opt.unwrap_or_else(|| "/".to_string()), recursive: true` → grants the
**entire filesystem, recursive** by default. Same for network → `localhost`, ipc → `default`.
A one-flag grant command that silently means "everything" is a foot-gun; require the path or
default to non-recursive/deny. Related: `parse_cli_scope` for `tool` scope always sets
`allowed_actions: vec!["*"]` (line ~14480) — the `--scope-target` value cannot narrow actions.

### F21 — Secrets and payloads passed via argv — LOW→MEDIUM (information disclosure)
`secret store --value <VAL>` / `secret rotate --value <VAL>`, `handoff initiate --payload`,
`grant --to`, `triage record --error/--notes` all carry sensitive text as command-line args:
visible in `ps`, `/proc/*/cmdline`, shell history, and audit `args` JSON. Recommend stdin/
env-var/file input (`--value-file` / `-`), which the CLI already models for other inputs.
`secret get --expose` prints the plaintext to stdout un-sanitized (a stored value containing
ESC would inject into the terminal — minor, the value is trusted-by-definition, but the
`sanitize_terminal` helper would cost nothing).

### F22 — `pep`/`handoff`/`sandbox` silently swallow store-recovery signals — LOW
`PepDecisionService::load_or_recover` results destructure to `(_, _recovered, _quarantine)`
and are discarded (lines ~15270, ~15440, ~15680, ~15760); `handoff` drops
`_recovery_warning` (~6135). The operator is never told the policy/grant store was corrupt and
auto-recovered — relevant for forensics ("why did my rule disappear?").
Also `mod preset list` uses `load_store().unwrap_or_else(|_| new_store)` — corrupt store looks
like an empty store.

### F23 — `evidence scan` byte-slice panic — LOW
Reiterating F11: `&r["sha256"].as_str().unwrap_or("")[..8]` (line ~7817) panics if the value is
shorter than 8 bytes (the `unwrap_or("")` arm makes `""[..8]` reachable). Sibling code in
`cmd_secrets` guards correctly with `if f.fingerprint.len() >= 8`.

### F24 — Audit `target` field pollution — LOW
`service stats` / `session stats` / `package stats` pass error-code strings
(`"INVALID_ARGUMENT"`, `LOAD_STORE_FAILED`, `UNHEALTHY_STORE`, `RECOVERY_FAILED`) as the row's
`target` column. Forensic queries filtering by target now match garbage. Same class as F9.

## Sections verified as WELL-HARDENED (read line-by-line)
- `main()`/argv: lossy UTF-8 conversion (no panic), unknown-command -> exit 2.
- `aiosh run`: no shell, argv-array `sandbox_exec`, `no_new_privs`, seccomp denylist
  (ptrace/mount/setuid/chroot/...), execute allow-list, `/tmp` rw + `/usr` ro.
- `aiosh sandbox exec`: `--` delimiter required, cwd `..` traversal rejected,
  `req.validate()`, stdout/stderr passed through `sanitize_terminal_output`, PEP grant wired in,
  exit-code mapping for unauthorized (1) vs exec-failed (127).
- `kernel_module`, `hardware`, `network`, `update`, `threat`, `compliance` families:
  consistent path hygiene (<=1024, no control chars), interface-name validation
  (`validate_interface_name` rejects `eth0;bad`), device-id length+control checks,
  and **every** untrusted string routed through `sanitize_terminal(_output)`.
- `fs_layout`: `read_bounded_text_file` — bounded, rejects FIFO/char devices (explicit comment
  about the hang/`/dev/zero` risk), null-byte rejection on inline JSON, size caps.
- `capability`/`pep`/`privilege`/`secret`/`threat`/`compliance` stores: dedicated
  `validate_*_service_path` / `validate_path` helpers (length, extension, `..`, control chars) —
  enforced at command entry, with adversarial unit tests (control chars, `../`, wrong ext, 1025
  chars) in `capability_cli_tests`, `pep_cli_tests`, `privilege_cli_tests`, `secret_cli_tests`,
  `threat_cli_tests`, `compliance_cli_tests`, `network_cli_tests`.
- `cmd_task`: strict grammar (`--` delimiter, 4096-byte caps, <=16 evidence), refusals audited.
- `cmd_secrets` (scanner): bounded scan (`max_bytes`), redacted snippets, guarded fp truncation.
- JSON envelope everywhere (`{code,data,error}`) — serde escapes control chars, so machine
  consumers are safe even where human output isn't sanitized (F4 is terminal-only).

## Machine sweep (all 21,065 lines)
`unsafe` 0 · `Command::new`/subprocess 0 · shell (`sh -c`,`/bin/sh`) 0 · `env::set_var` 0 ·
`md5/sha1/rand/thread_rng` 0 · `chmod/0o777` 0 · `panic!/unreachable!/todo!` 0 ·
`.unwrap()/.expect(` 84 · `fs::remove*` 33 · path ops 24 · secret-shaped lines 222 · tmp paths 30.

## Verification status / limitations
- **Coverage:** 21,065 / 21,065 lines read verbatim (11 windows), plus an independent
  40-pattern machine sweep over the whole file, plus spot-checks into `aiosh-core`
  (`audit.rs::open`, `fs_layout_service::read_bounded_text_file`, `secret_service::load_from_path`).
- **Not run:** `cargo check`/`cargo test` — `cargo` is not installed in this environment
  (`cargo: command not found`). No source files were modified by this audit (only this report),
  so nothing was broken by the review itself.
- **Out of scope:** logic delegated into `aiosh-core` (pentest tool spawning, sandbox_exec
  implementation, secret encryption at rest, audit hash chain) — flagged where the CLI's usage
  of it looked risky, but core internals deserve their own pass (the MCP server is next).

## Priority fix list
1. F18 — replace `unwrap_or_default()` on vault/privilege loads with fail-closed error handling.
2. F19 — never `let _ =` a save after a security-state mutation; propagate (template:
   `cmd_service action` PERSIST_FAILED).
3. F1/F12 — remove `/tmp` fallbacks for audit DB and CI results (refuse, or use
   `$XDG_RUNTIME_DIR` + O_EXCL/O_NOFOLLOW + 0600).
4. F6/F7 — route every file read through `read_bounded_text_file` (fixes cap + FIFO + TOCTOU).
5. F4 — wrap ALL human-readable output in `sanitize_terminal` (distro/image/service/session/
   package/handoff/triage/repo/doc/evidence families are missing it).
6. F2 — replace the 84 `.expect()/.unwrap()` I/O panics with the `{code,data,error}` envelope.
7. F20 — require `--scope-path` (or non-recursive default) for filesystem grants.
8. F21 — accept secrets via stdin/file instead of argv.
