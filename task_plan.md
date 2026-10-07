# AIOS Active Task Plan — v2 (course correction 2026-08-20)

## Goal (v2, amended)

Deliver the user-stated vision:

> **A Linux system for ethical hacking on the inside, a Windows-style desktop on
> the outside, with AI as a first-class S-rank kernel subsystem that controls
> the whole system.**

This supersedes the v1 plan that focused on a from-scratch RISC-V microkernel
as the shipping target. The microkernel work is preserved as research
substrate but is no longer the shipping path.

## Phase ordering — v2 critical path

1. **Phase 0 — Pillar C spine (S-rank AI subsystem).** Pluggable inference
   backends; MCP JSON-RPC server; PEP capability grants; audit ring.
   **This is the NEW critical path.**
2. **Phase 1 — Pillar A wrappers.** Top Kali/Parrot/BlackArch tools
   exposed as MCP tools, MITRE ATT&CK category-aligned.
3. **Phase 2 — Pillar B installer.** Kali/Debian LTS + XFCE/KDE with
   Windows-look theme (Kali Undercover) + Wine 11 + Proton 11.
4. **Phase 3 — AI ↔ Pillar A integration.** Goal-driven recon-to-report
   pipeline orchestrated by the S-rank agent.
5. **Phase 4 — AI ↔ Pillar B integration.** GUI automation over Wayland /
   X11 / KWin / UIA / AT-SPI.
6. **Phase 5 — Hardening, cross-platform, release.**

### 2026-09-07 — ARCHITECTURAL PIVOT: Kali Linux Base, Windows GUI & Pre-installed Tool Wrapper Strategy

Strategic decision to adopt **Kali Linux** as the primary underlying distribution:
- **Base Substrate**: Rebased OS target onto **Kali Linux Rolling (Debian-derived)**. Leverages Kali's 600+ pre-packaged penetration testing binaries, out-of-the-box kernel wireless injection drivers, and package ecosystem (`apt`).
- **Tool Architecture (Pillar A)**: Zero from-scratch tool development. Wrap Kali's native binaries (`airmon-ng`, `airodump-ng`, `aircrack-ng`, `nmap`, `gobuster`, `arp-scan`, `hashcat`, `tshark`, `sqlmap`) with AIOS Policy Enforcement Point (PEP) gating, runtime bounds, and SQLite WAL audit logging.
- **Desktop Interface (Pillar B)**: Deliver a Windows 10/11 desktop experience via XFCE `kali-undercover` or KDE Plasma Fluent themes, eliminating Linux terminal friction for operators.
### 2026-09-19 — MILESTONE: Kernel Module Core Service CLOSED (T-01611..T-01620) & CLI Surface Implemented (T-01621..T-01626)

Completed tasks T-01617 through T-01626:
- **Kernel Module Management / Core Service Finalization (T-01617..T-01620)**:
  - Sub-Epic 2 security review (threats KS-A1..KS-A5), hardening (staging files, leak-free rollback, 10 MiB limit), comprehensive documentation in `docs/kernel_module_management.md`, and Sub-Epic 2 milestone closure.
- **Kernel Module Management / CLI Surface (T-01621..T-01626)**:
  - Research on subcommand design, error envelopes, and argument parsing.
  - Specification of command syntax, exit codes, and invariants KC1..KC5.
  - Scaffolding `cmd_kernel_module` in `code/aiosh-rust/aiosh-cli/src/main.rs`.
  - Implementation of full subcommands (`list`, `show`, `blacklist`, `unblacklist`, `options`, `autoload`, `unautoload`, `preset`, `export`).
  - Unit testing in `main.rs` (`test_cmd_kernel_module_flow`, 100% pass rate).
  - Integration smoke testing in `code/aiosh-cli/tests/test_kernel_module_cli_smoke.py` (ALL TESTS PASSED).
- **Audit & Verification**:
  - Comprehensive security audit in `docs/tasks/evidence/SECURITY_AUDIT_BATCH_T01617_T01626.md`.
  - Next task pointer advances to **T-01627** (`Phase 1 — Linux Base System & Bootable Target / Kernel Module Management / CLI surface: Security Review`).

### 2026-09-19 — MILESTONE: Kernel Module Data Model CLOSED (T-01601..T-01610) & Core Service Initialized (T-01611..T-01616)

Completed tasks T-01607 through T-01616:
- **Kernel Module Management / Data Model Finalization (T-01607..T-01610)**:
  - Sub-Epic 1 security review (threats KM-A1..KM-A5), hardening (bounds, metacharacter neutralization), comprehensive documentation in `docs/kernel_module_management.md`, and milestone closure.
- **Kernel Module Management / Core Service (T-01611..T-01616)**:
  - Research (service coordinator, procfs/sysfs introspection boundaries, staging file isolation).
  - Specification (`KernelModuleStore`, `KernelModuleService`, and invariants KS1..KS5).
  - Scaffolding `code/aiosh-rust/aiosh-core/src/kernel_module_service.rs` and crate registration.
  - Implementation of store mutations, conflict detection, preset application, and procfs fallback.
  - Unit tests verified (6/6 passing in `kernel_module_service::tests`).
  - Integration tests verified (6/6 passing in `test_kernel_module_service.rs`).
- **Audit & Verification**:
  - Comprehensive security audit in `docs/tasks/evidence/SECURITY_AUDIT_BATCH_T01607_T01616.md`.
  - Next task pointer advances to **T-01617** (`Phase 1 — Linux Base System & Bootable Target / Kernel Module Management / core service: Security Review`).

### 2026-09-19 — MILESTONE: Filesystem Layout Epic CLOSED (T-01501..T-01600) & Kernel Module Data Model Initialized (T-01601..T-01606)

Completed tasks T-01597 through T-01606:
- **Filesystem Layout Epic Finalization (T-01597..T-01600)**:
  - Sub-Epic 10 security review (threats R-A1..R-A5), harness hardening (sandbox isolation, leak-free staging), documentation in `docs/filesystem_layout.md`, and final milestone closure.
  - Finalized all 100 tasks of the Filesystem Layout Epic (`T-01501..T-01600`) with full FL1..FL14 battery passing.
- **Kernel Module Management / Data Model (T-01601..T-01606)**:
  - Research (sysfs/procfs interfaces, modprobe.d directives, CIS baseline).
  - Specification (types `ModuleInfo`, `ModprobeRule`, `KernelModuleConfig`, and invariants KM1..KM5).
  - Scaffolding `code/aiosh-rust/aiosh-core/src/kernel_module.rs` and crate registration.
  - Implementation of data model, validation engine, `/proc/modules` parser, and canonical presets.
  - Unit tests verified (6/6 passing in `kernel_module::tests`).
  - Integration tests verified (6/6 passing in `test_kernel_module_data_model.rs`).
- **Audit & Verification**:
  - Comprehensive security audit in `docs/tasks/evidence/SECURITY_AUDIT_BATCH_T01597_T01606.md`.
  - Next task pointer advances to **T-01607** (`Phase 1 — Linux Base System & Bootable Target / Kernel Module Management / data model: Security Review`).

### 2026-09-19 — BATCH COMPLETE: Tasks T-01587..T-01596 (Sub-Epic 9 Closed & Sub-Epic 10 Recovery & Validation FL14)

Completed tasks T-01587 through T-01596:
- **Sub-Epic 9 Documentation Finalization (T-01587..T-01590)**:
  - Security review (threats D-A1..D-A4), hardening (malformed markdown resilience, bounded reads), documentation in `docs/filesystem_layout.md`, and milestone closure verification.
- **Sub-Epic 10 Recovery & Validation (T-01591..T-01596)**:
  - Research (corruption failure modes, crash consistency), specification (criteria R1..R5), scaffolding, test implementation in `code/aiosh-cli/tests/test_fs_layout_recovery_validation.py`, unit test verification, and test runner integration (**FL14** in `tools/test_fs_layout_suites.py`).
- **Audit & Verification**:
  - Full battery `tools/test_fs_layout_suites.py` criteria FL1..FL14 PASS.
  - Comprehensive security audit in `docs/tasks/evidence/SECURITY_AUDIT_BATCH_T01587_T01596.md`.
- **Task Pointer Advance**:
  - Next task pointer advances to **T-01597** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / recovery & validation: Security Review`).

### 2026-09-19 — MILESTONE: Filesystem Layout Documentation CLOSED 10/10 (T-01581..T-01590)

Complete research, specification, scaffolding, implementation, unit testing, integration, security review, hardening, documentation, and verification for Phase 1 `Filesystem Layout / documentation` (10/10 tasks, `T-01581..T-01590`):
- **Documentation Verification & Schema Parity (`code/aiosh-cli/tests/test_fs_layout_documentation.py`)**:
  - Test cases D1..D5: CLI subcommand completeness in `aiosh layout --help`, MCP manifest schema parity in `aiosh-mcp tools/list` with strict `additionalProperties: false`, in-tree evidence link integrity (all 79 referenced task files verified), JSON code block syntactic validity (all 18 code blocks), and error code documentation completeness (all 21 error codes documented in §4.12).
- **Aggregate Runner Integration (`tools/test_fs_layout_suites.py`)**:
  - Registered criterion **FL13**, running alongside FL1..FL12 with 100% pass rate.
- **Verification Battery**:
  - `tools/test_fs_layout_suites.py` criteria FL1..FL13 PASS.
- **Milestone Advance**: task pointer advances to **T-01591** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / recovery & validation: Research`).

### 2026-09-19 — MILESTONE: Filesystem Layout Observability CLOSED 10/10 (T-01571..T-01580)

Complete research, specification, scaffolding, implementation, unit testing, integration, security review, hardening, documentation, and verification for Phase 1 `Filesystem Layout / observability` (10/10 tasks, `T-01571..T-01580`):
- **Observability & Telemetry (`code/aiosh-cli/tests/test_fs_layout_observability.py`)**:
  - Test cases O1..O5: telemetry emission completeness (100% emission rate for CLI and MCP), audit correlation & queryability via `aiosh audit tail`, outcome fidelity (`ok`/`success`, `error`, `refused`), state inspection parity between CLI and MCP, and destructive mutation flagging (`destructive: true` on partition shrink/delete).
- **Aggregate Runner Integration (`tools/test_fs_layout_suites.py`)**:
  - Registered criterion **FL12**, running alongside FL1..FL11 with 100% pass rate.
- **Verification Battery**:
  - `tools/test_fs_layout_suites.py` criteria FL1..FL12 PASS.
- **Milestone Advance**: task pointer advances to **T-01581** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / documentation: Research`).

### 2026-09-19 — MILESTONE: Filesystem Layout Security Policy CLOSED 10/10 (T-01561..T-01570)

Complete research, specification, scaffolding, implementation, unit testing, integration, security review, hardening, documentation, and verification for Phase 1 `Filesystem Layout / security policy` (10/10 tasks, `T-01561..T-01570`):
- **Security Policy Enforcement (`code/aiosh-cli/tests/test_fs_layout_security_policy.py`)**:
  - Test cases P1..P5: PEP gating for all mutations (`register`, `set_active`, `remove`, `import_fstab`), fail-closed wrong tool scope checks (`pentest.*`), path confinement across allowed and denied directories (`scope.paths`), positive authorized mutations emitting `outcome="ok"` audit rows, and read-only ungated operations (`get`, `list`, `probe`, `diff`, `fstab`).
- **Aggregate Runner Integration (`tools/test_fs_layout_suites.py`)**:
  - Registered criterion **FL11**, running alongside FL1..FL10 with 100% pass rate.
- **Verification Battery**:
  - `tools/test_fs_layout_suites.py` criteria FL1..FL11 PASS.
- **Milestone Advance**: task pointer advances to **T-01571** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / observability: Research`).

### 2026-09-19 — MILESTONE: Filesystem Layout Automated Tests CLOSED 10/10 (T-01551..T-01560)

Complete research, specification, scaffolding, implementation, unit testing, integration, security review, hardening, documentation, and verification for Phase 1 `Filesystem Layout / automated tests` (10/10 tasks, `T-01551..T-01560`):
- **Automated Lifecycle & Edge-Case Suite (`code/aiosh-cli/tests/test_fs_layout_automated_cases.py`)**:
  - Test cases A1..A8: full lifecycle state machine, built-in layout deletion protection, active layout deletion protection, fstab import/export cycle, capacity feasibility probing (under, minimum, tight slack warning, generous), differential destructive detection, corrupted store tamper resistance, and SQLite WAL audit logging.
- **Aggregate Runner Integration (`tools/test_fs_layout_suites.py`)**:
  - Registered criterion **FL10**, running alongside FL1..FL9 with 100% pass rate.
- **Verification Battery**:
  - `tools/test_fs_layout_suites.py` criteria FL1..FL10 PASS.
  - `cargo test -p aiosh-core -p aiosh-cli -p aiosh-mcp` (655 passed, 0 failed).
- **Milestone Advance**: task pointer advances to **T-01561** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / security policy: Research`).

### 2026-09-19 — MILESTONE: Filesystem Layout Configuration CLOSED 10/10 (T-01541..T-01550)


Complete research, specification, scaffolding, implementation, unit testing, integration, security review, hardening, documentation, and verification for Phase 1 `Filesystem Layout / configuration` (10/10 tasks, `T-01541..T-01550`):
- **Configuration Contract (`aiosh_core::fs_layout`)**:
  - Invariants FL1..FL6: FL6 enforces at least one mount marked `required == true`.
  - Strict deserialization: `deny_unknown_fields` across layout specifications and persisted `FilesystemLayoutStore`.
  - Directory permission mode bounds: octal mask `1..=0o7777` (`mode: 0` rejected).
  - CIS benchmark security options: `/tmp` and `/dev/shm` mounts require `nodev`, `nosuid`, and `noexec`.
  - UsrMerge symlink confinement: `symlink_target` must be a relative path rooted at `usr` without `.` or `..` traversals.
  - Metadata hygiene: `created_at` must be RFC 3339 UTC ending in `Z`; fstab `dump` frequency must be `0` or `1`.
- **Operator CLI & Agent MCP Hardening**:
  - 10 MiB stream-bounded reads (`MAX_LAYOUT_DOC_BYTES`), 1 MiB inline payload bounds.
  - Fail-closed validation and parse errors producing honest, hash-chained SQLite WAL audit rows (ADR-0035 §F-2).
  - Atomic persistence with `.tmp.<pid>` staging and symlink overwrite prevention.
- **Verification Battery**:
  - `tools/test_fs_layout_suites.py` criteria FL1..FL9 PASS.
  - `cargo test -p aiosh-core -p aiosh-cli -p aiosh-mcp` (655 passed, 0 failed).
- **Milestone Advance**: task pointer advances to **T-01551** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / automated tests: Research`).

### 2026-09-17 — MILESTONE: Filesystem Layout CLI Surface CLOSED 10/10 (T-01521..T-01530)

Complete research, specification, scaffolding, implementation, unit/integration testing, security review, hardening, documentation, and verification for Phase 1 `Filesystem Layout / CLI surface` (10/10 tasks, `T-01521..T-01530`):
- **Operator CLI Surface (`aiosh layout`)**: `code/aiosh-rust/aiosh-cli/src/main.rs`:
  - Read subcommands: `list`, `show` (positional `ID`, `--standard`, `--container`, `--spec`), `validate` / alias `check`, `probe --bytes <N>`, `diff [<source_id> <target_id>]`, `fstab`.
  - Mutation subcommands: `register --spec <file_or_json>`, `set-active <id>`, `remove <id>`, `import-fstab <id> <name> --fstab <file_or_content> [--base <id>]`.
  - Layout selection precedence: positional `ID` > `--standard` (`standard_uefi` preset) > `--container` (`minimal_container` preset) > `--spec` > the store's active layout. `--standard` had been advertised in `--help` but silently ignored by the resolver; it is now wired to the canonical preset and pinned by two smoke assertions.
  - Uniform result envelope `{code, data, error}` on every branch, exit codes `0` (success) / `1` (operational, validation, I/O) / `2` (argument), and one SHA-256 hash-chained SQLite WAL audit row per invocation (ADR-0035), including fail-open paths.
  - Input hardening: `--spec` / `--fstab` / `--store` must be regular files (FIFOs and character devices refused by type instead of blocking or streaming), 10 MiB cap enforced during the read (not from metadata alone), staged files created `O_CREAT | O_EXCL` with bounded retries, fsync-then-rename atomic persistence that preserves the staged file when only the rename fails.
- **Shared store with the agent surface**: the CLI and the `aios.fs_layout.*` MCP tools read/write one canonical store, verified by the cross-surface parity suite.
- **Automated Suites**:
  - `code/aiosh-cli/tests/test_fs_layout_cli_smoke.py` (criterion `FL3`).
  - `code/aiosh-cli/tests/test_fs_layout_audit_security.py` (`FL4`, audit emission + CWE-150 escape-injection proof).
  - `code/aiosh-cli/tests/test_fs_layout_hardening.py` (`FL7`, non-regular paths, bounded reads, atomic persistence).
  - `tools/test_fs_layout_suites.py` criteria `FL1..FL7` PASS, plus `cargo test -p aiosh-core` (582 passed), `-p aiosh-cli` (24), `-p aiosh-mcp` (12), and the `SB1..SB9` / `D1..D6` baseline smoke set.
- **Documentation**: `docs/filesystem_layout.md` §4 (all 11 subcommands, selection precedence, verified end-to-end walkthrough, exit/error-code contract) and §6 (11 honest limitations); repository index entry `docs/README.md` §8.14.
- **Milestone Advance**: task pointer advances to **T-01531** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / MCP/API surface: Research`).

### 2026-09-16 — MILESTONE: Filesystem Layout Core Service CLOSED 10/10 (T-01511..T-01520)

Complete research, specification, scaffolding, implementation, unit testing, CLI/MCP integration, security review, hardening, and verification for Phase 1 `Filesystem Layout / core service` (10/10 tasks, `T-01511..T-01520`):
- **Core Service (`aiosh_core::fs_layout_service`)**: `code/aiosh-rust/aiosh-core/src/fs_layout_service.rs`:
  - `FilesystemLayoutStore`: in-memory registry of layout profiles, pre-seeded with canonical UEFI and container presets; protects built-ins and active layout against accidental removal.
  - `FilesystemLayoutService`: coordinator managing layout probing, diffing, fstab reconciliation, and atomic persistence.
  - Invariants `CS1..CS5`: store coherence, target capacity feasibility, destructive mutation flagging, fstab topological order, atomic persistence with tempfile replace and 10 MiB limit.
  - `probe_target`: evaluates block device size against required minimum and partition sums with saturating arithmetic, warning if slack < 10%.
  - `diff_layouts`: calculates itemized partition, mount, and directory deltas, flagging `destructive: true` on partition deletions, shrinking, or filesystem format changes.
  - `save_to_path` & `load_from_path`: crash-safe persistence via `.tmp.<pid>` with symlink overwrite protection.
- **Operator CLI Surface (`aiosh layout`)**: `code/aiosh-rust/aiosh-cli/src/main.rs`:
  - `aiosh layout list [--json]`
  - `aiosh layout probe [--bytes <N>] [--json]`
  - `aiosh layout diff [<source_id> <target_id>] [--json]`
- **Autonomous Agent MCP Surface (`aios.fs_layout.*`)**: `code/aiosh-rust/aiosh-mcp/src/main.rs`:
  - `aios.fs_layout.list`: Enumerate registered layout profiles.
  - `aios.fs_layout.probe`: Evaluate target disk capacity.
  - `aios.fs_layout.diff`: Compute differential comparisons between layouts.
- **Verification Battery**:
  - `test_fs_layout_service.rs` (11/11 PASS).
  - `test_fs_layout_data_model.rs` (19/19 PASS).
  - `test_cmd_fs_layout_flow` (1/1 PASS).
  - `test_mcp_fs_layout_tools` (1/1 PASS).
  - `test_session_suites.py` (SB1..SB9 PASS).
  - `test_session_doc.py` (D1..D6 PASS).
  - `test_session_mcp_smoke.py` (8/8 PASS).

### 2026-09-16 — MILESTONE: Filesystem Layout Data Model CLOSED 10/10 (T-01501..T-01510)

Complete research, specification, scaffolding, implementation, unit testing, CLI/MCP integration, security review, hardening, and verification for Phase 1 `Filesystem Layout / data model` (10/10 tasks, `T-01501..T-01510`):
- **Data Model Core (`aiosh_core::fs_layout`)**: `code/aiosh-rust/aiosh-core/src/fs_layout.rs`:
  - `FsType`: Ext4, Btrfs, Xfs, Vfat, Tmpfs, Devtmpfs, Procfs, Sysfs, Overlayfs, Squashfs, Swap, Custom.
  - `PartitionType`: Canonical GPT Type GUID resolution (ESP, LinuxRoot, LinuxHome, LinuxSwap, LinuxVar, LinuxGeneric).
  - `MountPointSpec` & `/etc/fstab`: Exact 6-field formatting and parsing conforming to Linux `fstab(5)` standards.
  - `PartitionSpec` & `DirectorySpec`: FHS 3.0 directories and UsrMerge symlinks (`/bin -> usr/bin`, etc.).
  - `FilesystemLayoutSpec`: Presets `standard_uefi` (64 GiB target host) and `minimal_container`.
  - Consistency invariants `FL1..FL5` actively validated:
    - `FL1`: Exactly one root mount point (`/`) with pass number 1.
    - `FL2`: Path hygiene (absolute paths, no `..` traversal, no control characters, no trailing slashes).
    - `FL3`: Mount hierarchy topology (parent precedes child, no duplicates).
    - `FL4`: CIS benchmark security mount options (`nodev` and `nosuid` mandatory on `/tmp` and `/dev/shm`).
    - `FL5`: Partition table boundaries ($\le 128$ partitions, positive sizes, ESP $\ge 100$ MiB formatted as `vfat`).
- **Operator CLI Surface (`aiosh layout`)**: `code/aiosh-rust/aiosh-cli/src/main.rs`:
  - `aiosh layout show [--standard|--container|--spec <path>] [--json]`
  - `aiosh layout validate [--standard|--container|--spec <path>] [--json]`
  - `aiosh layout fstab [--standard|--container|--spec <path>] [--json]`
  - `aiosh layout check [--standard|--container|--spec <path>] [--json]`
  - Emits structured audit records via `classify_and_emit` to SQLite WAL ring.
- **Autonomous Agent MCP Surface (`aios.fs_layout.*`)**: `code/aiosh-rust/aiosh-mcp/src/main.rs`:
  - `aios.fs_layout.get`: Reference layout discovery.
  - `aios.fs_layout.validate`: Invariant validation over specifications or inline JSON.
  - `aios.fs_layout.fstab`: Automated `/etc/fstab` file generation.
  - All tools dispatched via `dispatch::recorded_call` into `AuditRing`.
- **Dedicated Automated Unit & Integration Suite**:
  - `code/aiosh-rust/aiosh-core/tests/test_fs_layout_data_model.rs`: 19/19 tests passing across FL1..FL5, boundary values, and negative cases.
  - `test_cmd_fs_layout_flow` in `aiosh-cli` passing.
  - `test_mcp_fs_layout_tools` in `aiosh-mcp` passing.
- **Documentation**:
  - Architecture and operational guide in `docs/filesystem_layout.md` with CLI and MCP examples.
- **Milestone Advance**:
  - `Filesystem Layout / data model` (10/10 tasks, T-01501..T-01510) COMPLETE.
  - Next task pointer advances to **T-01511** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / core service: Research`).

### 2026-09-16 — MILESTONE: User Session Bootstrap Recovery & Validation CLOSED 10/10 (T-01491..T-01500) — USER SESSION BOOTSTRAP EPIC COMPLETE (100/100, TASK 1500 ACHIEVED!)

Complete implementation, governance, verification, and hardening for Phase 1 `User Session Bootstrap / recovery & validation` (10/10 tasks, `T-01491..T-01500`) and conclusion of the entire User Session Bootstrap feature (100/100 tasks, `T-01401..T-01500`):
- **Recovery & Validation Subsystem (`aiosh_core::session_recovery`)**: `code/aiosh-rust/aiosh-core/src/session_recovery.rs`:
  - Enforces mathematical & consistency invariants `SSR1..SSR5`:
    - `SSR1`: `valid_sessions + invalid_sessions == total_sessions`
    - `SSR2`: `healthy == (errors.is_empty() && invalid_sessions == 0)`
    - `SSR3`: `invalid_sessions > 0 => errors.len() >= invalid_sessions`
    - `SSR4`: Non-destructive quarantine via `.bak.<YYYYMMDD_HHMMSS_micros>` with POSIX `0600` permissions.
    - `SSR5`: Single foreground session per hardware seat (`seat0`), no duplicate leader PIDs across non-terminated sessions.
  - Core methods: `validate_session_store`, `create_backup_file`, `recover_session_store_with_backup`, `load_or_recover`.
- **Operator CLI Surface (`aiosh session check` / `recover`)**: `code/aiosh-rust/aiosh-cli/src/main.rs`:
  - `aiosh session check [--fix] [--store <path>] [--json]` providing human-readable diagnostic summaries or structured JSON envelopes with SQLite WAL audit row emission (`session.check` / `session.repair`).
  - `aiosh session recover [--store <path>] [--json]` shortcut for automatic repair with quarantine backup.
- **Autonomous Agent MCP Surface (`aios.session.check`)**: `code/aiosh-rust/aiosh-mcp/src/main.rs`:
  - JSON-RPC 2.0 tool `aios.session.check` registered in tool manifest, handling inspection and `auto_recover: true` self-healing with quarantine backup and SQLite WAL audit logging.
- **Dedicated Automated Unit & Integration Suite**:
  - `code/aiosh-rust/aiosh-core/tests/test_session_recovery.rs`: 9/9 tests passing across SSR1..SSR5, capacity boundary limits, and lifecycle corruption scenarios.
- **End-to-End Smoke & Integration Parity**:
  - `code/aiosh-mcp/tests/test_session_mcp_smoke.py`: 8/8 test phases passing including `test_session_check_and_recover`.
  - `tools/test_session_suites.py`: criteria `SB1..SB9` passing with 0 failures.
  - `tools/test_session_doc.py`: documentation criteria `D1..D6` passing.
- **Documentation**:
  - `docs/user_session_bootstrap.md` (§10) and `code/aiosh-mcp/README.md` updated with operational guide, copy-pasteable CLI/MCP examples, constraints, and task evidence links.
- **Grand Milestone**:
  - **User Session Bootstrap (100/100 tasks, T-01401..T-01500) COMPLETE.**
  - Task pointer advances to **T-01501** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / data model: Research`).

### 2026-09-11 — MILESTONE: User Session Bootstrap Configuration CLOSED 10/10 (T-01441..T-01450)

Complete implementation, governance, verification, and hardening for Phase 1 `User Session Bootstrap / configuration` (10/10 tasks, `T-01441..T-01450`):
- **Configuration Subsystem (`aiosh_core::session_config`)**: `code/aiosh-rust/aiosh-core/src/session_config.rs`:
  - `SessionConfig` struct, default constants, and validation enforcing invariants `SC1..SC7`:
    - `SC1`: Store path validity & boundaries ($\le 1024$ bytes, rejection of control characters and null bytes).
    - `SC2`: User capacity bounds strictly enforced to $[1 \dots 128]$ active sessions per user account.
    - `SC3`: Total store capacity bounds strictly enforced to $[10 \dots 10,000]$ total sessions.
    - `SC4`: Inactivity auto-lock idle timeout bounds $[10 \dots 86,400]$ seconds.
    - `SC5`: Max store size bytes bounded to $[64\text{ KiB} \dots 100\text{ MiB}]$.
    - `SC6`: Resolution precedence: Explicit File > Environment Variables (`AIOS_SESSION_*`) > Defaults.
    - `SC7`: Config file size cap $\le 64\text{ KiB}$ with stream bounding and fail-loud parsing.
- **Operator CLI Surface (`aiosh session config`)**: `code/aiosh-rust/aiosh-cli/src/main.rs`:
  - `aiosh session config [--config <path>] [--json]` providing human-readable formatted output or structured JSON envelope with SQLite WAL audit row emission.
- **Autonomous Agent MCP Surface (`aios.session.config`)**: `code/aiosh-rust/aiosh-mcp/src/main.rs`:
  - JSON-RPC 2.0 tool `aios.session.config` registered and dispatched under PEP capability gating with SQLite WAL audit logging.
- **Dedicated Automated Unit & Integration Suite**:
  - `code/aiosh-rust/aiosh-core/tests/test_session_config.rs`: 9/9 tests passing across SC1..SC7 invariants.
- **Master Test Runner Matrix (`tools/test_session_suites.py`)**:
  - Integrated criterion `SB5` (`test_sb5_configuration`). All 5 criteria `SB1..SB5` PASS cleanly.
- **Documentation**:
  - `code/aiosh-cli/README.md` and `code/aiosh-mcp/README.md` updated with configuration options and examples.
- **Ledger Pointer**: Advances to **T-01451** (`Phase 1 — Linux Base System & Bootable Target / User Session Bootstrap / automated tests: Research`).

### 2026-09-09 — MILESTONE: User Session Bootstrap MCP/API Surface CLOSED 10/10 (T-01431..T-01440)

Complete implementation, governance, verification, and hardening for Phase 1 `User Session Bootstrap / MCP API surface` (10/10 tasks, `T-01431..T-01440`):
- **Full MCP Tool Surface (`aios.session.*`)**: `code/aiosh-rust/aiosh-mcp/src/main.rs`:
  - `aios.session.validate`: Schema syntax & invariant checking for session ID, username, and `UserSessionSpec` against rules `SB1..SB5`.
  - `aios.session.list`: In-memory & on-disk session discovery with multi-field filtering (`username`, `state`, `session_type`, `seat`, `limit`).
  - `aios.session.get`: Precision inspection of session status and specification by `session_id`.
  - `aios.session.action`: High-assurance state machine transition dispatcher (`authenticate`, `activate`, `lock`, `unlock`, `terminate`) with seat arbitration.
  - `aios.session.create`: Atomic session provisioning with validation, capacity enforcement, and persistent store sync.
- **Cross-Substrate Parity (CLI <-> MCP)**:
  - Verified bidirectional lifecycle interoperability: session created via CLI, queried/authenticated via MCP, activated via CLI, locked via MCP, verified locked via CLI, unlocked via CLI, two-stage terminated via MCP, and confirmed terminated via CLI.
- **Defense-in-Depth Hardening**:
  - Request line ceiling: 1 MiB transport-level cap (`-32700: request line exceeds 1048576 bytes`).
  - Ingestion payload ceiling: 1 MiB limit on inline JSON objects/strings in `validate` and `create`.
  - Query bounds: `limit` parameter in `aios.session.list` strictly enforced to $[1 \dots 10,000]$.
  - Path sanitization: `store_path` parameter strictly bounded to $\le 1024$ characters with zero control characters across all tools.
  - Identifier validation: early `validate_session_id` checks on `get` and `action` prior to store lookups.
  - Clean resource safety: Atomic writes via isolated `.tmp.<pid>.<nanos>` files with guaranteed cleanup on error.
- **Audit Non-Repudiation**:
  - Every MCP execution path writes append-only, SHA-256 hash-chained audit rows to SQLite WAL (`$AIOSH_HOME/audit.db`) with monotonic `audit_id`.
- **Test Suite Matrices**:
  - `code/aiosh-mcp/tests/test_session_mcp_smoke.py`: 7/7 suites passing (manifest, validate, list/get, action, create/persist, cross-surface parity, hardening).
  - `cargo test -p aiosh-mcp`: 11/11 unit tests passing cleanly.
  - `tools/test_session_suites.py`: All 4 criteria `SB1..SB4` PASS.
  - Baseline service suites `tools/test_service_suites.py`: All 10 criteria `SS1..SS10` PASS.
- **Documentation**:
  - `code/aiosh-mcp/README.md` updated with full tool table, copy-pasteable JSON-RPC 2.0 requests, honest constraints disclosure, and evidence links.
- **Ledger Pointer**: Advances to **T-01441** (`Phase 1 — Linux Base System & Bootable Target / User Session Bootstrap / Automated Integration Tests: Research`).

### 2026-09-09 — MILESTONE: User Session Bootstrap CLI Surface CLOSED 10/10 (T-01421..T-01430)

Complete implementation, governance, verification, and hardening for Phase 1 `User Session Bootstrap / CLI surface` (10/10 tasks, `T-01421..T-01430`):
- **CLI Subcommand Surface (`aiosh session`)**: `code/aiosh-rust/aiosh-cli/src/main.rs`:
  - Full subcommand suite implemented: `validate`, `list`, `show`, `status` (alias), `action`, `create`, plus ergonomics shortcuts (`activate`, `lock`, `unlock`, `terminate`, `auth`).
  - Strict bounded option validation: `--limit <n>` constrained to $1 \le n \le 10,000$, `--store <path>` bounded to $\le 1024$ bytes and ASCII control character rejection.
  - Sizing limits enforced: 1 MiB payload cap on input specs / inline JSON with explicit `PAYLOAD_TOO_LARGE` exit code 2 error envelope.
  - Zero silent failure: Deterministic JSON error envelopes conforming to ADR-0035 §D-2 across all failure modes (syntax errors, validation failures, illegal state transitions, store read/write errors).
  - Clean resource safety: Process-isolated atomic persistence via PID+nanosecond tempfiles with bounded retries and guaranteed tempfile cleanup on error paths.
- **In-Tree & Standalone Test Suites**:
  - `test_cmd_session_flow` in `code/aiosh-rust/aiosh-cli/src/main.rs` verifying end-to-end routing, validation, list/show/action, shortcuts, error envelopes, and limits.
  - `code/aiosh-cli/tests/test_session_cli_smoke.py` passing 6/6 test suites across help, validation, commands, shortcuts, and hardening.
  - `tools/test_session_suites.py` passing 4/4 criteria (`SB1..SB4`).
- **Audit Non-Repudiation**:
  - Every invocation branch (including invalid arguments, payload breaches, unknown subcommands, and illegal state transitions) emits an append-only, SHA-256 hash-chained audit row to `$AIOSH_HOME/audit.db`.
- **Documentation**:
  - `code/aiosh-cli/README.md` updated with subcommands table, copy-pasteable examples, parameter references, and honest constraints disclosure.
- **Ledger Pointer**: Advances to **T-01431** (`Phase 1 — Linux Base System & Bootable Target / User Session Bootstrap / MCP API surface: Research`).

### 2026-09-09 — MILESTONE: User Session Bootstrap Core Service CLOSED 10/10 (T-01411..T-01420)

Complete implementation, governance, verification, and hardening for Phase 1 `User Session Bootstrap / core service` (10/10 tasks, `T-01411..T-01420`):
- **Core Service Subsystem**: `code/aiosh-rust/aiosh-core/src/session_service.rs` providing `UserSessionService` coordinator, action execution, seat arbitration, and idle tracking enforcing invariants `CS1..CS5`:
  - `CS1`: State Monotonicity & Lifecycle: Deterministic forward transitions (`Initializing` $\to$ `Authenticating` $\to$ `Active` $\rightleftharpoons$ `Locked` $\to$ `Terminating` $\to$ `Terminated`); invalid transitions rejected with structured error envelopes; terminated immutable.
  - `CS2`: Seat Arbitration: At most one session per physical/virtual seat (e.g. `seat0`) can hold `SessionScope::Foreground`. Activating any session demotes prior foreground sessions on that seat to `SessionScope::Background`.
  - `CS3`: Capacity Bounds: Hard limit of $\le 32$ active sessions per user account, and $\le 1,024$ total sessions in store.
  - `CS4`: Action Reporting: Structured `UserSessionActionReport` envelope on all actions detailing `session_id`, `action`, `previous_state`, `new_state`, `success`, `error`, and `timestamp`.
  - `CS5`: Idle & Lock Consistency: Continuous tracking of `idle_seconds`; `touch_activity` resets idle duration to 0; `state == Locked` strictly matches `locked == true`; activity updates never unlock locked sessions.
- **Operator CLI Surface**: `code/aiosh-rust/aiosh-cli/src/main.rs`:
  - `aiosh session list [--user <username>] [--state <state>] [--type <type>] [--seat <seat>] [--limit <n>] [--json] [--store <path>]`
  - `aiosh session show <session_id> [--json] [--store <path>]`
  - `aiosh session action <session_id> <authenticate|activate|lock|unlock|terminate> [--json] [--store <path>]`
- **Autonomous Agent MCP Surface**: `code/aiosh-rust/aiosh-mcp/src/main.rs`:
  - JSON-RPC 2.0 tools `aios.session.list`, `aios.session.get`, and `aios.session.action` registered and dispatched under PEP capability gating with SQLite WAL audit logging.
- **Master Test Runner Matrix (`tools/test_session_suites.py`)**:
  - Integrated criterion `SB4` (`test_sb4_core_service_lifecycle`). All 4 criteria `SB1..SB4` PASS cleanly.
- **Unit & Smoke Suites**:
  - `code/aiosh-rust/aiosh-core/tests/test_session_service.rs` (10 unit & hardening tests passing across CS1..CS5).
  - `code/aiosh-cli/tests/test_session_cli_smoke.py` (5 test suites passing with full error envelope coverage).
- **Ledger Pointer**: Advances to **T-01421** (`Phase 1 — Linux Base System & Bootable Target / User Session Bootstrap / CLI surface: Research`).

### 2026-09-09 — MILESTONE: User Session Bootstrap Data Model CLOSED 10/10 (T-01401..T-01410)

Complete implementation, governance, verification, and hardening for Phase 1 `User Session Bootstrap / data model` (10/10 tasks, `T-01401..T-01410`):
- **Data Model Architecture**: `code/aiosh-rust/aiosh-core/src/session.rs` delivering core session structures and validation engine enforcing criteria `SB1..SB5`:
  - `SB1`: Session ID syntax & bounds: $[1 \dots 64]$ chars, alphanumeric start, `[a-zA-Z0-9_.-]`, strict rejection of path traversal (`..`), slashes, control chars, whitespace, and shell metacharacters.
  - `SB2`: User identity & UID/GID: POSIX username $[1 \dots 32]$ chars (lowercase/underscore start, `[a-z0-9_-]`), valid UID/GID $\le 2,147,483,647$.
  - `SB3`: Lifecycle state machine: Deterministic forward transitions (`Initializing` $\to$ `Authenticating` $\to$ `Active` $\rightleftharpoons$ `Locked` $\to$ `Terminating` $\to$ `Terminated`); invalid state transitions rejected; terminal states are immutable.
  - `SB4`: Environment isolation: $\le 256$ keys, uppercase alphanumeric syntax, values $\le 4,096$ chars, null byte rejection, `XDG_RUNTIME_DIR` absolute Unix path without `..` traversal.
  - `SB5`: Capacity limits: Max 32 concurrent active sessions per user, max 1,024 total sessions in store, 10 MiB serialized store file cap, 1 MiB spec payload cap.
- **Session Types & Classes**: First-class support for `AiAgent` session environment architecture alongside interactive `Tty`, `X11`, and `Wayland` sessions, with `Agent` session class for autonomous agent co-pilots.
- **Operator CLI Surface**: `code/aiosh-rust/aiosh-cli/src/main.rs`:
  - `aiosh session validate [--id <id>] [--user <user>] [--spec <file_or_json>] [--json]` providing exit code 0 on valid and 2 on invalid.
- **Autonomous Agent MCP Surface**: `code/aiosh-rust/aiosh-mcp/src/main.rs`:
  - JSON-RPC 2.0 tool `aios.session.validate` (`session_id`, `username`, `spec`) registered and dispatched under PEP capability gating with SQLite WAL audit logging.
- **Master Test Runner Matrix (`tools/test_session_suites.py`)**:
  - Validates criteria `SB1..SB3`: `SB1` (unit test suite), `SB2` (CLI smoke suite), `SB3` (MCP test suite). All criteria PASS.
- **Unit & Smoke Suites**:
  - `code/aiosh-rust/aiosh-core/tests/test_session_data_model.rs` (8 unit tests passing across SB1..SB5).
  - `code/aiosh-cli/tests/test_session_cli_smoke.py` (4 test groups passing with Windows payload limit hardening).
- **Ledger Pointer**: Advances to **T-01411** (`Phase 1 — Linux Base System & Bootable Target / User Session Bootstrap / core service: Research`).

### 2026-09-09 — MILESTONE: Init & Service Supervision Recovery & Validation CLOSED 10/10 (T-01391..T-01400) — EPIC CLOSED (100/100)

Complete implementation, governance, verification, and hardening for Phase 1 `Init & Service Supervision / recovery & validation`, marking the complete closure of the entire **Init & Service Supervision** epic (`T-01301..T-01400`):
- **Recovery & Validation Subsystem**: `code/aiosh-rust/aiosh-core/src/service_recovery.rs` enforcing formal criteria `SR1..SR5`:
  - `SR1`: Mathematical conservation: $\text{valid\_services} + \text{invalid\_services} = \text{total\_services}$.
  - `SR2`: Health equivalence: $\text{healthy} \iff (\text{errors.is\_empty}() \land \text{invalid\_services} == 0)$.
  - `SR3`: Error attribution: $\text{invalid\_services} > 0 \implies \text{errors.len}() \ge \text{invalid\_services}$.
  - `SR4`: Non-destructive forensic preservation: Corrupted or unreadable files are quarantined to `<path>.corrupt.<ts>.bak` with collision counter bounding ($\le 10,000$). Damaged data is never silently discarded.
  - `SR5`: Self-healing canonical fallback: Reconstitutes valid reference services (`aios-securityd.service`, `auditd.service`, `dbus.service`, `systemd-journald.service`, `network-manager.service`, `ssh.service`) achieving $\text{healthy} == \text{true}$ and verified topological acyclicity.
- **Operator CLI Surface**: `code/aiosh-rust/aiosh-cli/src/main.rs`:
  - `aiosh service check [--fix] [--store <path>] [--json]` providing read-only audit mode (exit code 1 on failure) and automated repair mode (exit code 0 with quarantine backup and fresh store generation).
- **Autonomous Agent MCP Surface**: `code/aiosh-rust/aiosh-mcp/src/main.rs`:
  - JSON-RPC 2.0 tool `aios.service.check` (`store_path`, `auto_recover`) with PEP capability gating and SQLite WAL audit logging.
- **Master Test Runner Matrix (`tools/test_service_suites.py`)**:
  - Integrated criterion `SS10` (`test_ss10_recovery`). All 10 criteria `SS1..SS10` PASS cleanly.
- **Unit & Smoke Suites**:
  - `code/aiosh-rust/aiosh-core/tests/test_service_recovery.rs` (7 tests passing across SR1..SR5, cyclic dependency detection, and hardening).
  - `code/aiosh-cli/tests/test_service_cli_smoke.py` (9 tests passing).
  - `code/aiosh-mcp/tests/test_service_mcp_smoke.py` (8 suites / 9 tools passing).
- **Ledger Pointer**: Advances to **T-01401** (`Phase 1 — Linux Base System & Bootable Target / User Session Bootstrap / data model: Research`).

### 2026-09-09 — MILESTONE: Init & Service Supervision Documentation CLOSED 10/10 (T-01381..T-01390)

Complete implementation, governance, verification, and hardening for Phase 1 `Init & Service Supervision / documentation`:
- **Architectural Reference Guide**: `docs/service_supervision.md` (17,708 bytes) delivering complete operator & agent guidance across 9 structural sections:
  1. Executive Summary & Architecture Overview (Mermaid FSM diagram, pipeline architecture)
  2. Data Model & Validation Invariants (`SS1..SS5`)
  3. Core Lifecycle Engine & FSM Transitions (`CS1..CS5`)
  4. Operator CLI Reference (`aiosh service` subcommands)
  5. Autonomous Agent MCP API Reference (`aios.service.*` tools)
  6. Configuration Subsystem & Precedence Engine (`SC1..SC7`)
  7. Automated Test Suites & Master Matrix (`ST1..ST5`, `SS1..SS9`)
  8. Security Policy, PEP Gating & Audit Logging (`SP1..SP6`)
  9. Observability, Telemetry & Diagnostics (`SO1..SO6`)
- **Documentation Invariant Test Suite**: `tools/test_service_doc.py` verifying criteria `D1..D6`:
  - `D1`: Document existence and sizing bounds [1000..500000 bytes].
  - `D2`: Mandatory presence of all 9 required top-level architectural sections.
  - `D3`: Zero forbidden placeholders (`TODO`, `TBD`, `FIXME`, dummy text).
  - `D4`: Exhaustive coverage of security policy invariants, CLI commands, and MCP tools.
  - `D5`: Negative rejection testing ensuring assertion failure when sections or invariants are stripped.
  - `D6`: Zero volatile snapshot counts (C6 compliant, immune to future test additions).
- **Master Test Runner Matrix (`tools/test_service_suites.py`)**:
  - Integrated criterion `SS9` (`test_ss9_documentation`). All criteria `SS1..SS9` PASS.
- **Lint & Compliance**:
  - `tools/check_task_docs.py docs/service_supervision.md` verified clean PASS across `C1..C6`.
- **Ledger Pointer**: Advances to **T-01391** (`Phase 1 — Linux Base System & Bootable Target / Init & Service Supervision / recovery & validation: Research`).

### 2026-09-09 — MILESTONE: Init & Service Supervision Observability CLOSED 10/10 (T-01371..T-01380)

Complete implementation, governance, verification, and hardening for Phase 1 `Init & Service Supervision / observability`:
- **Subsystem Architecture**: `code/aiosh-rust/aiosh-core/src/service_observability.rs` delivering `ServiceObservabilityReport` enforcing criteria `SO1..SO6`:
  - `SO1`: Inventory completeness with strict mathematical conservation: $\sum \text{state} = \sum \text{mode} = \sum \text{type} = \sum \text{policy} = \text{total\_services}$.
  - `SO2`: Categorical distributions across service states, startup modes, service types, and restart policies.
  - `SO3`: Health metrics (`healthy_count`, `unhealthy_count`), tracking of failed service names, and process restart counters aggregated with saturation arithmetic.
  - `SO4`: Bounded $O(1)$ memory dependency distribution histogram buckets (`"0"`, `"1-2"`, `"3-5"`, `"6+"`).
  - `SO5`: Cross-evaluation with `ServiceSecurityPolicy` reporting compliance, violations, and prohibited services (`telnet.service`).
  - `SO6`: Deterministic ISO timestamping, standardized JSON result envelope, and SQLite WAL audit logging.
- **Operator CLI Surface**: `code/aiosh-rust/aiosh-cli/src/main.rs`:
  - `aiosh service stats` and alias `aiosh service observability` with `--store`, `--policy`, `--config`, and `--json` flags.
- **Autonomous Agent MCP Surface**: `code/aiosh-rust/aiosh-mcp/src/main.rs`:
  - Tool `aios.service.stats` registered and dispatched under PEP gating and SQLite WAL audit trail.
- **Master Test Runner Matrix (`tools/test_service_suites.py`)**:
  - Integrated criterion `SS8` (`test_ss8_observability`). All criteria `SS1..SS8` PASS.
- **Unit & Smoke Suites**:
  - `code/aiosh-rust/aiosh-core/tests/test_service_observability.rs` (7 tests covering SO1..SO7).
  - `code/aiosh-cli/tests/test_service_cli_smoke.py` (8 tests passing).
  - `code/aiosh-mcp/tests/test_service_mcp_smoke.py` (7 tests passing).
- **Ledger Pointer**: Advances to **T-01381** (`Phase 1 — Linux Base System & Bootable Target / Init & Service Supervision / documentation: Research`).

### 2026-09-06 — MILESTONE: Init & Service Supervision MCP API Surface CLOSED 10/10 (T-01331..T-01340)

Complete implementation, governance, verification, and hardening for Phase 1 `Init & Service Supervision / MCP/API surface`:
- **Autonomous Agent MCP Surface**: `code/aiosh-rust/aiosh-mcp/src/main.rs` exposing all 5 standard JSON-RPC 2.0 service supervision tools:
  - `aios.service.validate`: Validation of service names (SS1) or complete `ServiceSpec` objects (SS1..SS5).
  - `aios.service.list`: Multi-parameter service catalog discovery (`pattern`, `state`, `startup_mode`, `limit`, `store_path`).
  - `aios.service.get`: Deep inspection returning service specification and dynamic runtime status.
  - `aios.service.action`: State machine lifecycle execution (`start`, `stop`, `restart`, `reload`, `enable`, `disable`, `mask`, `unmask`) with atomic disk persistence.
  - `aios.service.order`: Topological startup execution planning using Kahn's algorithm with cycle detection.
- **Security, Gating & Audit Integration**:
  - Gated by Policy Enforcement Point (`PEP`) capability checks with `grant_id`.
  - Non-repudiable audit row emission for all queries and actions via `dispatch::recorded_call` and `AuditRing`.
  - Strict input validation: length bounds on names (128), patterns (256), and store paths (1024); control character rejection across all strings.
- **Automated Smoke & Integration Testing**:
  - Authored standalone test suite `code/aiosh-mcp/tests/test_service_mcp_smoke.py` asserting JSON-RPC 2.0 stdio behavior across all tools, boundary values, and negative cases.
  - Rust unit test suite `tests::test_mcp_service_tools` in `aiosh-mcp`.
  - Updated `tools/test_service_suites.py` criterion `SS3` description (`validate, list, get, action, order`). All criteria `SS1..SS4` PASS.
- **Documentation**:
  - Documented tools, JSON-RPC schemas, copy-pasteable call examples, constraints, and limitations in `code/aiosh-mcp/README.md`.
- **Ledger Pointer**: Advances to **T-01341** (`Phase 1 — Linux Base System & Bootable Target / Init & Service Supervision / configuration: Research`).

### 2026-09-06 — MILESTONE: Init & Service Supervision CLI Surface CLOSED 10/10 (T-01321..T-01330)

Complete implementation, governance, verification, and hardening for Phase 1 `Init & Service Supervision / CLI surface`:
- **Operator CLI Surface**: `code/aiosh-rust/aiosh-cli/src/main.rs` delivering `cmd_service`:
  - `validate`: Invariant validation for names (`SS1`) and specifications (`SS1..SS5`) with 1 MiB payload ceiling.
  - `list`: Multi-parameter service querying (`--pattern`, `--state`, `--mode`, `--limit`, `--store`, `--json`).
  - `show` & `status`: Service specification and runtime state inspection.
  - `action`: State machine transition dispatcher (`start`, `stop`, `restart`, `reload`, `enable`, `disable`, `mask`, `unmask`).
  - Direct Action Shortcuts: `start`, `stop`, `restart`, `reload`, `enable`, `disable`, `mask`, `unmask` with option preservation and honest audit rows.
  - `order`: Topological startup execution calculation with cycle detection via Kahn's algorithm.
- **Cross-Substrate Parity & Audit**: Standardized JSON envelopes across all commands; unconditional audit logging via `classify_and_emit` to `audit.log` / SQLite WAL ring (`audit.db`).
- **Smoke & Unit Suites**:
  - `task_cli_tests::test_cmd_service_flow`: Rust CLI unit/integration suite.
  - `code/aiosh-cli/tests/test_service_cli_smoke.py`: Standalone CLI smoke test.
  - `tools/test_service_suites.py`: All criteria `SS1..SS4` PASS.
- **Ledger Pointer**: Advances to **T-01331** (`Phase 1 — Linux Base System & Bootable Target / Init & Service Supervision / MCP API surface: Research`).

### 2026-09-06 — MILESTONE: Init & Service Supervision Core Service CLOSED 10/10 (T-01311..T-01320)

Complete implementation, governance, verification, and hardening for Phase 1 `Init & Service Supervision / core service`:
- **Core Service Store & Registry**: `code/aiosh-rust/aiosh-core/src/service_service.rs` delivering `ServiceStore` implementing `CS1..CS5`:
  - `CS1`: Unique service specification registration with schema validation.
  - `CS2`: Deterministic FSM lifecycle action engine (`start`, `stop`, `restart`, `reload`, `enable`, `disable`, `mask`, `unmask`).
  - `CS3`: Topological startup execution planning using Kahn's algorithm with cycle detection.
  - `CS4`: Filtered querying by name pattern, lifecycle state, startup mode, and limit bounds.
  - `CS5`: Atomic filesystem persistence using PID-isolated tempfile rename and 10 MiB payload ceiling.
- **Operator CLI Surface**: Integrated in `code/aiosh-rust/aiosh-cli/src/main.rs`:
  - `aiosh service list`, `aiosh service show`, `aiosh service action`, `aiosh service order` with audit row emission.
- **Autonomous Agent MCP Surface**: Integrated in `code/aiosh-rust/aiosh-mcp/src/main.rs`:
  - Registered and dispatched `aios.service.list`, `aios.service.get`, `aios.service.action`, `aios.service.order` with PEP authorization and hash-chained audit logging.
- **Master Test Runner Matrix (`tools/test_service_suites.py`)**: All criteria `SS1` (data model integrity), `SS2` (CLI surface), `SS3` (MCP surface), and `SS4` (core service lifecycle, FSM & dependency ordering) PASS.
- **Unit & Integration Suite**: `code/aiosh-rust/aiosh-core/tests/test_service_service.rs` (6 tests covering CS1..CS5).
- **Ledger Pointer**: Advances to **T-01321** (`Phase 1 — Linux Base System & Bootable Target / Init & Service Supervision / CLI surface: Research`).

### 2026-09-06 — MILESTONE: Init & Service Supervision Data Model CLOSED 10/10 (T-01301..T-01310)

Complete implementation, governance, verification, and hardening for Phase 1 `Init & Service Supervision / data model`:
- **Unified Data Model Subsystem**: `code/aiosh-rust/aiosh-core/src/service.rs` delivering `ServiceSpec`, `ServiceStatus`, `ServiceHealth`, `ServiceType`, `ServiceState`, `ServiceRestartPolicy`, `ServiceStartupMode`, `ServiceDependencyType`, `ServiceDependency`, `ServiceAction`, and `ServiceQuery`.
- **Validation Invariants (SS1..SS5)**: Enforcing strict service naming syntax matching systemd/OpenRC (`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`), string length boundaries [1..128], valid extensions, execution command bounds and traversal protection (`SS2`), dependency graph hygiene without self-loops (`SS3`), resource timeouts and environment sizing bounds (`SS4`), and lifecycle state consistency (`SS5`).
- **Operator CLI Surface**: Integrated `aiosh service validate (--name <name> | --spec <file_or_json>) [--json]` in `aiosh-cli/src/main.rs` with 1 MiB payload protection and SQLite WAL audit logging.
- **Autonomous Agent MCP Surface**: Registered and dispatched `aios.service.validate` tool in `aiosh-mcp/src/main.rs` with PEP authorization and audit trail.
- **Master Test Runner Matrix (`tools/test_service_suites.py`)**: All criteria `SS1` (data model integrity), `SS2` (CLI surface), and `SS3` (MCP surface) PASS.
- **Unit & Integration Suite**: `code/aiosh-rust/aiosh-core/tests/test_service_data_model.rs` (6 tests covering SS1..SS5 and serde roundtrips).
- **Ledger Pointer**: Advances to **T-01311** (`Phase 1 — Linux Base System & Bootable Target / Init & Service Supervision / core service: Research`).

### 2026-09-05 — MILESTONE: Package Management Documentation CLOSED 10/10 (T-01281..T-01290)

Complete implementation, governance, verification, and hardening for Phase 1 `Package Management / documentation`:
- **Architecture & Operational Guide**: Created `docs/package_management.md` detailing all 9 core architectural components (Executive Overview with Mermaid diagram, Core Data Model PM1..PM5, Store Registry CS1..CS5, Configuration PC1..PC6, Security Policy PP1..PP6, Observability PO1..PO6, Operator CLI surface, Autonomous Agent MCP surface, and Failure Modes / Audit Trail).
- **Automated Documentation Test Suite**: Implemented `tools/test_package_doc.py` verifying criteria `D1..D6`:
  - `D1`: File existence & size constraints ($[1000 \dots 5\text{ MiB}]$).
  - `D2`: Verbatim presence of all 9 required structural section headers.
  - `D3`: Zero forbidden rot markers (`TODO`, `FIXME`, `TBD`, `XXX`, `PLACEHOLDER`).
  - `D4`: Exhaustive invariant (`PM1..PM5`, `CS1..CS5`, `PC1..PC6`, `PP1..PP6`, `PO1..PO6`), CLI, and MCP tool token coverage.
  - `D5`: Negative rejection testing on malformed documents.
  - `D6`: Zero volatile snapshot counters (C6 compliant).
- **Master Test Runner Matrix (`tools/test_package_suites.py`)**: Integrated criterion `PM9` (`test_package_doc`). All criteria `PM1..PM9` PASS.
- **Repository Index Synchronization**: Linked guide in `docs/README.md` under section 8.12.
- **Ledger Pointer**: Advances to **T-01291** (`Phase 1 — Linux Base System & Bootable Target / Package Management / recovery & validation: Research`).

### 2026-09-05 — MILESTONE: Package Management Observability CLOSED 10/10 (T-01271..T-01280)

Complete implementation, governance, verification, and hardening for Phase 1 `Package Management / observability`:
- **Package Observability Subsystem**: `code/aiosh-rust/aiosh-core/src/package_observability.rs` implementing `PackageObservabilityReport`, multi-dimensional aggregations, and telemetry serialization.
- **Invariants Enforced (PO1..PO6)**:
  - `PO1`: Inventory completeness (exact package count tracking; robust zeroed telemetry on empty stores).
  - `PO2`: Multi-dimensional distribution (breakdowns across state, format, and target architecture).
  - `PO3`: Storage footprint telemetry (`total_installed_size_bytes` calculation with saturation arithmetic and `average_package_size_bytes`).
  - `PO4`: Categorical dependency histogram bounding (`"0"`, `"1-5"`, `"6-10"`, `"11+"` with $O(1)$ memory).
  - `PO5`: Policy compliance telemetry (integrates with `PackageSecurityPolicy`, reports compliant count, violations, and prohibited packages).
  - `PO6`: Read-only deterministic telemetry emission with ISO timestamps and standard error envelopes.
- **Operator CLI Surface**: Integrated `aiosh package stats [--store <path>] [--config <path>] [--json]` in `aiosh-cli/src/main.rs`.
- **MCP API Surface**: Registered and dispatched `aios.package.stats` tool in `aiosh-mcp/src/main.rs` with immutable SQLite WAL audit logging.
- **Master Test Runner Matrix (`tools/test_package_suites.py`)**: Added criterion `PM8` (`test_package_observability`). All criteria `PM1..PM8` PASS.
- **Unit & Integration Suite**: `code/aiosh-rust/aiosh-core/tests/test_package_observability.rs` (7 tests covering PO1..PO7, file roundtrips, and hardening bounds).
- **Ledger Pointer**: Advances to **T-01281** (`Phase 1 — Linux Base System & Bootable Target / Package Management / documentation: Research`).

### 2026-09-04 — MILESTONE: Package Management Security Policy CLOSED 10/10 (T-01261..T-01270)

Complete implementation, governance, verification, and hardening for Phase 1 `Package Management / security policy`:
- **Package Security Policy Subsystem**: `code/aiosh-rust/aiosh-core/src/package_policy.rs` implementing `PackageSecurityPolicy`, `PackagePolicyMode` (`Enforcing`, `Audit`, `Permissive`), `PackagePolicyVerdict`, and `PackagePolicyViolation`.
- **Invariants Enforced (PP1..PP6)**:
  - `PP1`: Bounds validation on architectures ($\le 64$), formats, prohibited list ($\le 1024$), package sizes ($[10\text{ KiB} \dots 100\text{ GiB}]$), and dependencies ($[1 \dots 1024]$).
  - `PP2`: Prohibited package enforcement (blocking unencrypted services `telnet`, `rsh-client`, `rsh-server`, `rlogin`, `rexec`, `nis`, `yp-tools` with case-insensitive checking).
  - `PP3`: Cryptographic SHA-256 checksum validation mandating 64-character lowercase hexadecimal digests (`^[0-9a-f]{64}$`).
  - `PP4`: Transport protocol and repository security (strictly mandating `https://` or `file://` mirror URLs; rejecting plaintext HTTP).
  - `PP5`: System hygiene (architecture whitelisting, format checks, package size limits, dependency bounds).
  - `PP6`: Operational modes and pre-mutation transaction plan scanning.
- **Operator CLI Surface**: Integrated `aiosh package policy [--config <path>] [--package <name>] [--json]` in `aiosh-cli/src/main.rs`.
- **MCP API Surface**: Registered and dispatched `aios.package.policy` tool in `aiosh-mcp/src/main.rs` with PEP audit logging into SQLite WAL ring buffer.
- **Master Test Runner Matrix (`tools/test_package_suites.py`)**: Added criterion `PM7` (`test_package_policy`). All criteria `PM1..PM7` PASS.
- **Unit & Integration Suite**: `code/aiosh-rust/aiosh-core/tests/test_package_policy.rs` (7 tests covering PP1..PP6, file roundtrips, and hardening bounds).
- **Ledger Pointer**: Advances to **T-01271** (`Phase 1 — Linux Base System & Bootable Target / Package Management / observability: Research`).

### 2026-09-04 — MILESTONE: Package Management Automated Tests CLOSED 10/10 (T-01251..T-01260)

Complete implementation, governance, verification, and hardening for Phase 1 `Package Management / automated tests`:
- **Automated Integration Test Suite**: `code/aiosh-rust/aiosh-core/tests/test_package_automated.rs` delivering comprehensive end-to-end integration and lifecycle verification for criteria `PT1..PT6`.
- **Criteria Enforced**:
  - `PT1`: Deterministic plan reproducibility over 50 iterations with SHA-256 plan hash stability.
  - `PT2`: Multi-step lifecycle state transitions (`Available` $\to$ `Installed` $\to$ `Upgraded` $\to$ `Available`) with size delta arithmetic (`CS4`).
  - `PT3`: Dependency closure failure modes (unsatisfied dependencies, missing packages, joint satisfaction) (`CS3`).
  - `PT4`: Configuration-governed store capacity limits (`PC2`, `PC3`) and disk reload persistence.
  - `PT5`: Anti-tamper detection on delta tampering and clean rollback to pristine state. Dry-run isolation.
  - `PT6`: Negative boundary matrix (empty action lists, >256 action overflow, duplicate registration `CS1`).
- **Master Test Runner Integration (`tools/test_package_suites.py`)**: Added criterion `PM6` (`test_package_automated`). All criteria `PM1..PM6` PASS.
- **Ledger Pointer**: Advances to **T-01261** (`Phase 1 — Linux Base System & Bootable Target / Package Management / security policy: Research`).

### 2026-09-04 — MILESTONE: Package Management Configuration CLOSED 10/10 (T-01241..T-01250)

Complete implementation, governance, verification, and hardening for Phase 1 `Package Management / configuration`:
- **Hierarchical Configuration Subsystem**: `code/aiosh-rust/aiosh-core/src/package_config.rs` delivering `PackageConfig` resolution with deterministic precedence: file config (`--config`) > environment variables (`AIOS_PACKAGE_*`) > secure defaults.
- **Invariants Enforced (PC1..PC6)**: Store path validation (`PC1`), store size ceiling `[64 KiB .. 100 MiB]` (`PC2`), bounded entity counts `[10 .. 100,000]` (`PC3`), repository transport security enforcing `https://` or `file://` (`PC4`), explicit file/env precedence (`PC5`), and 64 KiB config stream bounded reads (`PC6`).
- **Operator CLI & MCP Surfaces**: `aiosh package config [--config <path>] [--json]` and `aios.package.config` MCP tool with structured JSON output, explicit error envelopes, and full SQLite WAL audit logging.
- **Master Test Runner Matrix (`tools/test_package_suites.py`)**: All criteria `PM1`, `PM2`, `PM3`, `PM4`, and `PM5` PASS.
- **Unit Suite**: `test_package_config` (7 tests covering PC1..PC6 invariants, file roundtrips, and env overrides).
- **Ledger Pointer**: Advances to **T-01251** (`Phase 1 — Linux Base System & Bootable Target / Package Management / automated tests: Research`).

### 2026-09-04 — MILESTONE: Package Management MCP/API Surface CLOSED 10/10 (T-01231..T-01240)

Complete implementation, governance, verification, and hardening for Phase 1 `Package Management / MCP/API surface`:
- **Comprehensive Autonomous Agent MCP Surface**: `code/aiosh-rust/aiosh-mcp/src/main.rs` delivering 6 MCP tools under `aios.package.*`:
  - `aios.package.validate`: Syntax validation of package names (`PM1`) and deep specification checks (`PM1..PM5`).
  - `aios.package.list`: Enumerate packages with format, state, pattern, and limit filters.
  - `aios.package.get`: Detailed specification lookup for a single package.
  - `aios.package.plan`: Transaction planning with dependency closure validation (`CS2`, `CS3`) and delta calculation (`CS4`).
  - `aios.package.search`: Substring search on names and descriptions with pagination limit [1..10,000].
  - `aios.package.apply`: Transaction execution with dry-run support, state transitions (`CS5`), and atomic persistence.
- **PEP Gating & Audit Logging**: Every tool execution is gated via `dispatch::recorded_call`, writing immutable SHA-256 hash-chained audit rows to SQLite WAL ring for every success, failure, or refusal.
- **Hardening & Defenses**: String bounds (names <= 128, patterns <= 256, paths <= 1,024), limit bounding [1..10,000], action count limit (10,000), ASCII control character rejection, and explicit error envelopes.
- **Master Test Runner Matrix (`tools/test_package_suites.py`)**: All criteria `PM1`, `PM2`, `PM3`, and `PM4` PASS.
- **Unit Suite**: `test_mcp_package_tools` (28 assertions covering positive flows, negative bounds, control characters, and disk persistence).
- **Ledger Pointer**: Advances to **T-01241** (`Phase 1 — Linux Base System & Bootable Target / Package Management / configuration: Research`).

### 2026-09-04 — MILESTONE: Package Management CLI Surface CLOSED 10/10 (T-01221..T-01230)

Complete implementation, governance, verification, and hardening for Phase 1 `Package Management / CLI surface`:
- **Comprehensive Operator CLI Surface**: `code/aiosh-rust/aiosh-cli/src/main.rs` delivering `aiosh package validate` (syntax and deep specification audit), `aiosh package list` (query and filter with bounds), `aiosh package show` (deep attribute inspection), `aiosh package search` (substring query engine), `aiosh package plan` (deterministic planning), and `aiosh package apply` (transaction execution with atomic store persistence).
- **Hardening & Security Controls**: 1 MiB payload protection on `--actions`, `--plan`, `--spec`, string bounds (names <= 64, patterns <= 256, paths <= 1,024), limit bounding [1..10,000], ASCII control character rejection, structured error envelopes, and complete SQLite `audit.db` logging via `classify_and_emit` on all execution branches (ADR-0035).
- **Master Test Runner Matrix (`tools/test_package_suites.py`)**: Criteria `PM1`, `PM2`, and `PM3` PASS.
- **Unit Suite**: `aiosh-cli::task_cli_tests::test_cmd_package_flow` exercising happy paths, dry-run flags, invalid inputs, error codes, and persistent store roundtrips.
- **Ledger Pointer**: Advances to **T-01231** (`Phase 1 — Linux Base System & Bootable Target / Package Management / MCP/API surface: Research`).

### 2026-09-04 — MILESTONE: Package Management Core Service CLOSED 10/10 (T-01211..T-01220)

Complete implementation, governance, verification, and hardening for Phase 1 `Package Management / core service`:
- **In-Memory Store Subsystem**: `code/aiosh-rust/aiosh-core/src/package_service.rs` delivering `PackageStore` with canonical Debian and Alpine reference packages, query engine, transaction planner (`plan_transaction`), execution engine (`execute_transaction`), and atomic disk persistence (`save_to_path`, `load_from_path`).
- **Core Invariants (CS1..CS5)**: Strictly enforced package ID uniqueness (`CS1`), deterministic transaction hash planning (`CS2`), dependency closure validation (`CS3`), delta arithmetic and anti-tamper checking (`CS4`), atomic persistence with RAII cleanup and bounded 10 MiB / 10,000 package limits (`CS5`).
- **Operator CLI & MCP Surfaces**: `aiosh package list/show/plan` and `aios.package.list/get/plan` tools with structured JSON error envelopes (`LOAD_STORE_FAILED`, `INVALID_ARGUMENT`, `PACKAGE_NOT_FOUND`, `PAYLOAD_TOO_LARGE`, `INVALID_JSON`, `PLAN_FAILED`) and SQLite WAL audit logging.
- **Master Test Runner Matrix (`tools/test_package_suites.py`)**: Criteria `PM1` and `PM2` PASS.
- **Unit Suite**: `code/aiosh-rust/aiosh-core/tests/test_package_service.rs` (9 tests passing in isolation).
- **Ledger Pointer**: Advances to **T-01221** (`Phase 1 — Linux Base System & Bootable Target / Package Management / CLI surface: Research`).

### 2026-09-04 — MILESTONE: Package Management Data Model CLOSED 10/10 (T-01201..T-01210)

Complete implementation, governance, verification, and hardening for Phase 1 `Package Management / data model`:
- **Unified Data Model Subsystem**: `code/aiosh-rust/aiosh-core/src/package.rs` delivering `PackageSpec`, `PackageFormat`, `PackageState`, `PackageDependency`, `PackageAction`, `PackageTransaction`, and `PackageQuery`.
- **Validation Invariants (PM1..PM5)**: Strictly enforced syntax for Debian and Alpine package names, size bounds (64-char versions, 4096-byte descriptions, 256 dependencies, 100 GiB ceiling), dependency hygiene, SHA-256 integrity, and HTTPS repository transport.
- **Operator CLI & MCP Surfaces**: `aiosh package validate (--name <name> | --spec <file_or_json>) [--json]` and `aios.package.validate` tool with 1 MiB payload protection and SQLite WAL audit logging.
- **Master Test Runner Matrix (`tools/test_package_suites.py`)**: Criterion `PM1` PASS.
- **Unit Suite**: `code/aiosh-rust/aiosh-core/tests/test_package_data_model.rs` (7 tests passing in isolation).
- **Ledger Pointer**: Advances to **T-01211** (`Phase 1 — Linux Base System & Bootable Target / Package Management / core service: Research`).

### 2026-09-04 — MILESTONE: Base Image Build Recovery & Validation CLOSED 10/10 (T-01191..T-01200) — BASE IMAGE BUILD EPIC COMPLETE (100/100, TASK 1200 ACHIEVED!)

Complete implementation, governance, verification, and hardening for Phase 1 `Base Image Build / recovery & validation`:
- **Corruption Recovery & Validation Subsystem**: `code/aiosh-rust/aiosh-core/src/base_image_recovery.rs` delivering manifest and store validation (`validate_manifest`, `validate_store`) and non-destructive corruption recovery (`load_or_recover`).
- **Mathematical Invariants (RV1..RV4)**: Verified arithmetic equality of manifests (`valid + invalid == total`), health flag consistency, error count tracking, and `.bak.<timestamp>` forensic anti-tampering backups.
- **Operator CLI & MCP Surfaces**: `aiosh image check [--fix] [--json] [--store <path>]` and `aios.image.check` tools with error envelopes and SQLite WAL audit logging.
- **Hardening & Defenses**: 1024 package limit, 100 GiB image size cap, 10 MiB store limit, and forensic backups.
- **Master Test Runner Matrix (`tools/test_image_suites.py`)**: All criteria `B1..B9` PASS.
- **Unit Suite**: `code/aiosh-rust/aiosh-core/tests/test_base_image_recovery.rs` (5 tests passing in isolation).
- **Full Epic Closure**: 100/100 tasks completed across Data Model (`T-01101..T-01110`), Core Service (`T-01111..T-01120`), CLI (`T-01121..T-01130`), MCP (`T-01131..T-01140`), Configuration (`T-01141..T-01150`), Automated Integration (`T-01151..T-01160`), Security Policy (`T-01161..T-01170`), Observability (`T-01171..T-01180`), Documentation (`T-01181..T-01190`), and Recovery & Validation (`T-01191..T-01200`).
- **Milestone Metric**: **TASK 1,200 / 10,000 (12.00%) REACHED!**
- **Ledger Pointer**: Advances to **T-01201** (`Phase 1 — Linux Base System & Bootable Target / Package Management / data model: Research`).

### 2026-09-04 — MILESTONE: Base Image Build Documentation CLOSED 10/10 (T-01181..T-01190)

Complete implementation, governance, verification, and hardening for Phase 1 `Base Image Build / documentation`:
- **Architecture & Operational Guide**: Comprehensive 9-section documentation authored in `docs/base_image_build.md` detailing image formats (`raw`, `qcow2`, `iso`), 4-stage build lifecycle, configuration precedence, security invariants (`P1..P7`), observability invariants (`OB1..OB5`), CLI and MCP tool references, and audit guarantees.
- **Automated Documentation Test Suite**: Standalone test suite `tools/test_base_image_doc.py` covering criteria `D1..D5`.
- **Rot-Proof Invariant Enforcement**: Confirmed path resolution and zero volatility in `docs/README.md` via `tools/check_task_docs.py` (C1..C6 PASS).
- **Master Test Runner Integration**: All criteria `B1..B8` in `tools/test_image_suites.py` PASS.
- **Ledger Pointer**: Advances to **T-01191** (`Phase 1 / Base Image Build / recovery & validation: Research`).

### 2026-09-04 — MILESTONE: Base Image Build Observability CLOSED 10/10 (T-01171..T-01180)

Complete implementation, governance, verification, and hardening for Phase 1 `Base Image Build / observability`:
- **Observability Reporting Engine**: `BaseImageObservabilityReport` in `code/aiosh-rust/aiosh-core/src/base_image_observability.rs` aggregating total manifests, format distributions, arch distributions, distro breakdowns, policy compliance, unique kernel versions, and storage budgets.
- **Arithmetic Invariants (OB1..OB5)**: Complete validation enforcing format/arch/distro breakdown sum equality, policy compliance bounds, and average calculation integrity.
- **CLI & MCP Tool Surfaces**: `aiosh image report` and `aios.image.report` with structured JSON output envelopes and SQLite WAL audit logging.
- **Security Hardening**: Enforced bounds (16 formats, 64 archs, 256 distros, 256 kernels), control character rejection, and fail-closed error handling.
- **Test Runner Matrix (`tools/test_image_suites.py`)**: All criteria `B1..B8` PASS.
- **Ledger Pointer**: Advances to **T-01181** (`Phase 1 / Base Image Build / documentation: Research`).

### 2026-09-01 — MILESTONE: Distro Selection & Justification Data Model CLOSED 10/10 (T-01001..T-01010) — PHASE 1 INITIATED

Complete implementation, governance, verification, and hardening for Phase 1 `Distro Selection & Justification / data model`:
- **Distribution Model Specification**: `DistroProfile`, `DistroEvaluation`, `DistroFamily`, `InitSystem`, `ArchTarget`, `CLibrary` in `code/aiosh-rust/aiosh-core/src/distro.rs`.
- **Target Invariant Validation**: `validate_distro_profile` enforcing semver kernel parsing, profile ID character whitelisting, and field bounds.
- **Production Scoring Engine**: Multi-criteria weighted evaluation algorithm (`DistroEvaluation::evaluate`).
- **Test Runner Matrix (`tools/test_distro_suites.py`)**: Criterion `D1` distro data model integrity and validation.
- **Unit Suite (`tools/test_distro_unit.py`)**: Behavioral assertions U01..U04 passing in isolation.
- **Documentation**: Updated `docs/README.md` with Phase 1 section and distro profiles.
- **Ledger Pointer**: Advances to **T-01011** (`Phase 1 / Distro Selection & Justification / core service: Research`).

### 2026-08-31 — MILESTONE: Agent Handoff Protocol Documentation CLOSED 10/10 (T-00991..T-01000) — EPIC COMPLETE (100/100) — TASK 1000 ACHIEVED!

Complete implementation, governance, verification, and hardening for `Agent Handoff Protocol / documentation`:
- **Full Epic Closure**: 100/100 tasks across Data Model (`T-00911..T-00920`), Core Service (`T-00921..T-00930`), CLI Surface (`T-00931..T-00940`), MCP/API Surface (`T-00941..T-00950`), Configuration (`T-00951..T-00960`), Automated Tests (`T-00961..T-00970`), Security Policy (`T-00971..T-00980`), Observability (`T-00981..T-00990`), and Documentation (`T-00991..T-01000`).
- **Comprehensive Documentation**: Complete coverage in `docs/README.md` with rot-proof invariants C1..C6.
- **Master Test Runner Matrix (`tools/test_handoff_suites.py`)**: All criteria `H1..H8` PASS.
- **Unit Suite (`tools/test_handoff_unit.py`)**: All assertions `U01..U17` PASS.
- **Milestone Metric**: **TASK 1000 / 10,000 (10.00%) REACHED!**
- **Ledger Pointer**: Advances to **T-01001** (`Phase 0 / Agent Coordination Protocol / data model: Research`).

### 2026-08-31 — MILESTONE: Agent Handoff Protocol Observability CLOSED 10/10 (T-00981..T-00990)

Complete implementation, governance, verification, and hardening for `Agent Handoff Protocol / observability`:
- **Observability Reporting Engine**: `HandoffReport` container in `code/aiosh-rust/aiosh-core/src/handoff.rs` with `total_handoffs`, `active_handoffs`, `completed_handoffs` distributions.
- **Arithmetic Invariant Enforcement**: `validate_handoff_report` guaranteeing `active + completed == total`.
- **Test Runner Matrix (`tools/test_handoff_suites.py`)**: Criterion `H8` observability metrics and report validation.
- **Unit Suite (`tools/test_handoff_unit.py`)**: Behavioral assertions U01..U17 passing in isolation.
- **Documentation**: Updated `docs/README.md` with observability metrics structure.
- **Ledger Pointer**: Advances to **T-00991** (`Agent Handoff Protocol / documentation: Research`).

### 2026-08-31 — MILESTONE: Agent Handoff Protocol Security Policy CLOSED 10/10 (T-00971..T-00980)

Complete implementation, governance, verification, and hardening for `Agent Handoff Protocol / security policy`:
- **Role-Based Authorization Gate**: `can_agent_act` and `verify_handoff_authorization` methods in `code/aiosh-rust/aiosh-core/src/handoff.rs` restricting control actions.
- **Fail-Closed Execution**: Rejection with `PermissionDenied` on any unauthorized caller interception.
- **Test Runner Matrix (`tools/test_handoff_suites.py`)**: Criterion `H7` security policy and actor authorization matrix.
- **Unit Suite (`tools/test_handoff_unit.py`)**: Behavioral assertions U01..U15 passing in isolation.
- **Documentation**: Updated `docs/README.md` with security authorization details.
- **Ledger Pointer**: Advances to **T-00981** (`Agent Handoff Protocol / observability: Research`).

### 2026-08-31 — MILESTONE: Agent Handoff Protocol Automated Tests CLOSED 10/10 (T-00961..T-00970)

Complete implementation, governance, verification, and hardening for `Agent Handoff Protocol / automated tests`:
- **State Matrix & Edge-Case Harness**: Comprehensive tests in `code/aiosh-rust/aiosh-core/src/handoff_service.rs` verifying rejection paths, cancellations, terminal state immutability, and 50+ concurrent requests.
- **Test Runner Matrix (`tools/test_handoff_suites.py`)**: Criterion `H6` automated edge cases, state matrix, and batch fuzzing.
- **Unit Suite (`tools/test_handoff_unit.py`)**: Behavioral assertions U01..U13 passing in isolation.
- **Documentation**: Updated `docs/README.md` with automated test details.
- **Ledger Pointer**: Advances to **T-00971** (`Agent Handoff Protocol / security policy: Research`).

### 2026-08-31 — MILESTONE: Agent Handoff Protocol Configuration CLOSED 10/10 (T-00951..T-00960)

Complete implementation, governance, verification, and hardening for `Agent Handoff Protocol / configuration`:
- **Configuration Engine (`aiosh-core::handoff_config`)**: `HandoffConfig` container managing storage caps, defaults, and TTL expiration settings.
- **Config-Aware Store Integration**: `HandoffStore::load_from_path_with_config` and `load_or_recover_with_config` enforcing configured thresholds.
- **Test Runner Matrix (`tools/test_handoff_suites.py`)**: Criterion `H5` configuration validation, bounds checking, and disk roundtripping.
- **Unit Suite (`tools/test_handoff_unit.py`)**: Behavioral assertions U01..U11 passing in isolation.
- **Documentation**: Updated `docs/README.md` with configuration parameters and environment variables.
- **Ledger Pointer**: Advances to **T-00961** (`Agent Handoff Protocol / automated tests: Research`).

### 2026-08-31 — MILESTONE: Agent Handoff Protocol MCP/API Surface CLOSED 10/10 (T-00941..T-00950)

Complete implementation, governance, verification, and hardening for `Agent Handoff Protocol / MCP/API surface`:
- **MCP Tool Endpoints (`aiosh-mcp`)**: `aios.handoff.list`, `show`, `initiate`, `accept`, `reject`, `complete`, `cancel` exposed via JSON-RPC 2.0.
- **PEP & Audit Integration**: Handled via `dispatch::recorded_call` ensuring strict PEP evaluation and SQLite audit trail emission.
- **Test Runner Matrix (`tools/test_handoff_suites.py`)**: Criterion `H4` MCP surface tools and flow.
- **Unit Suite (`tools/test_handoff_unit.py`)**: Behavioral assertions U01..U09 passing in isolation.
- **Documentation**: Updated `docs/README.md` with MCP tool schemas and JSON-RPC examples.
- **Ledger Pointer**: Advances to **T-00951** (`Agent Handoff Protocol / configuration: Research`).

### 2026-08-31 — MILESTONE: Agent Handoff Protocol CLI Surface CLOSED 10/10 (T-00931..T-00940)

Complete implementation, governance, verification, and hardening for `Agent Handoff Protocol / CLI surface`:
- **CLI Commands (`aiosh-cli`)**: `aiosh handoff [list|show|initiate|accept|reject|complete|cancel]` with full parameter validation and exit codes.
- **Audit Compliance**: Synchronous audit row emission via `classify_and_emit` on every state change.
- **Test Runner Matrix (`tools/test_handoff_suites.py`)**: Criterion `H3` CLI surface subcommands and flow.
- **Unit Suite (`tools/test_handoff_unit.py`)**: Behavioral assertions U01..U07 passing in isolation.
- **Documentation**: Updated `docs/README.md` with CLI commands and examples.
- **Ledger Pointer**: Advances to **T-00941** (`Agent Handoff Protocol / MCP/API surface: Research`).

### 2026-08-31 — MILESTONE: Agent Handoff Protocol Core Service CLOSED 10/10 (T-00921..T-00930)

Complete implementation, governance, verification, and hardening for `Agent Handoff Protocol / core service`:
- **State Store (`aiosh-core::handoff_service`)**: `HandoffStore` with state transitions (`accept`, `reject`, `complete`, `cancel`), deduplication, active queue filtering, and report generation.
- **Persistence & Recovery**: Atomic temporary file write (`.tmp`) and fail-safe corruption recovery (`load_or_recover`).
- **Test Runner Matrix (`tools/test_handoff_suites.py`)**: Criterion `H2` core service store lifecycle, transitions & persistence.
- **Unit Suite (`tools/test_handoff_unit.py`)**: Behavioral assertions U01..U05 passing in isolation.
- **Documentation**: Updated `docs/README.md` with core service store documentation.
- **Ledger Pointer**: Advances to **T-00931** (`Agent Handoff Protocol / CLI surface: Research`).

### 2026-08-31 — MILESTONE: Agent Handoff Protocol Data Model CLOSED 10/10 (T-00911..T-00920)

Complete implementation, governance, verification, and hardening for `Agent Handoff Protocol / data model`:
- **Core Primitives (`aiosh-core::handoff`)**: `HandoffRecord` container (`HND-<hash>`), `HandoffReport`, status & priority enums, deterministic SHA-256 fingerprinting.
- **Invariant Validation**: `validate_handoff_record` and `validate_handoff_report` structural checkers.
- **Test Runner Matrix (`tools/test_handoff_suites.py`)**: Criterion `H1` data model integrity and signature determinism.
- **Unit Suite (`tools/test_handoff_unit.py`)**: Behavioral assertions U01..U03 passing in isolation.
- **Documentation**: New section `## Agent Handoff Protocol (T-00911..T-01000)` in `docs/README.md`.
- **Ledger Pointer**: Advances to **T-00921** (`Agent Handoff Protocol / core service: Research`).

### 2026-08-31 — MILESTONE: Regression Triage Recovery & Validation CLOSED 10/10 (T-00901..T-00910) — EPIC CLOSED (100/100)

Complete implementation, governance, verification, and hardening for `Regression Triage / recovery & validation`:
- **Validation Engine (`aiosh-core::triage`)**: `validate_triage_record` structural checks (ID, SHA-256 fingerprint, non-empty fields, occurrence bounds).
- **Resilient Recovery (`aiosh-core::triage_service`)**: `TriageStore::load_or_recover` gracefully handling corrupted or invalid store files with diagnostic warnings.
- **Criteria T1..T8 Matrix (`tools/test_triage_suites.py`)**: Full coverage across data model, core service, CLI, MCP tools, config, E2E lifecycle, observability, and recovery resilience.
- **Unit Suite Extensions (`tools/test_triage_unit.py`)**: Behavioral assertions U01..U09 passing in isolation.
- **EPIC COMPLETE**: Regression Triage Epic (`T-00811..T-00910`) **100/100 tasks CLOSED**.
- **Ledger Pointer**: Advances to **T-00911** (`Agent Handoff Protocol / data model: Research`).

### 2026-08-31 — MILESTONE: Regression Triage Documentation CLOSED 10/10 (T-00891..T-00900)

Complete implementation, governance, verification, and hardening for `Regression Triage / documentation`:
- **Comprehensive Reference (`docs/README.md`)**: Complete specifications for data models, core service store, CLI subcommands, MCP JSON-RPC tools, `TriageConfig`, automated testing, security invariants, and observability.
- **Structural Integrity (C1..C6)**: Validated using `tools/check_task_docs.py`.
- **Ledger Pointer**: Advances to **T-00901** (`recovery & validation: Research`).

### 2026-08-31 — MILESTONE: Regression Triage Observability CLOSED 10/10 (T-00881..T-00890)

Complete implementation, governance, verification, and hardening for `Regression Triage / observability`:
- **Observability Metrics (`aiosh-core::triage`)**: `status_counts()`, `severity_counts()`, and standardized `summary_line()` diagnostics on `TriageReport`.
- **Test Runner Criterion T7 (`tools/test_triage_suites.py`)**: Validates diagnostic calculations and lifecycle reporting.
- **Unit Suite Extensions (`tools/test_triage_unit.py`)**: Extended U01..U08 behavioral assertions.
- **Documentation & Invariants**: Updated `docs/README.md` passing all C1..C6 structural invariants.
- **Ledger Pointer**: Advances to **T-00891** (`documentation: Research`).

### 2026-08-31 — MILESTONE: Regression Triage Security Policy CLOSED 10/10 (T-00871..T-00880)

Complete implementation, governance, verification, and hardening for `Regression Triage / security policy`:
- **Security Policy Invariants (`SECURITY.md`)**: Formally defined prohibitions against falsifying or bypassing regression triage records; mandated immutable SQLite WAL audit emission.
- **Evidence Linking**: Linked security review `docs/tasks/evidence/T-00877-security.md` into `SECURITY.md` § Security Knowledge Index.
- **Automated OpenSSF Scorecard Compliance**: Verified criteria S1..S5 in `tools/check_security_policy.py`.
- **Documentation & Invariants**: Updated `docs/README.md` passing all C1..C6 structural invariants.
- **Ledger Pointer**: Advances to **T-00881** (`observability: Research`).

### 2026-08-31 — MILESTONE: Regression Triage Automated Tests CLOSED 10/10 (T-00861..T-00870)

Complete implementation, governance, verification, and hardening for `Regression Triage / automated tests`:
- **Automated Test Matrix (`tools/test_triage_suites.py`)**: Full coverage of criteria `T1..T6` (data model, core store, CLI, MCP tools, config, and E2E recurrence lifecycle).
- **Behavioral Unit Test Suite (`tools/test_triage_unit.py`)**: Validates test runner functions, execution harness, and exit code isolation.
- **Documentation & Invariants**: Updated `docs/README.md` passing all C1..C6 structural invariants.
- **Ledger Pointer**: Advances to **T-00871** (`security policy: Research`).

### 2026-08-31 — MILESTONE: Regression Triage Configuration CLOSED 10/10 (T-00851..T-00860)

Complete implementation, governance, verification, and hardening for `Regression Triage / configuration`:
- **Configuration Module (`aiosh-core::triage_config`)**: `TriageConfig`, `should_ingest_suite`, parameter boundary checks, and size-capped persistence.
- **Service Integration (`aiosh-core::triage_service`)**: `load_from_path_with_config` and `ingest_ci_summary_with_config`.
- **CLI Integration (`aiosh-cli::main`)**: `--config <path>` flag and `$AIOS_TRIAGE_CONFIG` environment override.
- **Test Runner (`tools/test_triage_suites.py`)**: Criterion `T5` validating configuration schema, validation rules, and suite filters.
- **Documentation & Invariants**: Updated `docs/README.md` passing all C1..C6 structural invariants.
- **Ledger Pointer**: Advances to **T-00861** (`automated tests: Research`).

### 2026-08-31 — MILESTONE: Regression Triage MCP/API Surface CLOSED 10/10 (T-00841..T-00850)

Complete implementation, governance, verification, and hardening for `Regression Triage / MCP/API surface`:
- **MCP JSON-RPC Tools (`aiosh-mcp::Server`)**: `aios.triage.list`, `aios.triage.show`, `aios.triage.record`, `aios.triage.resolve`, `aios.triage.check` with parameter validation and SQLite WAL audit logging.
- **Test Runner (`tools/test_triage_suites.py`)**: Criterion `T4` validating tool manifest, execution, error states, and resolution cycle.
- **Documentation & Invariants**: Updated `docs/README.md` passing all C1..C6 structural invariants.
- **Ledger Pointer**: Advances to **T-00851** (`Fingerprinting & dedup: Research`).

### 2026-08-31 — MILESTONE: Regression Triage CLI Surface CLOSED 10/10 (T-00831..T-00840)

Complete implementation, governance, verification, and hardening for `Regression Triage / CLI surface`:
- **CLI Subcommands (`aiosh-cli::main`)**: `aiosh triage` supporting `list`, `show`, `record`, `resolve`, `ingest`, and `check` with JSON output and SQLite WAL audit trail logging.
- **Test Runner (`tools/test_triage_suites.py`)**: Criterion `T3` validating CLI commands, parameter handling, and exit codes.
- **Documentation & Invariants**: Updated `docs/README.md` passing all C1..C6 structural invariants.
- **Ledger Pointer**: Advances to **T-00841** (`MCP/API: Research`).

### 2026-08-31 — MILESTONE: Regression Triage Core Service CLOSED 10/10 (T-00821..T-00830)

Complete implementation, governance, verification, and hardening for `Regression Triage / core service`:
- **Core Service (`aiosh-core::triage_service`)**: `TriageStore`, `ingest_ci_summary`, failure deduplication, resolution transitions, reopening upon regression recurrence, and size-capped disk persistence.
- **Test Runner (`tools/test_triage_suites.py`)**: Criterion `T2` validating store persistence, status lifecycle, and CI summary ingestion.
- **Documentation & Invariants**: Updated `docs/README.md` passing all C1..C6 structural invariants.
- **Ledger Pointer**: Advances to **T-00831** (`CLI: Research`).

### 2026-08-31 — MILESTONE: Regression Triage Data Model CLOSED 10/10 (T-00811..T-00820)

Complete implementation, governance, verification, and hardening for `Regression Triage / data model`:
- **Core Types (`aiosh-core::triage`)**: `TriageStatus`, `TriageSeverity`, `TriageRecord`, `TriageReport`, `validate_triage_report`, and deterministic `compute_failure_signature`.
- **Test Runner (`tools/test_triage_suites.py`)**: Criterion `T1` verifying data model integrity and failure fingerprinting.
- **Documentation & Invariants**: Updated `docs/README.md` passing all C1..C6 structural invariants.
- **Ledger Pointer**: Advances to **T-00821** (`core service: Research`).

### 2026-08-31 — GRAND MILESTONE: Secrets & Access Hygiene Subsystem CLOSED (100/100 tasks T-00711..T-00810)

Complete implementation, governance, verification, and hardening for all sub-epics of `Secrets & Access Hygiene`:
- **Recovery & Validation (`aiosh-core::secrets`)**: `validate_secret_report` enforcing structural invariants, fault-tolerant scanning, and documented remediation protocols.
- **Criteria K1..K9 Suite (`tools/test_secrets_suites.py`)**: Full coverage of data models, scanners, CLI, MCP tools, config, observability, and validation.
- **Documentation & Invariants**: Updated `docs/README.md` and `SECURITY.md` passing all C1..C6 and S1..S5 invariants.
- **Ledger Pointer**: Advances to **T-00811**.

### 2026-08-31 — MILESTONE: Secrets & Access Hygiene Documentation CLOSED 10/10 (T-00791..T-00800)

Complete implementation, governance, verification, and hardening for `Secrets & Access Hygiene / documentation`:
- **Subsystem Reference (`docs/README.md`)**: Comprehensive documentation covering data models, scanning engines, CLI usage, MCP JSON-RPC schemas, and configuration.
- **Documentation Invariant Health**: 100% compliant with criteria C1..C6 in `tools/check_task_docs.py`.
- **Ledger Pointer**: Advances to **T-00801** (`recovery & validation: Research`).

### 2026-08-31 — MILESTONE: Secrets & Access Hygiene Observability CLOSED 10/10 (T-00781..T-00790)

Complete implementation, governance, verification, and hardening for `Secrets & Access Hygiene / observability`:
- **Observability Methods (`aiosh-core::secrets`)**: `SecretScanReport::severity_counts()` and `SecretScanReport::summary_line()` providing structured severity breakdowns and human-readable diagnostics.
- **Automated Test Criteria K8**: Extended `tools/test_secrets_suites.py` validating metrics integrity and telemetry formatting.
- **Documentation & Invariants**: Updated `docs/README.md` passing all C1..C6 structural invariants.
- **Ledger Pointer**: Advances to **T-00791** (`documentation: Research`).

### 2026-08-31 — MILESTONE: Secrets & Access Hygiene Security Policy CLOSED 10/10 (T-00771..T-00780)

Complete implementation, governance, verification, and hardening for `Secrets & Access Hygiene / security policy`:
- **Security Policy Integration (`SECURITY.md`)**: Formalized vulnerability criteria prohibiting plaintext credential emission and scanner bypass; linked security review `docs/tasks/evidence/T-00777-security.md`.
- **Automated OpenSSF Scorecard Compliance**: Verified criteria S1..S5 in `tools/check_security_policy.py`.
- **Documentation & Invariants**: Updated `docs/README.md` passing all C1..C6 structural invariants.
- **Ledger Pointer**: Advances to **T-00781** (`observability: Research`).

### 2026-08-31 — MILESTONE: Secrets & Access Hygiene Automated Tests CLOSED 10/10 (T-00761..T-00770)

Complete implementation, governance, verification, and hardening for `Secrets & Access Hygiene / automated tests`:
- **Automated Suite Runner (`tools/test_secrets_suites.py`)**: Complete validation of criteria K1..K7 covering data model, private keys, API tokens, configuration credentials, CLI commands, MCP tools, and `SecretsConfig`.
- **Hardening & Isolation**: Enforced 120s execution timeouts, isolated ephemeral temp directories, and robust error diagnostics.
- **Documentation & Invariants**: Updated `docs/README.md` passing all C1..C6 structural invariants.
- **Ledger Pointer**: Advances to **T-00771** (`security policy: Research`).

### 2026-08-31 — MILESTONE: Secrets & Access Hygiene Configuration CLOSED 10/10 (T-00751..T-00760)

Complete implementation, governance, verification, and hardening for `Secrets & Access Hygiene / configuration`:
- **Configuration Engine (`aiosh-core::secrets_config`)**: Shipped `SecretsConfig` with versioning, bounded file/line limits, ignored directories, and allowlist patterns with strict schema validation.
- **Default Baseline & Precedence**: Created `docs/secrets_config.json` with precedence order `--config` $\to$ `AIOS_SECRETS_CONFIG` $\to$ `docs/secrets_config.json` $\to$ `SecretsConfig::default()`.
- **Automated Tests & Invariants**: Unit test coverage in `secrets_config::tests` (3/3 PASS), CLI integration in `aiosh-cli::task_cli_tests` (16/16 PASS), standalone runner `tools/test_secrets_suites.py` validating criteria `K1..K7`.
- **Documentation & Invariants**: Updated `docs/README.md` passing all C1..C6 structural invariants.
- **Ledger Pointer**: Advances to **T-00761** (`automated tests: Research`).

### 2026-08-31 — MILESTONE: Secrets & Access Hygiene MCP/API Surface CLOSED 10/10 (T-00741..T-00750)

Complete implementation, governance, verification, and hardening for `Secrets & Access Hygiene / MCP/API surface`:
- **MCP Server Tools (`aiosh-mcp`)**: Shipped `aios.secrets.scan` and `aios.secrets.check` with JSON-RPC 2.0 schemas, full workspace/file scanning, and safe redaction guarantees.
- **Dispatch Gating & Auditing**: Calls route via `dispatch::recorded_call` generating honest SQLite WAL audit rows.
- **Automated Tests & Invariants**: Unit test coverage in `aiosh_mcp::tests` passing 4/4, standalone runner `tools/test_secrets_suites.py` validating criteria `K1..K6`.
- **Documentation & Invariants**: Updated `docs/README.md` passing all C1..C6 structural invariants.
- **Ledger Pointer**: Advances to **T-00751** (`configuration: Research`).

### 2026-08-31 — MILESTONE: Secrets & Access Hygiene CLI Surface CLOSED 10/10 (T-00731..T-00740)

Complete implementation, governance, verification, and hardening for `Secrets & Access Hygiene / CLI surface`:
- **CLI Subcommand Surface (`aiosh-cli`)**: Shipped `aiosh secrets scan` and `aiosh secrets check` with full `--repo`, `--file`, `--max-bytes`, and `--json` support.
- **Prose & Machine-Readable Output**: Clean finding cards with redacted snippets, cryptographic fingerprints, and severity breakdown counters.
- **Automated Tests & Invariants**: Unit test coverage in `aiosh-cli::task_cli_tests` passing 16/16, standalone suite runner `tools/test_secrets_suites.py` validating criteria `K1..K5`.
- **Documentation & Invariants**: Updated `docs/README.md` passing all C1..C6 structural invariants.
- **Ledger Pointer**: Advances to **T-00741** (`MCP server surface: Research`).

### 2026-08-31 — MILESTONE: Secrets & Access Hygiene Core Service CLOSED 10/10 (T-00721..T-00730)

Complete implementation, governance, verification, and hardening for `Secrets & Access Hygiene / core service`:
- **Core Service Operations (`aiosh-core::secrets_service`)**: `scan_file_for_secrets` (SEC-001 private keys, SEC-002 AWS access keys, SEC-003 GitHub PATs, SEC-004 generic API keys, SEC-005 configuration passwords) with null-byte binary filtering, line length limits (4096 bytes), and 16 MiB size bounds.
- **Workspace Ingestion (`scan_workspace_for_secrets`)**: Full directory recursion skipping VCS/build directories (`.git`, `target`, `node_modules`, `.venv`, `dist`) with aggregated `SecretScanReport` outputs.
- **Unit & Suite Testing**: Unit test coverage in `secrets_service::tests` passing 7/7, and test runner `tools/test_secrets_suites.py` validating criteria `K1..K4`.
- **Documentation & Invariants**: Updated `docs/README.md` passing all C1..C6 structural invariants.
- **Ledger Pointer**: Advances to **T-00731** (`CLI surface: Research`).

### 2026-08-30 — MILESTONE: Secrets & Access Hygiene Data Model CLOSED 10/10 (T-00711..T-00720)

Complete implementation, governance, verification, and hardening for `Secrets & Access Hygiene / data model`:
- **Data Model Core (`aiosh-core::secrets`)**: `SecretSeverity` (`Critical`, `High`, `Medium`, `Low`, `Info`), `SecretPatternKind` (`PrivateKey`, `ApiToken`, `AwsCredentials`, `PasswordInConfig`, `HighEntropyGeneric`), `SecretFinding`, and `SecretScanReport`.
- **Safe Boundary Redaction (`redact_secret_value`)**: Preserves 4 prefix / 4 suffix characters for strings $\ge 12$ chars with `****` masking and full multi-byte Unicode boundary handling.
- **Invariant Validation (`validate_secret_report`)**: Enforces arithmetic consistency across severity totals and array lengths.
- **Unit & Baseline Testing**: Unit test coverage in `secrets::tests` passing 5/5, and standalone test suite runner `tools/test_secrets_suites.py` validating criteria `K1`.
- **Documentation & Verification**: Updated `docs/README.md` passing all C1..C6 structural invariants.
- **Ledger Pointer**: Advances to **T-00721** (`service & ingest: Research`).

### 2026-08-30 — GRAND MILESTONE: Repository Health CLOSED 100/100 (T-00611..T-00710)

Complete architecture, data modeling, APIs, CLI, MCP tools, automated invariant checkers, security policies, observability diagnostics, documentation, and recovery routines for the entire **Repository Health Diagnostics** component (100/100 tasks complete):
- **Data Model & Schema (T-00611..T-00620)**: `RepoHealthReport`, `RepoHealthCheck`, `HealthStatus`, and `HealthCategory` in `aiosh-core::repo_health`.
- **Service & Ingest Layer (T-00621..T-00630)**: Built `aiosh-core::repo_health_service` supporting git tree hygiene, 16 MiB file bounds scanning, and security governance audits.
- **CLI Subcommand Surface (T-00631..T-00640)**: Delivered `aiosh repo health` and `aiosh repo check` with dual prose and `--json` rendering.
- **MCP Tool Integration (T-00641..T-00650)**: Exposed `aios.repo.health` and `aios.repo.check` with JSON-RPC 2.0 schemas.
- **Configuration & Defaults (T-00651..T-00660)**: Added `RepoHealthConfig` with Twelve-Factor env resolution and 64 KiB configuration security cap.
- **Automated Tests & Invariants (T-00661..T-00670)**: Deployed `tools/test_repo_health_suites.py` asserting criteria `H1..H7`.
- **Security Policy & Governance (T-00671..T-00680)**: Enforced OpenSSF criteria compliance, read-only guarantees, and immutable audit logs.
- **Observability & Diagnostics (T-00681..T-00690)**: Added sub-millisecond `duration_ms` per-check and aggregate telemetry counters.
- **Documentation & Formatter (T-00691..T-00700)**: Implemented `format_repo_health_summary` with 50-item detail clamping (`tools/check_task_docs.py` C1..C6).
- **Recovery & Validation (T-00701..T-00710)**: Implemented `recover_default_repo_health_config`, `reconstruct_repo_health_report`, `validate_repo_health_report`, and `reconcile_repo_health` ensuring zero-downtime diagnostic recovery.
- **Ledger Pointer**: Advances to **T-00711**.

### 2026-08-30 — MILESTONE: Repository Health Documentation CLOSED 10/10 (T-00691..T-00700)

Complete implementation, governance, verification, and hardening for `Repository Health / documentation`:
- **Human-Readable Formatter (`format_repo_health_summary`)**: Renders clean console and log summaries of `RepoHealthReport` with per-check elapsed timings, status indicators (`[Pass]`, `[Warn]`, `[Fail]`, `[Skip]`), and aggregate counters.
- **Defensive Detail Clamping**: Standardized 50-item detail clamping with explicit truncated item notification (`... (<N> additional items truncated)`).
- **Unit & Smoke Testing**: Unit test coverage in `repo_health_service::tests` passing 9/9, along with CLI and MCP smoke suites.
- **Verification & Documentation**: Verified across all test suites (`test_repo_health_suites.py` H1..H7, `check_security_policy.py` S1..S5, `check_task_docs.py` C1..C6, `check_evidence.py` E1..E4).
- **Ledger Pointer**: Advances to **T-00701** (`recovery & validation: Research`).

### 2026-08-29 — MILESTONE: Repository Health Observability CLOSED 10/10 (T-00681..T-00690)

Complete implementation, governance, verification, and hardening for `Repository Health / observability`:
- **Timing & Counter Observability (`RepoHealthReport`, `RepoHealthCheck`)**: Added `duration_ms` timing per individual check and summary level, along with aggregate status counters (`total_checks`, `passed_checks`, `warn_checks`, `failed_checks`, `skipped_checks`).
- **CLI and MCP Diagnostics**: Structured health inspection surfaced via CLI (`aiosh repo health [--json]`) and MCP (`aios.repo.health`).
- **Hardening & Defensive Limits**: Enforced 50-item clamping on untracked git details, ignored heavy build folders (`.git`, `target`, `node_modules`, `.venv`), and safe argument vectorization for subprocesses.
- **Verification & Documentation**: Verified across all test suites (`test_repo_health_suites.py` H1..H7, `check_security_policy.py` S1..S5, `check_task_docs.py` C1..C6, `check_evidence.py` E1..E4).
- **Ledger Pointer**: Advances to **T-00691** (`documentation: Research`).

### 2026-08-29 — GRAND MILESTONE: Evidence & Audit Trail CLOSED 100/100 (T-00511..T-00610)

Complete architecture, data modeling, APIs, CLI, MCP tools, automated invariant checkers, security policies, observability diagnostics, documentation, and recovery routines for the entire **Evidence & Audit Trail** component (100/100 tasks complete):
- **Data Model & Schema (T-00511..T-00520)**: Formally specified `TaskEvidenceManifest`, `EvidenceRecord`, `EvidenceStep`, and SQLite WAL audit records with deterministic SHA-256 attestation.
- **Service & Ingest Layer (T-00521..T-00530)**: Built `aiosh-core::evidence_service` supporting atomic manifest creation, record append, SHA-256 verification, and strict path containment.
- **CLI Subcommand Surface (T-00531..T-00540)**: Delivered `aiosh evidence hash`, `aiosh evidence verify`, and `aiosh evidence scan` with dual prose and `--json` rendering.
- **MCP Tool Integration (T-00541..T-00550)**: Exposed `aios.evidence.hash`, `aios.evidence.verify`, and `aios.evidence.scan` with full JSON-RPC 2.0 schemas.
- **Configuration & Defaults (T-00551..T-00560)**: Added `EvidenceConfig` (`config/evidence.config.json`) with environment variable overrides and a 64 KiB configuration security cap.
- **Automated Tests & Invariant Checkers (T-00561..T-00570)**: Deployed `tools/check_evidence.py` asserting criteria `E1` (directory health), `E2` (ledger consistency), `E3` (file bounds & UTF-8), and `E4` (deterministic SHA-256).
- **Security Policy & PEP (T-00571..T-00580)**: Enforced PEP token gating on mutating actions, fail-closed denial policies, and audit trail tamper resistance (`tools/check_security_policy.py` criteria `S1`..`S5`).
- **Observability & Diagnostics (T-00581..T-00590)**: Added `EvidenceTelemetry` and `collect_evidence_telemetry` with 512-byte outcome string clamping (`clamp_str`).
- **Documentation & Formatter (T-00591..T-00600)**: Implemented `format_evidence_summary`, updated `docs/README.md` passing all doc invariants (`tools/check_task_docs.py` `C1`..`C6`).
- **Recovery & Validation (T-00601..T-00610)**: Implemented `recover_default_evidence_config`, `reconstruct_evidence_manifest`, `scan_evidence_directory`, and `reconcile_evidence_manifest` ensuring zero-downtime recovery of task evidence catalogs.
- **Ledger Pointer**: Advances to **T-00611**.

### 2026-08-29 — MILESTONE: Evidence & Audit Trail Observability CLOSED 10/10 (T-00581..T-00590)

Complete implementation, governance, verification, and hardening for `Evidence & Audit Trail / observability`:
- **Observability Data Model (`EvidenceTelemetry`)**: Standardized aggregate metrics schema (`total_records`, `valid_records`, `missing_files_count`, `hash_mismatches_count`, `is_healthy`) derived deterministically via `collect_evidence_telemetry()`.
- **Diagnostic Invariants & Clamping**: Structured audit trail event emission with 512-byte outcome string clamping (`clamp_str`) protecting SQLite WAL from buffer flooding.
- **Unit Testing**: Comprehensive unit tests covering healthy reports, degraded reports, empty boundary states, all-missing states, and JSON serialization roundtrips (`test_collect_evidence_telemetry`).
- **Cross-Substrate Integration & Verification**: Validated full integration across CLI (`aiosh evidence verify --json`), MCP (`aios.evidence.verify`), and Rust integration test harnesses (`test_evidence_e2e.rs`).
- **Documentation & Verification**: Integrated observability documentation into `docs/README.md` passing all structural doc invariants (`tools/check_task_docs.py` C1..C6).
- **Ledger Pointer**: Advances to T-00591 (`documentation: Research`).

### 2026-08-29 — MILESTONE: Evidence & Audit Trail Security Policy CLOSED 10/10 (T-00571..T-00580)

Complete implementation, governance, verification, and hardening for `Evidence & Audit Trail / security policy`:
- **Security Policy Invariants (`SECURITY.md`)**: Formally classified evidence tampering, checksum forgery, and out-of-bounds artifact traversal under reportable vulnerability definitions, verified in CI via `tools/check_security_policy.py` (criteria S1..S5).
- **PEP Enforcement & Authorization (`evidence_service.rs` / `pep.rs`)**: Gated all mutating actions (`aios.evidence.record`, `evidence.record`, `aios.evidence.set`, `evidence.set`) behind verified PEP grant tokens with fail-closed default, while permitting unauthenticated read-only operations (`hash`, `scan`, `verify`).
- **Audit Ring Refusals (ADR-0035 §F-2)**: Structured logging of policy denials appending honest `outcome="refused"` rows to SQLite WAL.
- **Unit & Integration Testing**: Unit test coverage in `evidence_service::tests::test_check_evidence_policy_enforcement` passing with zero regressions across CLI and MCP smoke suites.
- **Documentation & Verification**: Integrated security policy documentation into `docs/README.md` passing all structural doc invariants (`tools/check_task_docs.py` C1..C6).
- **Ledger Pointer**: Advances to T-00581 (`observability: Research`).

### 2026-08-29 — MILESTONE: Evidence & Audit Trail Automated Tests CLOSED 10/10 (T-00561..T-00570)

Complete implementation, governance, verification, and hardening for `Evidence & Audit Trail / automated tests`:
- **Evidence Verification Checker (`tools/check_evidence.py`)**: Asserts criteria `E1` (directory health), `E2` (ledger consistency across sampled completed tasks), `E3` (16 MiB size bounds & valid UTF-8), and `E4` (deterministic SHA-256 calculation).
- **Behavioral Unit Test Suite (`tools/test_check_evidence.py`)**: 15 test cases (U01..U14 + S01) testing positive, negative, boundary, and blindness sensitivity in temporary isolated sandboxes.
- **Cross-Substrate Tests & CI Integration (`tools/ci_suites.py`)**: Registered `evidence_cli_smoke`, `evidence_mcp_smoke`, `evidence_checker`, and `evidence_unit` into the canonical CI runner registry, verified by `tools/test_ci_suites.py` (W1..W7).
- **Rust End-to-End Suite (`test_evidence_e2e.rs`)**: 10-step lifecycle manifest verification, tampering detection, missing file reporting, and query helpers.
- **Documentation & Verification**: Operator manuals and execution examples integrated in `docs/README.md` passing all structural doc invariants (`tools/check_task_docs.py` C1..C6).
- **Ledger Pointer**: Advances to T-00571 (`security policy: Research`).

### 2026-08-28 — MILESTONE: Dependency & Toolchain Pinning Epic CLOSED 90/90 (T-00311..T-00400)

Complete implementation, governance, verification, and hardening for `Dependency & Toolchain Pinning`:
- **Core Manifest & Data Model (T-00311..T-00320)**: `ToolchainManifest` supporting `rust_version`, `python_version`, `node_version`, and `enforce_hashes` with provenance tracing (`to_json_with_sources`).
- **MCP Server Surface (T-00321..T-00330)**: `aios.toolchain.config.get` and `aios.toolchain.check` tools with typed JSON-RPC handlers.
- **CLI Surface (T-00331..T-00340)**: `aiosh toolchain show` and `aiosh toolchain check [--config <path>]` commands.
- **Configuration & Overrides (T-00341..T-00350)**: Multi-source resolution (`$AIOSH_TOOLCHAIN_CONFIG`, `config/toolchain.json`, defaults) bounded by 64KB file caps.
- **Physical Enforcement (T-00351..T-00360)**: Native Rust version probing (`rustc -V`, `python3 -V`, `node -v`) with 15s execution timeouts and child process reap.
- **Automated Tests (T-00361..T-00370)**: Standalone smoke suites (`test_toolchain_cli_smoke.py`, `test_toolchain_mcp_smoke.py`) integrated into CI runner (`tools/ci_suites.py`).
- **Security Policy & PEP (T-00371..T-00380)**: PEP token gating for mutating actions (`aios.toolchain.set`), `SECURITY.md` criteria (S1..S5), and audit WAL persistence.
- **Observability & Diagnostics (T-00381..T-00390)**: `ToolchainTelemetry`, 512-byte string output clamping (`clamp_str`), and `aiosh audit tail` diagnostic access.
- **Documentation (T-00391..T-00400)**: Canonical operator and agent reference manual in `docs/README.md` passing all C1..C6 structural invariants (`tools/check_task_docs.py`).
- **Ledger Pointer**: Advances to T-00401.

### 2026-08-23 — MILESTONE: CI Smoke Orchestration data model CLOSED 10/10 (T-00111..T-00120)

`tools/ci_suites.py` (registry: 19 suites, order-is-contract, timeouts)
+ `tools/ci_run.py` (production orchestrator: per-suite wall-clock
timeouts with process-group kill, bounded log tails, atomic
machine-readable run summary at `$AIOSH_CI_RESULTS`). `ci/run_all_smokes.sh`
is now a delegating shim; the registry is the single source. Hardening:
group-kill verified zero survivors; 5 MiB log → 12 B tail output.
Verified: full CI **19/19 PASS** through the new path (180515 ms) + W-suite
W1..W7 (`docs/tasks/evidence/T-00120-verify.md`). Ledger pointer: T-00121.

### 2026-08-23 — MILESTONE: Recovery & validation component CLOSED 10/10 (T-00101..T-00110)

`task validate` shipped on all four surfaces (Rust CLI, Rust MCP,
Python MCP reference, Python reference CLI): read-only integrity report
comparing live `TASK_STATE.json` against deterministic event-log replay —
drift/seq/pointer checks fatal, evidence existence+orphans warning-only;
report-only by design (rebuild stays sole repair). Hardening closed
security finding F-1 (evidence path confinement); full findings payload is
byte-parity across Rust-MCP and Python-MCP (modulo audit_id). Verified:
full CI **19/19 PASS** + cargo 82 tests
(`docs/tasks/evidence/T-00110-verify.md`). Ledger pointer: T-00111.

### 2026-08-22 — MILESTONE: Task Ledger Control epic CLOSED 10/10 (T-00011..T-00100)

Documentation component shipped and verified: `tools/check_task_docs.py`
(six structural doc-invariants C1..C6, capped reads, root-bounded link
containment), U-suite **20/20** incl. a blindness-sensitivity proof,
both suites permanent in CI. Docs: README §"Documentation invariants"
with live-verified example + limitations. Verified: full CI **19/19
PASS** + cargo 79 tests (`docs/tasks/evidence/T-00100-verify.md`).
All ten components now closed: data model, core service, CLI,
MCP/API, configuration, automated tests, security policy,
observability, documentation, recovery & validation ← next: T-00101.

### 2026-08-22 — Observability sub-epic CLOSED (T-00081..T-00090)

`aios.task {action:"metrics"}` / `aiosh task metrics` shipped and
verified: stable additive-only snapshot `{tasks, audit, config}`,
counts-only disclosure, grant-free read-only, one honest audit row per
call. Tests-first caught two real defects pre-review (wire accepted
task_id on metrics; CLI silently ignored stray operands) — both fixed
and pinned by the new permanent `metrics_smoke` suite (O1–O8).
Discoverability added to the published inputSchema enum on both
substrates; O(1) COUNT(*) hardening; SPEC §8.6 operator docs.
Verified: cargo 79 tests + **CI 17/17 PASS**
(`docs/tasks/evidence/T-00090-verify.md`). Ledger pointer: T-00091.

### 2026-08-22 — Security policy sub-epic CLOSED (T-00071..T-00080)

Root `SECURITY.md` shipped (OpenSSF criteria met; owner-provided
advisory channel; scope from six component reviews; 7d/90d CVD;
rule-pack governance) + permanent `security_policy` CI suite. Review:
no fabrications/secrets; links verified. **CI 16/16 PASS**
(`docs/tasks/evidence/T-00080-verify.md`). Ledger pointer: T-00081.

### 2026-08-22 — Automated tests sub-epic CLOSED (T-00061..T-00070)

New cross-surface matrix suite (`test_ledger_matrix_smoke.py`, M1–M8)
pins what per-surface tests cannot: one-grant-both-servers,
narrow-grant rejection, concurrent-writer lock-busy (bounded), config
propagation, grant expiry fail-closed, block/unblock. Wired into CI →
**15/15 suites PASS**. Suites hardened (subprocess timeouts,
holder kill-safety); suites themselves security-reviewed (no leaks/no
bypass). Design fact encoded: `rebuild` is lock-free by design.
Ledger pointer: T-00071.

### 2026-08-22 — Configuration sub-epic CLOSED (T-00051..T-00060)

Ledger knobs are now operator-configurable via six `AIOSH_LEDGER_*`
env vars (Twelve-Factor-aligned; defaults == shipped constants; loud
named errors; floors + 86400s lock ceiling; python parity). Exposed by
`aiosh task config`; deliberately NOT agent-exposable via MCP (D5).
Security-reviewed (no open bypass); documented SPEC §8.3. Verified:
79 cargo tests + all wire suites + **CI 14/14 PASS**
(`docs/tasks/evidence/T-00060-verify.md`). Ledger pointer: T-00061.

### 2026-08-22 — MCP/API surface sub-epic CLOSED (T-00041..T-00050)

The Python reference server now mirrors the Rust `aios.task` tool
(`aios_task`: 7 actions, one grant valid across BOTH substrates).
P-suite caught a real gating hole pre-review (`rebuild` mis-classified
read-only) — fixed and permanently pinned. Hardening: module caching,
audited loader failures, bool-id rejection. Verified: 77 cargo tests +
U/W/C/P suites + **CI 13/13 PASS**
(`docs/tasks/evidence/T-00050-verify.md`). SPEC §7 L5 RESOLVED, §8.2
added. Ledger pointer: T-00051.

### 2026-08-22 — CLI surface sub-epic CLOSED (T-00031..T-00040)

`aiosh task` unified onto `task_service::TaskCall` (one validation
source with MCP): strict grammar (u64≥1, non-empty note/reason,
4096/16 caps, dash-value rejection, `--` delimiter), per-subcommand
help; evidence-item cap added to core; **non-UTF-8 argv panic
eliminated** (lossy + audited). Security-reviewed (no open bypass);
documented in SPEC §8.1. Verified: 77 cargo tests, U1..U16, W1..W8,
C1..C9, **CI 12/12 PASS** (`docs/tasks/evidence/T-00040-verify.md`).
Ledger pointer: T-00041 (configuration component begins).

### 2026-08-22 — Core service sub-epic CLOSED (T-00021..T-00030)

The agent-facing ledger surface shipped end-to-end: `aios.task` MCP
tool behind classifier→PEP→audit (read-only status/check; grant-gated
mutations), D3 resolver repair, D4 rebuild replay in both substrates,
bounded lock wait, 1 MiB transport cap. Security-reviewed with no open
bypass; documented in `docs/SPEC-TASK-LEDGER.md` §7–§9; verified with
64 cargo tests + U1..U16 + W1..W8 + **CI 11/11 PASS**
(`docs/tasks/evidence/T-00030-verify.md`). Ledger pointer: T-00031
(CLI-surface sub-epic begins).

### 2026-08-22 — Task Ledger Control epic CLOSED (T-00011..T-00020)

The 10-task ledger-control epic is verified complete: data model
researched, specified, implemented in Rust (`aiosh-core/src/ledger.rs`),
wired as `aiosh task …`, audited, security-reviewed, hardened,
documented (`docs/SPEC-TASK-LEDGER.md`), and verified — full baseline
10/10 PASS with captured evidence
(`docs/tasks/evidence/T-00020-verify.md`). Ledger pointer: T-00021.
Known limitations L1–L5 recorded in the spec §7 as decisions-needed
(Rust default path resolution; rebuild-vs-skip pointer rewind; flock is
single-host only; evidence attested not validated; parity smoke covers
done+block flows).

### 2026-08-21 — FULL RUST REWRITE (user directive, SHIPPED)

The shipping stack is now **Rust** (`code/aiosh-rust/`), replacing the
TypeScript CLI + Python MCP server as the ship path. All Sprint 0-3
capabilities were ported and verified:
- **aiosh-core** — canonical JSON/sha256, audit ring (SQLite WAL + hash
  chain), classifier R-01..R-12, PEP grants, retention (rotation + bloom +
  verify --full), pentest wrappers (nmap/nikto/sqlmap/tshark/aircrack-ng),
  Landlock + seccomp sandbox, Ollama/stub agent loop.
- **aiosh-cli** — `aiosh` binary: `status`, `run`, `audit tail/verify/
  rotate/segments/seen`, `grant create/list/revoke`, `pentest`, `classify`,
  `agent`.
- **aiosh-mcp** — stdio JSON-RPC MCP server (initialize / tools/list — 12
  tools / tools/call) with every call routed through the classifier→PEP→
  audit gate.
- **Green:** zero-warning `cargo build`; 45 `cargo test` cases, including a
  port of the Python classifier fixture matrix (SC1..SC10) pinning
  byte-identical behavior with the legacy substrates; end-to-end smoke
  `code/aiosh-rust/ci/rust_smoke.sh` (build + tests + MCP wire contract +
  CLI status) wired into `ci/run_all_smokes.sh` first.
- The legacy TS (`code/aiosh-cli`) and Python (`code/aiosh-mcp`) trees are
  retained as the cross-substrate reference contract, not the ship path.

### Done in Sprint 0 (shipped, pre-Rust)
- MCP server skeleton + FastMCP stdio transport.
- aiosh-cli (TypeScript): `status`, `run`, `agent` (stub), `audit tail/verify`,
  `grant create/list/revoke`.
- Hash-chained append-only SQLite WAL audit ring.
- Cross-substrate canonical-JSON invariant (TS ↔ Python).
- 5-tool MCP manifest: `aios.fs.read`, `aios.process.list`,
  `aios.audit.tail`, `aios.audit.verify`, `aios.pentest.nmap` (stub).

### Done in Sprint 1 (shipped 2026-08-20)
- Real Pillar-A pentest wrapper set — five tools:
  `pentest.nmap`, `pentest.nikto`, `pentest.sqlmap`,
  `pentest.tshark`, `pentest.aircrack-ng`.
- Both surfaces (MCP and CLI) share the audit ring through the same
  canonical-JSON invariant.
- Every pentest tool call writes one chain-extending audit row.
- 5-suite pentest smoke (`tests/test_pentest_smoke.py`) passes:
  S1 no-grant → refused; S2 grant+no-binary → refused-no-binary;
  S3 scope.tools mismatch → refused; S4 scope.paths mismatch → refused;
  S5 chain integrity holds across TS+Python writers.
- CLI bridge `code/aiosh-cli/src/pentest.ts` exposed as
  `aiosh pentest {nmap|nikto|sqlmap|tshark|aircrack-ng} <args> --grant <id>`.
- Cross-substrate canonical-JSON bug fixed (TS now stores args_json in
  canonical form so nested undefined→null placeholders round-trip).

### Done in Sprint 1.5 (shipped 2026-08-20)
- Replaced the key-grep `cFlagsFor()` with a **deterministic rule-pack
  classifier** (`R-01`…`R-12`) in both TS and Python.
- `classify()` returns `{c_flags, rule_ids, evidence, overall_verdict,
  policy_revision}` — every fired rule contributes a stable rule ID,
  confidence, and human-readable evidence the audit row carries
  verbatim.
- `policy_revision` field (`sprint-1.5-rule-pack-v1`) makes classifier
  behavior version-stamped; any rule-pack change requires a bump.
- Cross-language invariant proven: 10/10 SC fixtures produce
  semantically-identical classifications in TS and Python (after
  numeric-format normalization); the 4 module-level lists are
  byte-equal.
- Bug caught and fixed during smoke: TS `equals` predicate was not
  resolving the `$DANGEROUS_BINS` sentinel, causing asymmetric
  `R-05a` firing between the two languages. Would have shipped
  silent refusals-by-default.
- New `aiosh classify <tool> [--target <t>] [--json-args '{...}']`
  CLI surface for user-driven checks.
- Formal spec: `docs/SPEC-CONSTITUTION-CLASSIFIER.md`.
- See `docs/SPRINT-0.md` §9 for full evidence trail.

### Sprint 2 — agent loop (SHIPPED + VERIFIED 2026-08-21)

The agent loop described below is **built and verified green**. The
`task_plan` text claiming "the remaining gap is the agent that calls
them" was stale relative to the tree — the agent already exists.

Shipped in code:
- `code/aiosh-cli/src/agent.ts` — Computer-Use loop
  (Observe → Think → Act → Loop), Ollama-0.22.1 backend with a
deterministic stub fallback, `classify()` preflight per tool call.
- `code/aiosh-mcp/aiosh_mcp/agent_bridge.py` — persistent MCP stdio
  client forwarding `tools/call` to the real `aiosh_mcp.server`.
- `aiosh agent <prompt>` CLI subcommand (Sprint-0 §2 stub now real).
- MCP dispatch gate (`_dispatch.py` + `server.py`) calls `classify()`
  on every tool — the ADR-0035 §D-4 boundary.

Verified 2026-08-21 (all smokes green after installing mcp/fastmcp +
npm deps and fixing a broken `node_modules/.bin/tsc` wrapper):
```
PASS: Sprint 1.5 classifier smoke (SC1..SC10 + cross-language)
PASS: aiosh-mcp smoke (TS↔Python chain, 9 tools)
PASS: aiosh-mcp Sprint 1 pentest smoke
PASS: aiosh run sandbox smoke (fail-open-with-audit)
PASS: aiosh demo smoke (D1 grant+scan · D2 no-grant refusal ·
      D3 classifier-first refusal)
```
Note: `test_demo_smoke.py` D1 reaches "attempted" but the host lacks
the `nmap` binary — the audited `outcome=refused 'nmap binary not on
PATH'` is the correct auditable answer, not a bug.

### Done in Sprint 3 (shipped 2026-08-21)

- **Audit-ring retention policy** (item 1 of the Sprint 3 queue):
  checkpointed segment rotation + per-segment bloom filters,
  implemented identically in both substrates.
  - New `audit_segments` table; rotation archives the oldest live rows
    byte-identically to `$AIOSH_HOME/audit-archive/segment-<id>.jsonl`,
    pins the file sha256, and records `{first/last row id, row_count,
    genesis_prev_hash, head_hash, bloom}`.
  - Rotation is archival, never destruction (P-2/O-4 compliant, RFC 9162
    §4.13 log-retirement pattern); the live chain re-anchors at the
    checkpoint head and the rotation event itself is an `audit.rotate`
    chain row (O-2). Rotation refuses to run on a broken chain.
  - `verify()` is anchor-aware on both substrates; `verify --full`
    replays every archive file (checksum + per-row re-hash + segment
    linkage) before the live walk.
  - `seen(hash)` answers live / maybe (bloom) / archive (exact scan) /
    no — no false negatives.
  - Surfaces: CLI `aiosh audit rotate [--keep N] [--dry-run]`,
    `audit segments`, `audit seen <hash> [--exact]`,
    `audit verify --full`; MCP `aios.audit.rotate` (PEP grant
    required), `aios.audit.segments`, `aios.audit.seen`,
    `aios.audit.verify(full)`.
  - Docs: `docs/research/AIOS-AUDIT-RING-RETENTION-2026-08-21.md`,
    `docs/SPEC-AUDIT-RETENTION.md`, ADR-0036.
  - Verified 2026-08-21: `tests/test_retention_smoke.py` R1–R7 all
    PASS (incl. TS-rotates→Python-verifies cross-substrate proof);
    all Sprint 0/1/1.5/2 smokes remain green.

### Active task (next)
**Sprint 3 — remaining hardening items.** With retention shipped, the
highest-value next steps (see Queued below) are: (2) the **`aiosh demo`
snap test** formalized into the CI suite; and (3) expanding the five
pentest wrappers toward the full Kali / MITRE ATT&CK v19 taxonomy.

### Queued (Sprint 2)
- **Sprint 3 (SHIPPED 2026-08-26): CI Smoke Orchestration documentation (T-00191..T-00200)**.
  - Formally documented the CI Smoke Orchestration architecture, CLI surface, and configuration parameters, completely wrapping up Phase 0 of the master ledger matrix!
- **Sprint 3 (SHIPPED 2026-08-26): CI Smoke Orchestration observability (T-00181..T-00190)**.
  - Standardized CI health metrics via iosh ci metrics action, completing the Phase 0 integration matrix.
- **Sprint 3 (SHIPPED 2026-08-25): CI Smoke Orchestration security policy (T-00171..T-00180)**.
  - Documented CI orchestrator vulnerability boundaries and updated the repository knowledge index.
- **Sprint 3 (SHIPPED 2026-08-25): CI Smoke Orchestration automated tests (T-00161..T-00170)**.
  - Brought the legacy ci_run.py orchestrator under automated test coverage.
- **Sprint 3 (SHIPPED 2026-08-25): CI Smoke Orchestration configuration (T-00151..T-00160)**.
  - Implemented Twelve-Factor environment configurations for CI orchestration bounds and file paths.
- **Sprint 3 (SHIPPED 2026-08-25): CI Smoke Orchestration MCP/API surface (T-00141..T-00150)**.
  - Integrated ios.ci into the Rust MCP server routing table.
- **Sprint 3 (SHIPPED 2026-08-25): CI Smoke Orchestration CLI surface (T-00131..T-00140)**.
  - Formally verified the CLI surface integration (iosh ci) implemented preemptively during T-00128.
- **Sprint 3 (SHIPPED 2026-08-25): CI Smoke Orchestration core service (T-00121..T-00130)**.
  - Native Rust implementation of iosh ci check, strict JSON artifact validation, 1MB file bounds, and honest audit row emission.
- **Sprint 2 (SHIPPED + verified 2026-08-21):** Ollama-0.22.1 /
  Anthropic-Computer-Use agent loop over MCP, gated by the Sprint-1.5
  classifier. ADR-0035 §D-2 (MCP tools) was already wired; §D-4
  (classifier gate) is enforced both as an agent-loop preflight
  (`agent.ts`) and at the MCP dispatch boundary (`_dispatch.py`).
- `aiosh demo` end-to-end scripted engagement (snap test).
- **Landlock + seccomp-bpf wrapper around `aiosh run`** —
  shipped in §11 (sandbox.py + cli.ts wiring + 3-scenario smoke).
  Sprint-2 gap closed; remaining env-dependent work is hardening
  the host kernel (Landlock ≥ 5.13 + accepting new seccomp filters),
  not the sandbox code.
- **Research-note tying the shipped rule-pack classifier to the
  neuron / Dynamic Neural Topology substrate:** shipped as
  `docs/research/AIOS-CLASSIFIER-PRIMITIVE-AND-NEURAL-SUBSTRATE-2026-08-20.md`
  (8 sections, 14 sub-headings). The classifier is *deliberately
  separate* from the cognition engine — see the note's
  three-way split: deterministic safety boundary / pluggable agent
  / preserved-but-unshipped neuron substrate.
- **Audit-ring retention policy (rotation / bloom filter)** — SHIPPED
  2026-08-21 in Sprint 3 item 1. See `### Done in Sprint 3` below.
- Expand pentest set to the full Kali/Parrot tool taxonomy across
  MITRE ATT&CK v19 categories.
- Rule-pack expansion beyond `R-12` as new tools / new attack
  categories land (version-stamped via `policy_revision`).

### Research done (2026-08-21)

- **Four open research gaps closed** in
  `docs/research/AIOS-RESEARCH-GAPS-2026-08-21.md` (all anchors fetched
  live 2026-08-21): Kali/MITRE ATT&CK v19.2 taxonomy → 9 proposed new
  wrappers + namespace rule; on-device inference (llama.cpp `ggml-org`,
  OpenAI-compatible `llama serve`, Ollama local/cloud); AI ↔ desktop hook
  (KWin 6 scripting + wlr virtual input + AT-SPI2, semantic-first
  `gui.*` set); prompt-injection defense for MCP *outputs* (R-11 covers
  args only; propose tagged `scan_output_for_pi`). Each carries a
  "Decisions needed" block → becomes ledger tasks per the no-skip law.

## Immediate actions for the next agent session

1. Read `docs/SPRINT-0.md` (Sprint 0 + Sprint 1 sections) — full
   shipped contract. Sprint 3 retention is documented in
   `docs/SPEC-AUDIT-RETENTION.md` + ADR-0036.
2. Read ADR-0035 (S-rank agent architecture) and Pillar-C clauses,
   plus ADR-0036 (audit-ring retention).
3. Pick a task — retention is SHIPPED (2026-08-21, verified green).
   Next queue items: formalize the `aiosh demo` snap test into a CI
   suite, then expand the five pentest wrappers toward the full
   Kali / MITRE ATT&CK v19 taxonomy.
4. Confirm baseline is green before starting (verified 2026-08-21):
   the **Rust** stack is the primary surface —
   `bash code/aiosh-rust/ci/rust_smoke.sh` (build + 45 tests + MCP wire
   contract + CLI status). The legacy suites
   (`python code/aiosh-mcp/tests/test_demo_smoke.py` AND
   `python code/aiosh-mcp/tests/test_smoke.py` AND
   `python code/aiosh-mcp/tests/test_pentest_smoke.py` AND
   `python code/aiosh-mcp/tests/test_retention_smoke.py` AND
   `bash code/aiosh-cli/tests/smoke.sh`) still run to pin the
   cross-substrate invariant.
5. Do not start implementation before research (see
   `mostimportanAIfolder/RESEARCH_EXECUTION_PROTOCOL.md`).

## Constraints

- Do not discard unrelated user changes.
- Do not change kernel code yet; v2 ships on Linux hosts, not the
  microkernel.
- Use repository evidence. ADRs and shipped code (with tests) are
  the source of truth for "what's done".
- Preserve unresolved/deferred tasks explicitly rather than silently
  deleting them.
- Cross-substrate canonical-JSON invariant MUST hold — the Rust
  `canonical()` (sorted keys, no whitespace, floats with `.0`) produces
  byte-identical hash chains with the legacy TS/Python substrates, and
  `code/aiosh-rust/aiosh-core/src/canonical.rs` documents the shared
  contract.

## Errors Encountered (Sprint 0/1)

| Error                                              | Cause                                       | Resolution                                                              |
|---------------------------------------------------|---------------------------------------------|-------------------------------------------------------------------------|
| `read_files` tool rejecting valid string              array | Tool-runtime parameter serialization quirk | Use `cat` via `run_terminal_command` for batch reads                      |
| Chain hash mismatch Sprint 1 row 1                | TS wrote args_json with stripped undefined keys, but canonicalJson hashed with them as null. | TS now writes args_json in canonical form too (`code/aiosh-cli/src/audit.ts`) |
| Sprint 0 cross-process tool-count equality        | Sprint 1 added 4 tools; the equality `actual != expected` broke | Relaxed to subset check: `expected <= actual`                            |
| `outcome: string` not assignable to OutcomeKind | `outcome` was a 3-valued narrow union       | Compute literal `"ok"|"refused"|"error"` and assign                       |
| `pentest.aircrack-ng` audit name with hyphen    | Python identifier can't carry hyphen        | Function named `aios_pentest_aircrack_ng`; audit tool hardcoded literal  |
| `spawned Bash Exit 1` on npx tsc from wrong dir  | shell cwd reset between commands            | `cd /c…and` chains each invocation                                       |

## Current decision

**Active track: Sprint 3 — remaining hardening items. Item 1
(audit-ring retention) SHIPPED 2026-08-21.**

Sprint 1 (pentest wrappers + cross-language audit), Sprint 1.5 (rule-pack
classifier + spec), Sprint 1.5b (Landlock/seccomp sandbox), Sprint 2
(Ollama/Anthropic agent loop over MCP, classifier-gated), and Sprint 3
item 1 (checkpointed segment rotation + bloom filter retention, ADR-0036)
are all shipped and verified green (2026-08-21).

**Next queue items:** (2) formalize `aiosh demo` snap test into CI
suite; (3) expand five pentest wrappers toward full Kali / MITRE
ATT&CK v19 taxonomy.

**Task-DB caveat:** `TASK_DATABASE.json` is a NON-authoritative,
graph-derived reconstruction (`authoritative: false`,
`provenance: graph-derived-recovery`) — its "89/89 COMPLETED" is an
artifact, not a real status. Source of truth for "what's done" is
repository evidence: ADRs + shipped code with green smokes (per
README *How to keep going*). The live v2/Sprint plan is this file.


### 2026-10-08 - MILESTONE: Proof of Restraint SHIPPED (T-02831..T-02892)

Proof of Restraint (ADR-0037, Invariants I-1..I-5) is shipped and maintained by standing rules:
- **Capability**: cryptographically prove a granted capability was left untouched (mint -> anchor -> prove -> verify), no trust in operator logs.
- **Components**: PEP mint/redeem (I-1), signed anchors (I-2), Bloom absence via retention (I-3), zero-DB standalone verifier (I-4), continuous conformance gate in CI (I-5).
- **Surfaces**: `restraint.generate_restraint_proof`, `verifier.verify_restraint_proof`, `python -m aiosh_mcp.verifier <proof.json> --pubkey <hex>`, `python3 tools/test_por_conformance_suites.py` (CI suite `por_conformance`), milestone demo `python3 tools/demo_por.py`.
- **Live demo (T-02892)**: honest proof verifies 7/7 checks; post-anchor tamper (delete row + re-chain) rejected with HEAD_HASH_MISMATCH (docs/tasks/evidence/T-02892-demo.md).
- **Docs**: docs/proof-of-restraint/PLAN.md (status: Shipped - maintained by standing rules), docs/SPEC-RESTRAINT-PROOF-GENERATOR.md, docs/SPEC-RESTRAINT-PROOF-VERIFIER.md, docs/SPEC-RESTRAINT-CONFORMANCE-GATE.md.
