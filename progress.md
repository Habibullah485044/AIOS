# Progress Log

## 2026-09-22 — T-02201..T-02210: Grant Lifecycle Data Model CLOSED (Invariants PEPGRANT1..PEPGRANT6, 10/10 tasks)

**What shipped:**
- Completed Sub-Epic 1 (Grant Lifecycle Data Model, T-02201..T-02210):
  - Invariants `PEPGRANT1..PEPGRANT6`: Finite State Machine (`Requested`, `Active`, `Suspended`, `Revoked`, `Expired`), strict identifier & hygiene validation, delegation & attenuation calculus, temporal & volumetric quota governance, authoritative cascade revocation, atomic JSON persistence (`.tmp.<pid>.<nonce>`).
  - Implemented `PepGrant`, `PepGrantState`, `PepGrantConstraints`, `PepGrantRevocation`, and `PepGrantStore` in `code/aiosh-rust/aiosh-core/src/pep_grant.rs`.
  - Operator CLI surface in `aiosh-cli`: `aiosh pep grant list`, `inspect`, `validate`, `revoke` with recursive `--cascade` support.
  - Agent MCP surface in `aiosh-mcp`: `aios.pep.grant.list`, `inspect`, `validate`, `revoke` registered in tool manifest and routed through `dispatch::recorded_call` with immutable SQLite audit row emission.
  - Standalone unit test suite in `code/aiosh-rust/aiosh-core/tests/test_pep_grant.rs` (10/10 tests PASS).
  - Integration smoke tests in `code/aiosh-cli/tests/test_pep_cli_smoke.py` and `code/aiosh-mcp/tests/test_pep_decision_smoke.py` (100% PASS).
  - Hardening bounds (`MAX_GRANTS_IN_STORE = 5000`, `MAX_GRANT_STORE_SIZE = 10 MiB`, `MAX_DELEGATION_DEPTH_LIMIT = 8`, metadata bounds).
  - Section 15 added to system reference `docs/pep_decision_engine.md`.
- **Milestone: Grant Lifecycle Sub-Epic 1 (Data Model) CLOSED — 10/10 tasks**.
- Next task pointer advances to **T-02211** (`Phase 2 — Security Kernel & PEP Fabric / Grant Lifecycle / core service: Research`).

## 2026-09-22 — T-02191..T-02200: PEP Decision Engine Recovery & Validation CLOSED & Entire PEP Epic FINALIZED (100/100 tasks)

**What shipped:**
- Completed Sub-Epic 10 (PEP Decision Engine Recovery & Validation, T-02191..T-02200):
  - Invariants `PEPRECV1..PEPRECV6`: Comprehensive structural & semantic rule validation, array & map representation parity, deterministic salvage and fail-closed strategies, atomic swap with mode 0600 quarantine.
  - Implemented `PepStoreValidator` and `PepRecoveryManager` in `code/aiosh-rust/aiosh-core/src/pep_recovery.rs`.
  - Operator CLI subcommands in `aiosh-cli`: `aiosh pep validate` and `aiosh pep recover`.
  - Agent MCP tools in `aiosh-mcp`: `aios.pep.validate` and `aios.pep.recover`.
  - Unit tests in `code/aiosh-rust/aiosh-core/tests/test_pep_recovery.rs` (8/8 PASS).
  - Integration smoke tests in `code/aiosh-cli/tests/test_pep_cli_smoke.py` and `code/aiosh-mcp/tests/test_pep_decision_smoke.py` (ALL PASS).
  - Complete security review against threats ABUSE-01..ABUSE-08, hardening with size caps and error envelopes, and Section 14 added to `docs/pep_decision_engine.md`.
- **Milestone: PEP Decision Engine Epic Formally CLOSED (100/100 tasks: T-02101..T-02200)**.
- Next task pointer advances to **T-02201** launching the **Grant Lifecycle Epic** (`Phase 2 — Security Kernel & PEP Fabric / Grant Lifecycle / data model: Research`).

## 2026-09-19 — T-01617..T-01626: Kernel Module Core Service CLOSED & CLI Surface Implemented (10/10 tasks)

**What shipped:**
- Completed Sub-Epic 2 (Kernel Module Management Core Service, T-01617..T-01620):
  - T-01617: Core Service Security Review against threats KS-A1..KS-A5.
  - T-01618: Core Service Hardening (staging files, leak-free rollback, 10 MiB limit).
  - T-01619: Core Service Documentation in `docs/kernel_module_management.md`.
  - T-01620: Sub-Epic 2 milestone closure verification.
- Executed Sub-Epic 3 (Kernel Module Management CLI Surface, T-01621..T-01626):
  - T-01621: CLI Surface Research (subcommand design, argument parsing, error envelopes).
  - T-01622: CLI Surface Specification (formal syntax, exit codes, invariants KC1..KC5).
  - T-01623: CLI Surface Scaffold (command routing in `aiosh-cli/src/main.rs`).
  - T-01624: CLI Surface Implementation (`cmd_kernel_module` supporting `list`, `show`, `blacklist`, `unblacklist`, `options`, `autoload`, `unautoload`, `preset`, `export`).
  - T-01625: CLI Surface Unit Test (`test_cmd_kernel_module_flow` in `main.rs`, 100% pass rate).
  - T-01626: CLI Surface Integration (`code/aiosh-cli/tests/test_kernel_module_cli_smoke.py`, 100% pass rate).
- Conducted comprehensive batch security audit in `docs/tasks/evidence/SECURITY_AUDIT_BATCH_T01617_T01626.md`.

**Verified:**
- `cargo test -p aiosh-cli --bin aiosh test_cmd_kernel_module_flow` (1 passed, 0 failed).
- `python code/aiosh-cli/tests/test_kernel_module_cli_smoke.py` (ALL TESTS PASSED).
- `python -c "import tools.task_ledger as tl; print(tl.validate_state())"` (valid, 1626 completed).
- Next task pointer advances to **T-01627** (`Phase 1 — Linux Base System & Bootable Target / Kernel Module Management / CLI surface: Security Review`).

## 2026-09-19 — T-01607..T-01616: Kernel Module Data Model CLOSED & Core Service Implemented (10/10 tasks)

**What shipped:**
- Completed Sub-Epic 1 (Kernel Module Management Data Model, T-01607..T-01610):
  - T-01607: Security review against threats KM-A1..KM-A5 (command injection, parameter safety, conflict prevention, CIS hardening).
  - T-01608: Hardening against bounded lengths, metacharacter neutralization, and panic-free error handling.
  - T-01609: Authored comprehensive guide `docs/kernel_module_management.md`.
  - T-01610: Sub-Epic 1 milestone closure verification (all invariants KM1..KM5 passing).
- Executed Sub-Epic 2 (Kernel Module Management Core Service, T-01611..T-01616):
  - T-01611: Research into service coordination, store persistence, and procfs/sysfs introspection.
  - T-01612: Formal specification of `KernelModuleStore`, `KernelModuleService`, and invariants KS1..KS5.
  - T-01613: Scaffolding `code/aiosh-rust/aiosh-core/src/kernel_module_service.rs` and crate registration in `lib.rs`.
  - T-01614: Implementation of store mutations, conflict detection, preset application, and procfs fallback.
  - T-01615: In-tree unit testing (6/6 tests passing in `kernel_module_service::tests`).
  - T-01616: External integration testing in `code/aiosh-rust/aiosh-core/tests/test_kernel_module_service.rs` (6/6 passing).
- Conducted comprehensive batch security audit in `docs/tasks/evidence/SECURITY_AUDIT_BATCH_T01607_T01616.md`.

**Verified:**
- `cargo test -p aiosh-core --lib kernel_module_service` (6 passed, 0 failed).
- `cargo test -p aiosh-core --test test_kernel_module_service` (6 passed, 0 failed).
- `python -c "import tools.task_ledger as tl; print(tl.validate_state())"` (valid, 1616 completed).
- Next task pointer advances to **T-01617** (`Phase 1 — Linux Base System & Bootable Target / Kernel Module Management / core service: Security Review`).

## 2026-09-19 — T-01597..T-01606: Filesystem Layout Epic CLOSED & Kernel Module Data Model Initialized (10/10 tasks)

**What shipped:**
- Completed Sub-Epic 10 and Finalized Filesystem Layout Epic (T-01597..T-01600):
  - T-01597: Security review of recovery & validation against threats R-A1..R-A5.
  - T-01598: Hardening of recovery harness (sandbox isolation, leak-free staging, bounded timeouts).
  - T-01599: Documented Sub-Epic 10 in `docs/filesystem_layout.md`.
  - T-01600: Verification & evidence milestone closure for Sub-Epic 10 and entire Filesystem Layout Epic (T-01501..T-01600).
- Executed Sub-Epic 1 (Kernel Module Management / Data Model, T-01601..T-01606):
  - T-01601: Research into sysfs/procfs module representation, modprobe.d directives, and CIS hardening.
  - T-01602: Specification of `ModuleInfo`, `ModprobeRule`, `KernelModuleConfig`, and invariants KM1..KM5.
  - T-01603: Scaffolding `code/aiosh-rust/aiosh-core/src/kernel_module.rs` and crate registration.
  - T-01604: Implementation of complete data model, validation engine, presets, and `/proc/modules` parser.
  - T-01605: Unit test execution (6/6 tests passing in `kernel_module::tests`).
  - T-01606: Integration test suite in `code/aiosh-rust/aiosh-core/tests/test_kernel_module_data_model.rs` (6/6 passing).
- Conducted comprehensive batch security audit in `docs/tasks/evidence/SECURITY_AUDIT_BATCH_T01597_T01606.md`.

**Verified:**
- `cargo test -p aiosh-core --lib kernel_module` (6 passed, 0 failed).
- `cargo test -p aiosh-core --test test_kernel_module_data_model` (6 passed, 0 failed).
- `python tools/test_fs_layout_suites.py` (FL1..FL14 PASS).
- `python -c "import tools.task_ledger as tl; print(tl.validate_state())"` (valid, 1606 completed).
- Next task pointer advances to **T-01607** (`Phase 1 — Linux Base System & Bootable Target / Kernel Module Management / data model: Security Review`).

## 2026-09-19 — T-01587..T-01596: Sub-Epic 9 Documentation Closed & Sub-Epic 10 Recovery & Validation (Criteria FL1..FL14, 10/10 tasks)

**What shipped:**
- Completed Sub-Epic 9 closing tasks:
  - T-01587: Security review of documentation (threat model D-A1..D-A4).
  - T-01588: Documentation hardening (bounded reads, malformed markdown resilience, fd leak protection).
  - T-01589: Documentation documentation in `docs/filesystem_layout.md`.
  - T-01590: Sub-Epic 9 verification and evidence milestone closure.
- Executed Sub-Epic 10 (Filesystem Layout Recovery & Validation):
  - T-01591: Recovery & validation research (store corruption, crash consistency, canonical preset fallbacks).
  - T-01592: Recovery & validation specification (criteria R1..R5 formalized).
  - T-01593: Recovery & validation scaffolding (`code/aiosh-cli/tests/test_fs_layout_recovery_validation.py`).
  - T-01594: Recovery & validation implementation (test suite covering R1..R5).
  - T-01595: Recovery & validation unit test (standalone execution with 100% pass rate).
  - T-01596: Recovery & validation integration (registered criterion **FL14** in `tools/test_fs_layout_suites.py`).
- Integrated criterion **FL14** into aggregate test runner `tools/test_fs_layout_suites.py`.
- Conducted comprehensive batch security audit in `docs/tasks/evidence/SECURITY_AUDIT_BATCH_T01587_T01596.md`.

**Verified:**
- `python tools/test_fs_layout_suites.py` (FL1..FL14 PASS).
- `python -c "import tools.task_ledger as tl; print(tl.validate_state())"` (valid, 1596 completed).
- Next task pointer advances to **T-01597** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / recovery & validation: Security Review`).

## 2026-09-19 — T-01581..T-01590 SHIPPED: Filesystem Layout Documentation CLOSED (Criteria FL1..FL13, 10/10 tasks)

**What shipped:**
- Delivered documentation test suite `code/aiosh-cli/tests/test_fs_layout_documentation.py` (D1..D5):
  - D1: CLI subcommand completeness (`aiosh layout --help` advertises all 10 subcommands).
  - D2: MCP manifest schema parity (`tools/list` matches all 10 tools with `additionalProperties: false`).
  - D3: Evidence link integrity (all 79 task evidence links resolve to valid files on disk).
  - D4: JSON snippet syntactic validity (all 18 JSON snippets parse cleanly).
  - D5: Error code documentation completeness (all 21 error codes documented in §4.12).
- Integrated criterion **FL13** into aggregate test runner `tools/test_fs_layout_suites.py`.
- Documented documentation test criteria, copy-pasteable examples, and limitations in `docs/filesystem_layout.md`.

**Verified:**
- `python tools/test_fs_layout_suites.py` (FL1..FL13 PASS).
- Milestone: **Filesystem Layout / documentation CLOSED — 10/10 tasks** (T-01581..T-01590).
- Next task pointer advances to **T-01591** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / recovery & validation: Research`).

## 2026-09-19 — T-01571..T-01580 SHIPPED: Filesystem Layout Observability CLOSED (Criteria FL1..FL12, 10/10 tasks)

**What shipped:**
- Delivered observability test suite `code/aiosh-cli/tests/test_fs_layout_observability.py` (O1..O5):
  - O1: Telemetry emission completeness (CLI & MCP invocations emit audit rows).
  - O2: Audit correlation & queryability (filter by tool and target via audit tail).
  - O3: Outcome fidelity (ok/success, error, refused correctly logged).
  - O4: State inspection parity (active layout & profile counts observable on CLI & MCP).
  - O5: Destructive mutation flagging (destructive: true reported on partition shrink/delete).
- Integrated criterion **FL12** into aggregate test runner `tools/test_fs_layout_suites.py`.
- Documented observability invariants, invocations, constraints, and limitations in `docs/filesystem_layout.md`.

**Verified:**
- `python tools/test_fs_layout_suites.py` (FL1..FL12 PASS).
- Milestone: **Filesystem Layout / observability CLOSED — 10/10 tasks** (T-01571..T-01580).
- Next task pointer advances to **T-01581** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / documentation: Research`).

## 2026-09-19 — T-01561..T-01570 SHIPPED: Filesystem Layout Security Policy CLOSED (Criteria FL1..FL11, 10/10 tasks)

**What shipped:**
- Delivered security policy test suite `code/aiosh-cli/tests/test_fs_layout_security_policy.py` (P1..P5):
  - P1: Gated mutation without grant -> refused by PEP gate (`gate == "pep"`, store file not written).
  - P2: Gated mutation with wrong tool scope -> refused by PEP gate (`gate == "pep"`).
  - P3: Gated mutation with out-of-scope path -> refused by PEP gate (`scope.paths` / path subject violation).
  - P4: Gated mutation with valid grant & in-scope paths -> allowed (`ok == true`, store written, audit row `outcome="ok"`).
  - P5: Read-only tools (`get`, `list`, `probe`, `diff`, `fstab`) executed without grant -> allowed (`ok == true`).
- Integrated criterion **FL11** into aggregate test runner `tools/test_fs_layout_suites.py`.
- Documented security policy invariants, invocations, constraints, and limitations in `docs/filesystem_layout.md`.

**Verified:**
- `python tools/test_fs_layout_suites.py` (FL1..FL11 PASS).
- Milestone: **Filesystem Layout / security policy CLOSED — 10/10 tasks** (T-01561..T-01570).
- Next task pointer advances to **T-01571** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / observability: Research`).

## 2026-09-19 — T-01551..T-01560 SHIPPED: Filesystem Layout Automated Tests CLOSED (Criteria FL1..FL10, 10/10 tasks)

**What shipped:**
- Delivered end-to-end automated test suite `code/aiosh-cli/tests/test_fs_layout_automated_cases.py` (A1..A8):
  - A1: Full lifecycle state machine (`list` -> `register` -> `set-active` -> `show` -> `diff` -> `probe` -> `remove`).
  - A2: Built-in deletion protection (prevents removal of canonical presets `standard_uefi`, `minimal_container`).
  - A3: Active layout deletion protection (prevents removal of currently active layout).
  - A4: fstab import & 6-field generation roundtrip.
  - A5: Target disk capacity feasibility probing (undersized, minimum, tight capacity warning, generous).
  - A6: Differential analysis with destructive change detection (`destructive: true`).
  - A7: Corrupted store tamper resistance (fail-closed preservation of on-disk files).
  - A8: SQLite WAL audit trail verification (ADR-0035 hash chaining).
- Integrated criterion **FL10** into aggregate test runner `tools/test_fs_layout_suites.py`.
- Documented full automated test suite, execution examples, and limitations in `docs/filesystem_layout.md`.

**Verified:**
- `python tools/test_fs_layout_suites.py` (FL1..FL10 PASS).
- `cargo test -p aiosh-core -p aiosh-cli -p aiosh-mcp` (655 passed, 0 failed).
- Milestone: **Filesystem Layout / automated tests CLOSED — 10/10 tasks** (T-01551..T-01560).
- Next task pointer advances to **T-01561** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / security policy: Research`).

## 2026-09-19 — T-01541..T-01550 SHIPPED: Filesystem Layout Configuration CLOSED (Criteria FL1..FL9, 10/10 tasks)


**What shipped:**
- Completed the configuration specification, validation engine, and store parsing for Filesystem Layout (`aiosh_core::fs_layout` and `aiosh_core::fs_layout_service`):
  - Invariants FL1..FL6: FL6 enforces at least one mount marked `required == true`.
  - Strict deserialization: `deny_unknown_fields` across all layout specifications and persisted `FilesystemLayoutStore`.
  - Directory permission mode bounds: octal mask `1..=0o7777` (`mode: 0` rejected).
  - CIS benchmark security options: `/tmp` and `/dev/shm` mounts require `nodev`, `nosuid`, and `noexec`.
  - UsrMerge symlink confinement: `symlink_target` must be a relative path rooted at `usr` without `.` or `..` traversals.
  - Metadata hygiene: `created_at` must be RFC 3339 UTC ending in `Z`; fstab `dump` frequency must be `0` or `1`.
- Delivered dedicated test suite `code/aiosh-cli/tests/test_fs_layout_config_validation.py` (U1..U12) and parity test case C9 in `test_fs_layout_mcp_contract.py`.
- Integrated FL9 into aggregate test runner `tools/test_fs_layout_suites.py`.
- Documented full configuration surface, copy-pasteable examples, and honest limitations in `docs/filesystem_layout.md`.

**Verified:**
- `python tools/test_fs_layout_suites.py` (FL1..FL9 PASS).
- `cargo test -p aiosh-core -p aiosh-cli -p aiosh-mcp` (655 passed, 0 failed).
- Milestone: **Filesystem Layout / configuration CLOSED — 10/10 tasks** (T-01541..T-01550).
- Next task pointer advances to **T-01551** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / automated tests: Research`).

## 2026-09-17 — T-01521..T-01530 SHIPPED: Filesystem Layout CLI Surface CLOSED (Criteria FL1..FL7, 10/10 tasks)


**What shipped:**
- Completed the operator CLI surface for Filesystem Layout in `code/aiosh-rust/aiosh-cli/src/main.rs` (`cmd_fs_layout` and helpers):
  - Read subcommands: `list`, `show`, `validate`/`check`, `probe --bytes`, `diff`, `fstab`.
  - Mutation subcommands: `register`, `set-active`, `remove`, `import-fstab` — the four commands that make the layout store operator-editable.
  - Documented selection precedence (positional `ID` > `--standard` > `--container` > `--spec` > active layout) and wired `--standard`, which `--help` had advertised but the resolver ignored.
  - Uniform `{code, data, error}` envelope, exit codes 0/1/2, and one hash-chained `audit.db` row per invocation.
  - Hardened inputs: regular-file requirement for `--spec`/`--fstab`/`--store`, stream-enforced 10 MiB caps, `O_CREAT|O_EXCL` staged files with bounded retries, fsync-then-rename atomic persistence preserving the staged file on rename failure.
- Delivered the CLI test suites `test_fs_layout_cli_smoke.py`, `test_fs_layout_audit_security.py`, and `test_fs_layout_hardening.py`, all registered in `tools/test_fs_layout_suites.py` as `FL3`, `FL4`, and `FL7`.
- Documented the full surface in `docs/filesystem_layout.md` (§4 subcommands + verified walkthrough + exit/error-code contract, §6 eleven honest limitations) and indexed it in `docs/README.md` §8.14.

**Verified:**
- `python tools/test_fs_layout_suites.py` (FL1..FL7 PASS).
- `cargo test -p aiosh-core` (30 targets, 582 passed, 0 failed).
- `cargo test -p aiosh-cli` (24 passed, 0 failed) and `cargo test -p aiosh-mcp` (12 passed, 0 failed).
- `python tools/test_session_suites.py` (SB1..SB9 PASS) and `python tools/test_session_doc.py` (D1..D6 PASS).
- `python code/aiosh-mcp/tests/test_session_mcp_smoke.py` (8/8 PASS) and `python code/aiosh-cli/tests/test_service_cli_smoke.py` (PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS) and `python tools/check_evidence.py` (E1..E4 PASS).
- Milestone: **Filesystem Layout / CLI surface CLOSED — 10/10 tasks** (T-01521..T-01530).
- Next task pointer advances to **T-01531** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / MCP/API surface: Research`).

## 2026-09-16 — T-01511..T-01520 SHIPPED: Filesystem Layout Core Service CLOSED (Invariants CS1..CS5, 10/10 tasks)

**What shipped:**
- Delivered Filesystem Layout Core Service in `code/aiosh-rust/aiosh-core/src/fs_layout_service.rs`:
  - `FilesystemLayoutStore`: profile registry pre-seeded with canonical UEFI and container layouts, tracking `active_layout_id`, protecting built-ins and active layout from deletion.
  - `FilesystemLayoutService`: coordinator exposing `probe_target()`, `diff_layouts()`, `export_fstab()`, `import_fstab_as_layout()`, `save_to_path()`, and `load_from_path()`.
  - Target feasibility probing: asserts minimum capacity requirements and partition allocation sums, warning when free headroom is < 10%.
  - Differential analysis (`LayoutDiff`): detects partition, mount, and directory modifications, automatically flagging destructive changes (`destructive: true`).
  - Safe atomic persistence: `.tmp.<pid>` sibling file writing with atomic rename and symlink overwrite protection.
  - Hardened with 10 MiB file limits, saturating arithmetic, and 128-mount import boundaries.
- Extended operator CLI (`aiosh layout <list|probe|diff>`) in `code/aiosh-rust/aiosh-cli/src/main.rs`.
- Extended agent MCP tools (`aios.fs_layout.list`, `aios.fs_layout.probe`, `aios.fs_layout.diff`) in `code/aiosh-rust/aiosh-mcp/src/main.rs`.
- Dedicated unit test suite `code/aiosh-rust/aiosh-core/tests/test_fs_layout_service.rs` (11/11 tests passing).
- Operational architecture documentation updated in `docs/filesystem_layout.md`.

**Verified:**
- `cargo test -p aiosh-core --test test_fs_layout_service` (11/11 PASS).
- `cargo test -p aiosh-core --test test_fs_layout_data_model` (19/19 PASS).
- `cargo test -p aiosh-cli --bin aiosh test_cmd_fs_layout_flow` (1/1 PASS).
- `cargo test -p aiosh-mcp --bin aiosh-mcp test_mcp_fs_layout_tools` (1/1 PASS).
- `python tools/test_session_suites.py` (SB1..SB9 PASS).
- `python tools/test_session_doc.py` (D1..D6 PASS).
- `python code/aiosh-mcp/tests/test_session_mcp_smoke.py` (8/8 PASS).
- Milestone: **Filesystem Layout / core service CLOSED — 10/10 tasks** (T-01511..T-01520).
- Next task pointer advances to **T-01521** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / CLI surface: Research`).

## 2026-09-16 — T-01501..T-01510 SHIPPED: Filesystem Layout Data Model CLOSED (Invariants FL1..FL5, 10/10 tasks)

**What shipped:**
- Delivered Filesystem Layout data model and validation engine in `code/aiosh-rust/aiosh-core/src/fs_layout.rs`:
  - Enforces invariants `FL1..FL5` (single root pass=1, path hygiene without `..`, parent-before-child mount topology, CIS security options `nodev,nosuid` on `/tmp` and `/dev/shm`, partition bounds $\le 128$ and ESP $\ge 100$ MiB formatted as `vfat`).
  - Standard reference presets: `standard_uefi()` (64 GiB target with ESP, root, swap, and CIS mounts) and `minimal_container()`.
  - Lossless `/etc/fstab` serialization (`generate_fstab`, `to_fstab_line`) and parsing (`parse_fstab_line`).
- Operator CLI surface (`aiosh layout <show|validate|fstab|check>`) in `code/aiosh-rust/aiosh-cli/src/main.rs` with structured JSON envelopes, file size bounds (10 MiB limit), and SQLite WAL audit logging.
- Autonomous agent MCP surface (`aios.fs_layout.get`, `aios.fs_layout.validate`, `aios.fs_layout.fstab`) in `code/aiosh-rust/aiosh-mcp/src/main.rs` with recorded dispatch.
- Standalone unit test suite `code/aiosh-rust/aiosh-core/tests/test_fs_layout_data_model.rs` (19/19 tests passing).
- Subsystem documentation and operational guide in `docs/filesystem_layout.md`.

**Verified:**
- `cargo test -p aiosh-core --test test_fs_layout_data_model` (19/19 PASS).
- `cargo test -p aiosh-cli --bin aiosh test_cmd_fs_layout_flow` (1/1 PASS).
- `cargo test -p aiosh-mcp --bin aiosh-mcp test_mcp_fs_layout_tools` (1/1 PASS).
- `python tools/test_session_suites.py` (SB1..SB9 PASS).
- `python tools/test_session_doc.py` (D1..D6 PASS).
- `python code/aiosh-mcp/tests/test_session_mcp_smoke.py` (8/8 PASS).
- Milestone: **Filesystem Layout / data model CLOSED — 10/10 tasks** (T-01501..T-01510).
- Next task pointer advances to **T-01511** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / core service: Research`).

## 2026-09-16 — T-01491..T-01500 SHIPPED: User Session Bootstrap Recovery & Validation CLOSED (Criteria SSR1..SSR5, 10/10 tasks) — USER SESSION BOOTSTRAP EPIC COMPLETE (100/100, TASK 1500 ACHIEVED!)

**What shipped:**
- Delivered recovery and validation subsystem for User Session Bootstrap in `code/aiosh-rust/aiosh-core/src/session_recovery.rs`:
  - Deep store validation: `validate_session_store` enforcing mathematical invariants `SSR1..SSR3`, capacity boundaries, and process/seat consistency (`SSR5`).
  - Automated non-destructive self-healing: `recover_session_store_with_backup` and `load_or_recover` creating timestamped quarantine backups (`.bak.<timestamp>`) with POSIX `0600` permissions and reconstituted canonical stores.
- Operator CLI surface (`aiosh session check [--fix] [--store <path>] [--json]` and `aiosh session recover [--store <path>] [--json]`) in `code/aiosh-rust/aiosh-cli/src/main.rs`.
- Autonomous agent MCP surface (`aios.session.check`) in `code/aiosh-rust/aiosh-mcp/src/main.rs` with `auto_recover: bool` support, recorded dispatch, and SQLite WAL audit logging.
- Standalone unit test suite `code/aiosh-rust/aiosh-core/tests/test_session_recovery.rs` (9/9 tests passing).
- Integrated into MCP smoke test `code/aiosh-mcp/tests/test_session_mcp_smoke.py` (`test_session_check_and_recover`) and master session suite `tools/test_session_suites.py` (`SB1..SB9`).
- Subsystem documentation updated in `docs/user_session_bootstrap.md` (§10) and `code/aiosh-mcp/README.md`.

**Verified:**
- `cargo test -p aiosh-core --test test_session_recovery` (9/9 PASS).
- `cargo test -p aiosh-core session_recovery` (5/5 PASS).
- `cargo test -p aiosh-mcp` (11/11 PASS).
- `cargo test -p aiosh-cli` (23/23 PASS).
- `python code/aiosh-mcp/tests/test_session_mcp_smoke.py` (8/8 PASS).
- `python tools/test_session_suites.py` (SB1..SB9 PASS).
- `python tools/test_session_doc.py` (D1..D6 PASS).
- Milestone: **User Session Bootstrap / recovery & validation CLOSED — 10/10 tasks** (T-01491..T-01500).
- Grand Milestone: **User Session Bootstrap (100/100 tasks, T-01401..T-01500) COMPLETE.** Pointer $\to$ **T-01501** (`Phase 1 — Linux Base System & Bootable Target / Filesystem Layout / data model: Research`).

## 2026-09-11 — T-01441..T-01450 SHIPPED: User Session Bootstrap Configuration CLOSED (Criterion SB5, 10/10 tasks)

**What shipped:**
- Delivered configuration subsystem for User Session Bootstrap in `code/aiosh-rust/aiosh-core/src/session_config.rs`:
  - `SessionConfig` struct enforcing invariants `SC1..SC7` (store paths, capacity quotas, idle timeouts, size caps, precedence, bounded reads).
  - Precedence engine: explicit `--config` file > environment variables (`AIOS_SESSION_*`) > built-in defaults.
- Operator CLI surface (`aiosh session config [--config <path>] [--json]`) in `code/aiosh-rust/aiosh-cli/src/main.rs`.
- Autonomous agent MCP surface (`aios.session.config`) in `code/aiosh-rust/aiosh-mcp/src/main.rs` with PEP gating and SQLite WAL audit logging.
- Unit test suite `code/aiosh-rust/aiosh-core/tests/test_session_config.rs` (9 tests passing across SC1..SC7).
- Updated master session runner `tools/test_session_suites.py` with criterion `SB5` (all 5 criteria SB1..SB5 PASS).
- Updated documentation in `code/aiosh-cli/README.md` and `code/aiosh-mcp/README.md`.

**Verified:**
- `python tools/test_session_suites.py` (SB1..SB5 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_session_config` (9/9 PASS).
- `cargo check --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh --bin aiosh-mcp` (PASS).
- Milestone: **User Session Bootstrap / configuration CLOSED — 10/10 tasks** (T-01441..T-01450). Pointer $\to$ **T-01451** (`Phase 1 — Linux Base System & Bootable Target / User Session Bootstrap / automated tests: Research`).

## 2026-09-06 — T-01331..T-01340 SHIPPED: Init & Service Supervision MCP API Surface CLOSED (Criteria SS1..SS4, 10/10 tasks)

**What shipped:**
- Delivered complete autonomous agent Model Context Protocol (MCP) API surface for Init & Service Supervision in `code/aiosh-rust/aiosh-mcp/src/main.rs`:
  - `aios.service.validate`: Validates service name syntax (SS1) or full `ServiceSpec` structures against `SS1..SS5` invariants.
  - `aios.service.list`: Discovers registered services with multi-dimensional filtering (`pattern`, `state`, `startup_mode`, `limit`, `store_path`).
  - `aios.service.get`: Retrieves specification and dynamic runtime status (`state`, `pid`, `health`, `started_at`).
  - `aios.service.action`: Dispatches lifecycle transitions (`start`, `stop`, `restart`, `reload`, `enable`, `disable`, `mask`, `unmask`) with atomic disk persistence.
  - `aios.service.order`: Plans topological startup execution sequences using Kahn's algorithm with cycle detection.
- Governance, PEP & Audit Non-Repudiation:
  - All calls route through `dispatch::recorded_call`.
  - Gated by Policy Enforcement Point capability checks (`grant_id`).
  - Emits tamper-evident audit records to `AuditRing` on every invocation (successes, errors, and rejections).
- Automated Testing:
  - Created standalone test suite `code/aiosh-mcp/tests/test_service_mcp_smoke.py` asserting stdio JSON-RPC 2.0 communication across valid and negative scenarios.
  - In-process Rust unit test suite `tests::test_mcp_service_tools` in `aiosh-mcp`.
  - Updated subsystem test runner `tools/test_service_suites.py` criterion `SS3` description.
- Hardening & Security Controls:
  - Enforced string boundaries (name 128, pattern 256, path 1024), control character rejection, atomic tempfile cleanup, and masking lifecycle rules.
- Documentation:
  - Updated `code/aiosh-mcp/README.md` with full tool descriptors, copy-pasteable JSON-RPC requests, and operational constraints.

**Verified:**
- `python tools/test_service_suites.py` (SS1..SS4 PASS).
- `python code/aiosh-mcp/tests/test_service_mcp_smoke.py` (ALL PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh-mcp test_mcp_service_tools` (PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- Evidence chain: `docs/tasks/evidence/T-01331-mcp-api-surface-research.md` … `T-01340-mcp-api-surface-verification-evidenc.md`.
- Milestone: **Init & Service Supervision / MCP API surface CLOSED — 10/10 tasks** (T-01331..T-01340). Pointer $\to$ **T-01341** (`Phase 1 — Linux Base System & Bootable Target / Init & Service Supervision / configuration: Research`).

## 2026-09-06 — T-01321..T-01330 SHIPPED: Init & Service Supervision CLI Surface CLOSED (Criteria SS1..SS4, 10/10 tasks)

**What shipped:**
- Delivered operator command-line interface for Init & Service Supervision in `code/aiosh-rust/aiosh-cli/src/main.rs`:
  - `cmd_service` routing subcommands:
    - `validate`: Deep validation of service names (SS1) and full specifications (SS1..SS5) with 1 MiB size ceiling.
    - `list`: Multi-parameter service querying with `--pattern`, `--state`, `--mode`, `--limit`, `--store`, and `--json`.
    - `show` & `status`: Service unit inspection rendering human-readable tables or standardized JSON envelopes.
    - `action`: State machine transition dispatcher (`start`, `stop`, `restart`, `reload`, `enable`, `disable`, `mask`, `unmask`).
    - Direct action shortcuts: `start`, `stop`, `restart`, `reload`, `enable`, `disable`, `mask`, `unmask` routing with option preservation.
    - `order`: Topological startup execution planning via Kahn's algorithm with cycle detection.
  - Root CLI help text updated with all service commands and shortcuts.
  - Standardized JSON result envelopes (`{"code": <n>, "data": ..., "error": ...}`).
  - Synchronous audit logging to `audit.log` / SQLite WAL ring via `classify_and_emit` on every execution path.
- Automated Testing & Invariants:
  - Added standalone smoke test suite `code/aiosh-cli/tests/test_service_cli_smoke.py` (7/7 tests passing).
  - Expanded Rust unit test suite `task_cli_tests::test_cmd_service_flow` in `aiosh-cli`.
  - Updated `tools/test_service_suites.py` criterion `SS2` description. All criteria `SS1..SS4` PASS.
- Hardening & Security Controls:
  - 1 MiB payload ceiling on specification files/strings, argument length limits, control character filtering, fail-open audit rows, and atomic tempfile cleanup.
- Documentation:
  - Updated `docs/README.md` under section 8.13 with full CLI command taxonomy, parameter options, and copy-pasteable examples.

**Verified:**
- `python tools/test_service_suites.py` (SS1..SS4 PASS).
- `python code/aiosh-cli/tests/test_service_cli_smoke.py` (ALL PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh test_cmd_service_flow` (PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- Evidence chain: `docs/tasks/evidence/T-01321-cli-surface-research.md` … `T-01330-cli-surface-verification-evidenc.md`.
- Milestone: **Init & Service Supervision / CLI surface CLOSED — 10/10 tasks** (T-01321..T-01330). Pointer $\to$ **T-01331** (`Phase 1 — Linux Base System & Bootable Target / Init & Service Supervision / MCP API surface: Research`).


## 2026-09-06 — T-01311..T-01320 SHIPPED: Init & Service Supervision Core Service CLOSED (Criteria SS1..SS4, 10/10 tasks)

**What shipped:**
- Implemented core service supervisor registry and lifecycle engine in `code/aiosh-rust/aiosh-core/src/service_service.rs`:
  - `ServiceStore`, `ServiceActionReport`, and invariants `CS1..CS5`:
    - `CS1`: Registry uniqueness and schema validation.
    - `CS2`: Finite State Machine lifecycle action engine (`start`, `stop`, `restart`, `reload`, `enable`, `disable`, `mask`, `unmask`).
    - `CS3`: Topological dependency ordering via Kahn's algorithm with cycle detection.
    - `CS4`: Filtered query matrix supporting name patterns, state, startup mode, and limit bounds.
    - `CS5`: Atomic filesystem persistence using PID-isolated tempfiles and 10 MiB payload ceiling.
- Operator CLI surface (`code/aiosh-rust/aiosh-cli/src/main.rs`):
  - `aiosh service list [--pattern <pat>] [--state <state>] [--mode <mode>] [--limit <n>] [--store <path>] [--json]`
  - `aiosh service show <name> [--store <path>] [--json]`
  - `aiosh service action <name> <action> [--store <path>] [--json]`
  - `aiosh service order <name> [--store <path>] [--json]`
  - Emits structured audit events to `audit.log` on every command dispatch.
- MCP tool surface (`code/aiosh-rust/aiosh-mcp/src/main.rs`):
  - `aios.service.list`: Filtered querying over registered services.
  - `aios.service.get`: Inspection of service specifications and runtime status.
  - `aios.service.action`: Lifecycle state transitions and mode administration.
  - `aios.service.order`: Topological startup execution planning.
  - Dispatches via `dispatch::recorded_call` with PEP authorization and hash-chained audit logging.
- Master Test Runner Matrix (`tools/test_service_suites.py`):
  - Added criterion `SS4` (`test_service_service`). All criteria `SS1..SS4` PASS.
- Hardening & Security Controls:
  - 10 MiB payload ceiling and 10,000 entity ceiling on store loading.
  - PID-isolated temporary files with automatic un-link on failure.
  - Kahn's algorithm with in-degree tracking preventing stack overflow and infinite cycles.
  - Fail-open honest audit logging to `audit.log` / SQLite WAL ring.
- Documentation:
  - Documented core service store, CLI/MCP commands, copy-pasteable examples, and constraints in `docs/README.md` under section 8.13.

**Verified:**
- `python tools/test_service_suites.py` (SS1..SS4 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_service_service` (6 unit tests PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh test_cmd_service_flow` (PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh-mcp test_mcp_service_tools` (PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- Evidence chain: `docs/tasks/evidence/T-01311-core-service-research.md` … `T-01320-core-service-verification-evidenc.md`.
- Milestone: **Init & Service Supervision / core service CLOSED — 10/10 tasks** (T-01311..T-01320). Pointer $\to$ **T-01321** (`Phase 1 — Linux Base System & Bootable Target / Init & Service Supervision / CLI surface: Research`).


## 2026-09-06 — T-01301..T-01310 SHIPPED: Init & Service Supervision Data Model CLOSED (Criteria SS1..SS3, 10/10 tasks)

**What shipped:**
- Implemented canonical service data model in `code/aiosh-rust/aiosh-core/src/service.rs`:
  - `ServiceSpec`, `ServiceStatus`, `ServiceHealth`, `ServiceType`, `ServiceState`, `ServiceRestartPolicy`, `ServiceStartupMode`, `ServiceDependencyType`, `ServiceDependency`, `ServiceAction`, and `ServiceQuery`.
  - Invariants `SS1..SS5`: Service naming syntax matching systemd/OpenRC (`SS1`), execution commands and traversal protection (`SS2`), dependency graph hygiene without self-loops (`SS3`), resource timeouts and environment sizing bounds (`SS4`), and lifecycle state consistency (`SS5`).
- Operator CLI surface:
  - `aiosh service validate (--name <name> | --spec <file_or_json>) [--json]` in `aiosh-cli/src/main.rs`.
- MCP tool surface:
  - `aios.service.validate` tool in `aiosh-mcp/src/main.rs` with PEP authorization and SQLite WAL ring audit logging.
- Master Test Runner Matrix (`tools/test_service_suites.py`):
  - Added criteria `SS1` (data model integrity), `SS2` (CLI surface), and `SS3` (MCP surface). All PASS.
- Hardening & Security Controls:
  - 1 MiB payload ceiling on specification files and inline strings, path traversal defense on working directories, POSIX user/group validation, timeout range bounding $[1 \dots 86,400]$ seconds, and fail-open honest audit logging to `audit.db` via `classify_and_emit`.
- Documentation:
  - Documented service data model, invariants SS1..SS5, CLI/MCP usage examples, and constraints in `docs/README.md` under section 8.13.

**Verified:**
- `python tools/test_service_suites.py` (SS1..SS3 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_service_data_model` (6 unit tests PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh test_cmd_service_flow` (PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh-mcp test_mcp_service_tools` (PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- Evidence chain: `docs/tasks/evidence/T-01301-data-model-research.md` … `T-01310-data-model-verification-evidenc.md`.
- Milestone: **Init & Service Supervision / data model CLOSED — 10/10 tasks** (T-01301..T-01310). Pointer $\to$ **T-01311** (`Phase 1 — Linux Base System & Bootable Target / Init & Service Supervision / core service: Research`).


## 2026-09-05 — T-01281..T-01290 SHIPPED: Package Management Documentation CLOSED (Criteria PM1..PM9, 10/10 tasks)

**What shipped:**
- Created dedicated architecture and operational guide: `docs/package_management.md`:
  - 9 core architectural sections covering Executive Overview with Mermaid diagram, Core Data Model (`PM1..PM5`), Store Registry (`CS1..CS5`), Configuration (`PC1..PC6`), Security Policy (`PP1..PP6`), Observability (`PO1..PO6`), Operator CLI reference, Autonomous Agent MCP reference, and Failure Modes / Audit Trail.
- Implemented automated documentation test suite: `tools/test_package_doc.py`:
  - Enforces criteria `D1..D6`: file existence & size bounds ($[1000 \dots 5\text{ MiB}]$), all 9 required section headings, zero rot markers (`TODO`, `FIXME`, `TBD`, etc.), complete invariant token coverage, negative rejection assertions, and zero volatile snapshot counters.
- Master Test Runner Matrix (`tools/test_package_suites.py`):
  - Added criterion `PM9` (`test_package_doc`). All criteria `PM1..PM9` PASS.
- Repository Index Synchronization:
  - Linked guide in `docs/README.md` under section 8.12.

**Verified:**
- `python tools/test_package_suites.py` (PM1..PM9 PASS).
- `python tools/test_package_doc.py` (D1..D6 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- Evidence chain: `docs/tasks/evidence/T-01281-documentation-research.md` … `T-01290-documentation-verification-evidenc.md`.
- Milestone: **Package Management / documentation CLOSED — 10/10 tasks** (T-01281..T-01290). Pointer $\to$ **T-01291** (`Phase 1 — Linux Base System & Bootable Target / Package Management / recovery & validation: Research`).


## 2026-09-05 — T-01271..T-01280 SHIPPED: Package Management Observability CLOSED (Criteria PM1..PM8, 10/10 tasks)

**What shipped:**
- Implemented package observability and telemetry report engine in `code/aiosh-rust/aiosh-core/src/package_observability.rs`:
  - `PackageObservabilityReport`, multi-dimensional breakdowns (`state_breakdown`, `format_breakdown`, `architecture_breakdown`), footprint metrics (`total_installed_size_bytes`, `average_package_size_bytes`), and dependency histogram (`0`, `1-5`, `6-10`, `11+`).
  - Invariants `PO1..PO6`: inventory completeness, multi-dimensional distributions, footprint saturation arithmetic (`u64::saturating_add`), bounded histogram buckets, security policy compliance evaluation, and deterministic read-only JSON serialization.
- Operator CLI surface:
  - `aiosh package stats [--store <path>] [--config <path>] [--json]` in `aiosh-cli/src/main.rs`.
- MCP tool surface:
  - `aios.package.stats` tool in `aiosh-mcp/src/main.rs` with structured responses and SQLite WAL ring audit logging.
- Master Test Runner Matrix (`tools/test_package_suites.py`):
  - Added criterion `PM8` (`test_package_observability`). All criteria `PM1..PM8` PASS.
- Hardening & Security Controls:
  - Path string bounds & control character validation on `generate_from_paths`, oversized path rejection (>1024 characters), explicit error envelopes (`LOAD_STORE_FAILED`, `LOAD_POLICY_FAILED`, `INVALID_ARGUMENT`), and fail-open honest audit logging to `audit.db` via `classify_and_emit`.
- Documentation:
  - Documented telemetry architecture, invariants PO1..PO6, CLI/MCP usage examples, and honest constraints.

**Verified:**
- `python tools/test_package_suites.py` (PM1..PM8 PASS).
- `cargo test -p aiosh-core --test test_package_observability` (7 unit tests PASS).
- `cargo test --bin aiosh test_cmd_package_flow` (PASS).
- `cargo test --bin aiosh-mcp test_mcp_package_tools` (PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- Evidence chain: `docs/tasks/evidence/T-01271-observability-research.md` … `T-01280-observability-verification-evidenc.md`.
- Milestone: **Package Management / observability CLOSED — 10/10 tasks** (T-01271..T-01280). Pointer $\to$ **T-01281** (`Phase 1 — Linux Base System & Bootable Target / Package Management / documentation: Research`).


## 2026-09-04 — T-01261..T-01270 SHIPPED: Package Management Security Policy CLOSED (Criteria PM1..PM7, 10/10 tasks)

**What shipped:**
- Implemented package security policy engine in `code/aiosh-rust/aiosh-core/src/package_policy.rs`:
  - `PackageSecurityPolicy`, `PackagePolicyMode` (`Enforcing`, `Audit`, `Permissive`), `PackagePolicyVerdict`, and `PackagePolicyViolation`.
  - Invariants `PP1..PP6`: configuration bounds, prohibited packages blocking (`telnet`, `rsh`, etc.), mandatory SHA-256 validation, transport security (`https://` or `file://`), architecture/format/size whitelisting, and pre-execution transaction evaluation.
- Operator CLI surface:
  - `aiosh package policy [--config <path>] [--package <name>] [--json]` in `aiosh-cli/src/main.rs`.
- MCP tool surface:
  - `aios.package.policy` tool in `aiosh-mcp/src/main.rs` with structured responses and PEP SQLite audit logging.
- Master Test Runner Matrix (`tools/test_package_suites.py`):
  - Added criterion `PM7` (`test_package_policy`). All criteria `PM1..PM7` PASS.
- Hardening & Security Controls:
  - Path string bounds & control character validation on `from_file`, 64 KiB read stream bounding (`MAX_POLICY_FILE_BYTES`), allowed repository ceiling (256 entries), and fail-closed evaluation rules.
- Documentation:
  - Documented architecture, invariants PP1..PP6, CLI/MCP usage examples, and environment variables.

**Verified:**
- `python tools/test_package_suites.py` (PM1..PM7 PASS).
- `cargo test -p aiosh-core --test test_package_policy` (7 unit tests PASS).
- `cargo test --bin aiosh test_cmd_package_flow` (PASS).
- `cargo test --bin aiosh-mcp test_mcp_package_tools` (PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- Evidence chain: `docs/tasks/evidence/T-01261-security-policy-research.md` … `T-01270-security-policy-verification-evidenc.md`.
- Milestone: **Package Management / security policy CLOSED — 10/10 tasks** (T-01261..T-01270). Pointer $\to$ **T-01271** (`Phase 1 — Linux Base System & Bootable Target / Package Management / observability: Research`).


## 2026-09-04 — T-01251..T-01260 SHIPPED: Package Management Automated Tests CLOSED (Criteria PM1..PM6, 10/10 tasks)

**What shipped:**
- Implemented comprehensive automated integration test suite in `code/aiosh-rust/aiosh-core/tests/test_package_automated.rs` covering criteria `PT1..PT6`:
  - `PT1`: Deterministic plan reproducibility over 50 iterations with SHA-256 hash stability.
  - `PT2`: Multi-step lifecycle state transitions (`Available` $\to$ `Installed` $\to$ `Upgraded` $\to$ `Available`) with size delta arithmetic (`CS4`).
  - `PT3`: Dependency closure failure modes (unsatisfied dependencies, missing packages, joint satisfaction) (`CS3`).
  - `PT4`: Configuration-governed store capacity limits (`PC2`, `PC3`) and disk reload persistence.
  - `PT5`: Anti-tamper detection on delta tampering and clean rollback to pristine state. Dry-run isolation.
  - `PT6`: Negative boundary matrix (empty action lists, >256 action overflow, duplicate registration `CS1`).
- Master Test Runner Matrix (`tools/test_package_suites.py`):
  - Added criterion `PM6` (`test_package_automated`). All criteria `PM1..PM6` PASS.
- Hardening & Security Controls:
  - 120s timeout bounds on runner subprocesses, RAII temporary directory lifecycle management, and fail-fast non-zero exit behavior.
- Documentation:
  - Updated documentation with test runner usage, matrix breakdown, copy-pasteable examples, and honest constraints.

**Verified:**
- `python tools/test_package_suites.py` (PM1..PM6 PASS).
- `cargo test -p aiosh-core --test test_package_automated` (6 tests PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- Evidence chain: `docs/tasks/evidence/T-01251-automated-tests-research.md` … `T-01260-automated-tests-verification-evidenc.md`.
- Milestone: **Package Management / automated tests CLOSED — 10/10 tasks** (T-01251..T-01260). Pointer $\to$ **T-01261** (`Phase 1 — Linux Base System & Bootable Target / Package Management / security policy: Research`).


## 2026-09-04 — T-01241..T-01250 SHIPPED: Package Management Configuration CLOSED (Criteria PM1..PM5, 10/10 tasks)

**What shipped:**
- Implemented hierarchical configuration subsystem in `code/aiosh-rust/aiosh-core/src/package_config.rs`:
  - `PackageConfig`: Struct representing runtime configuration (`store_path`, `max_store_size_bytes`, `max_entity_count`, `allowed_repositories`, `default_format`, `auto_update`).
  - Strict validation against invariants `PC1..PC6`.
  - Deterministic resolution precedence: file config (`--config`) > environment variables (`AIOS_PACKAGE_*`) > hardcoded defaults.
  - Safe bounded file parsing: 64 KiB read cap (`MAX_CONFIG_FILE_BYTES = 65_536`) with bounded stream reading (`take(65_536 + 1)`).
- Operator CLI surface:
  - `aiosh package config [--config <path>] [--json]` supporting human and machine-readable output and error envelopes.
- MCP tool surface:
  - `aios.package.config`: Autonomous agent configuration inspection tool with PEP gating and SQLite audit emission.
- Master Test Runner Matrix (`tools/test_package_suites.py`):
  - Added criterion `PM5` (`test_package_config`).
- Documentation:
  - Updated `docs/README.md` (§8.12) with invariants `PC1..PC6`, copy-pasteable CLI commands, and MCP JSON-RPC examples.

**Verified:**
- `python tools/test_package_suites.py` (PM1..PM5 PASS).
- `cargo test -p aiosh-core --test test_package_config` (7 unit tests PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- Evidence chain: `docs/tasks/evidence/T-01241-configuration-research.md` … `T-01250-configuration-verification-evidenc.md`.
- Milestone: **Package Management / configuration CLOSED — 10/10 tasks** (T-01241..T-01250). Pointer $\to$ **T-01251** (`Phase 1 — Linux Base System & Bootable Target / Package Management / automated tests: Research`).


## 2026-09-04 — T-01231..T-01240 SHIPPED: Package Management MCP/API Surface CLOSED (Criteria PM1..PM4, 10/10 tasks)

**What shipped:**
- Implemented complete autonomous agent MCP tool surface in `code/aiosh-rust/aiosh-mcp/src/main.rs`:
  - `aios.package.validate`: Syntax validation of package names (`PM1`) and deep specification checks (`PM1..PM5`).
  - `aios.package.list`: Enumerate packages with format, state, pattern, and limit filters.
  - `aios.package.get`: Detailed specification lookup for a single package.
  - `aios.package.plan`: Transaction planning with dependency closure validation (`CS2`, `CS3`) and delta calculation (`CS4`).
  - `aios.package.search`: Substring search on names and descriptions with pagination limit [1..10,000].
  - `aios.package.apply`: Transaction execution with dry-run support, state transitions (`CS5`), and atomic persistence.
- Security and hardening defenses:
  - PEP authorization gating and immutable audit row emission via `dispatch::recorded_call` on all 6 tool paths (ADR-0035).
  - Strict input validation: package names <= 128 chars, search patterns <= 256 chars, store paths <= 1,024 chars, action arrays <= 10,000 items, and ASCII control-character rejection.
  - Limit pagination bounds [1..10,000].
  - Standard JSON result envelope `{ "ok": bool, ... }` with zero silent failures.
  - RAII cleanup of temporary files on write errors.
- Master Test Runner Matrix (`tools/test_package_suites.py`):
  - Added criterion `PM4` (`test_mcp_package_tools`).
- Documentation:
  - Updated `docs/README.md` (§8.12) with tool specifications and JSON-RPC copy-pasteable examples.

**Verified:**
- `python tools/test_package_suites.py` (PM1..PM4 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh-mcp test_mcp_package_tools` (28 assertions PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- Evidence chain: `docs/tasks/evidence/T-01231-mcp-api-surface-research.md` … `T-01240-mcp-api-surface-verification-evidenc.md`.
- Milestone: **Package Management / MCP/API surface CLOSED — 10/10 tasks** (T-01231..T-01240). Pointer $\to$ **T-01241** (`Phase 1 — Linux Base System & Bootable Target / Package Management / configuration: Research`).


## 2026-09-04 — T-01221..T-01230 SHIPPED: Package Management CLI Surface CLOSED (Criteria PM1..PM3, 10/10 tasks)

**What shipped:**
- Implemented comprehensive operator CLI surface in `code/aiosh-rust/aiosh-cli/src/main.rs`:
  - `aiosh package validate`: Syntax (PM1) and complete specification deep-audit (PM1..PM5).
  - `aiosh package list`: Enumerate packages with format, state, pattern filters and bounded limit [1..10,000].
  - `aiosh package show`: Inspect package details, dependencies, and sizing with bounds and control-character sanitization.
  - `aiosh package search`: Substring search on package names and descriptions with pattern length caps (<=256) and control-character rejection.
  - `aiosh package plan`: Deterministic transaction planning, dependency closure validation, and size delta calculation.
  - `aiosh package apply`: Transaction execution, state transitions, atomic persistence (`--store <path>`), and ADR-0035 audit emission.
- Hardening and security defenses:
  - 1 MiB payload ceiling on `--actions`, `--plan`, and `--spec` inputs (inline and files).
  - Control-character rejection and length bounding on patterns, package names, and store paths.
  - Standard error result envelopes with explicit machine-readable codes.
  - Complete SQLite `audit.db` logging via `classify_and_emit` on all paths.
- Added criterion `PM3` to `tools/test_package_suites.py`.
- Documented CLI surface in `docs/README.md` (§8.12).

**Verified:**
- `python tools/test_package_suites.py` (PM1..PM3 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh test_cmd_package_flow` (PASS).
- `cargo run --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh -- package list --json` (PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- Evidence chain: `docs/tasks/evidence/T-01221-cli-surface-research.md` … `T-01230-cli-surface-verification-evidenc.md`.
- Milestone: **Package Management / CLI surface CLOSED — 10/10 tasks** (T-01221..T-01230). Pointer $\to$ **T-01231** (`Phase 1 — Linux Base System & Bootable Target / Package Management / MCP/API surface: Research`).


## 2026-09-04 — T-01211..T-01220 SHIPPED: Package Management Core Service CLOSED (Criteria PM1..PM2, 10/10 tasks)
 
**What shipped:**
- Implemented `PackageStore` in `code/aiosh-rust/aiosh-core/src/package_service.rs` supporting Debian, Alpine, Flatpak, and Tarball packages.
- Implemented core invariants `CS1..CS5`:
  - `CS1`: Registry package identifier uniqueness.
  - `CS2`: Deterministic transaction planning with SHA-256 fingerprinting.
  - `CS3`: Dependency closure validation across action batches.
  - `CS4`: Delta arithmetic verification and tamper detection.
  - `CS5`: Safe persistence with atomic rename, `.tmp` RAII cleanup, 10 MiB stream ceiling, and 10,000 package count limit.
- Integrated operator CLI subcommands: `aiosh package list`, `aiosh package show`, `aiosh package plan` with 1 MiB payload limits and structured error envelopes.
- Integrated autonomous agent MCP tools: `aios.package.list`, `aios.package.get`, `aios.package.plan` with PEP capability gating and SQLite WAL audit logging.
- Extended standalone test runner `tools/test_package_suites.py` with criterion `PM2`.
- Created unit test suite in `code/aiosh-rust/aiosh-core/tests/test_package_service.rs` (9 tests passing).
- Documented Package Management core service in `docs/README.md` (Section 8.12).
 
**Verified:**
- `python tools/test_package_suites.py` (PM1..PM2 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_package_service` (9/9 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh test_cmd_package_flow` (PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh-mcp test_mcp_package_tools` (PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- Evidence chain: `docs/tasks/evidence/T-01211-core-service-research.md` … `T-01220-core-service-verification-evidenc.md`.
- Milestone: **Package Management / core service CLOSED — 10/10 tasks** (T-01211..T-01220). Pointer $\to$ **T-01221** (`Phase 1 — Linux Base System & Bootable Target / Package Management / CLI surface: Research`).
 
 
## 2026-09-04 — T-01201..T-01210 SHIPPED: Package Management Data Model CLOSED (Criterion PM1, 10/10 tasks)

**What shipped:**
- Created unified Linux package management data model in `code/aiosh-rust/aiosh-core/src/package.rs` supporting Debian (`deb`), Alpine (`apk`), `flatpak`, and `tarball`.
- Implemented core types: `PackageSpec`, `PackageFormat`, `PackageState`, `PackageDependency`, `PackageAction`, `PackageTransaction`, and `PackageQuery`.
- Implemented and verified validation invariants `PM1..PM5`:
  - `PM1`: Package naming syntax conforming to `^[a-z0-9][a-z0-9+.-]*$`, length `1..=128`.
  - `PM2`: Strict size bounds on version (64), architecture (64), description (4096), dependencies (256), package size (100 GiB), transaction actions (256).
  - `PM3`: Dependency hygiene rejecting self-dependencies and duplicate dependency specifications.
  - `PM4`: Checksum (64-hex SHA-256) and HTTPS repository URL enforcement.
  - `PM5`: State consistency (installed packages require positive installed size).
- Integrated operator CLI subcommand: `aiosh package validate (--name <name> | --spec <file_or_json>) [--json]` with 1 MiB payload ceiling.
- Integrated autonomous agent MCP tool: `aios.package.validate` with PEP authorization gating and SQLite WAL audit logging.
- Created standalone test runner `tools/test_package_suites.py` with criterion `PM1`.
- Created standalone integration test suite in `code/aiosh-rust/aiosh-core/tests/test_package_data_model.rs` (7 tests passing).
- Updated root specification `docs/README.md` (Section 8.12).

**Verified:**
- `python tools/test_package_suites.py` (PM1 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_package_data_model` (7/7 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh test_cmd_package_flow` (PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh-mcp test_mcp_package_tools` (PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- Evidence chain: `docs/tasks/evidence/T-01201-data-model-research.md` … `T-01210-verify.md`.
- Milestone: **Package Management / data model CLOSED — 10/10 tasks** (T-01201..T-01210). Pointer $\to$ **T-01211** (`Phase 1 — Linux Base System & Bootable Target / Package Management / core service: Research`).


## 2026-09-04 — T-01191..T-01200 SHIPPED: Base Image Build Recovery & Validation CLOSED (Criteria B1..B9, FULL EPIC COMPLETE 100/100, TASK 1200 ACHIEVED!)

**What shipped:**
- Created Base Image Build Recovery & Validation subsystem in `code/aiosh-rust/aiosh-core/src/base_image_recovery.rs`.
- Implemented deep manifest and store validation (`validate_manifest`, `validate_store`) and non-destructive corruption recovery (`load_or_recover`).
- Enforced and mathematically verified invariants `RV1..RV4`:
  - `RV1`: `valid_manifests + invalid_manifests == total_manifests`
  - `RV2`: `healthy == (errors.is_empty() && invalid_manifests == 0)`
  - `RV3`: `invalid_manifests > 0 ==> errors.len() >= invalid_manifests`
  - `RV4`: Non-destructive recovery creates `<path>.bak.<timestamp>` before re-seeding with clean defaults.
- Integrated operator CLI subcommand: `aiosh image check [--fix] [--json] [--store <path>]`.
- Integrated autonomous agent MCP tool: `aios.image.check` with optional `store_path` and `auto_recover: bool`.
- Enforced hardening caps (1024 package limit, 100 GiB image size cap, 10 MiB store limit, forensic `.bak` anti-tampering).
- Extended master test runner `tools/test_image_suites.py` with criterion `B9`.
- Created standalone integration test suite in `code/aiosh-rust/aiosh-core/tests/test_base_image_recovery.rs`.
- Updated architectural guide `docs/base_image_build.md` (Sections 7, 8, and 9) and `docs/README.md` (Section 8.11).
- Completed the entire **Base Image Build Epic (T-01101..T-01200 — 100/100 tasks)**!
- Milestone metric: **TASK 1,200 / 10,000 (12.00%) REACHED!**

**Verified:**
- `python tools/test_image_suites.py` (B1..B9 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_base_image_recovery` (5/5 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh test_cmd_image_flow` (PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh-mcp test_mcp_image_tools` (PASS).
- `python tools/test_base_image_doc.py` (D1..D5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- Evidence chain: `docs/tasks/evidence/T-01191-recovery-validation-research.md` … `T-01200-verify.md`.
- Milestone: **Base Image Build Epic CLOSED — 100/100 tasks (T-01101..T-01200)**. Pointer $\to$ **T-01201** (`Phase 1 — Linux Base System & Bootable Target / Package Management / data model: Research`).



**What shipped:**
- Created comprehensive 9-section operational and architectural guide in `docs/base_image_build.md` covering target formats (`raw`, `qcow2`, `iso`), core data models, 4-stage build lifecycle with Mermaid diagram, configuration precedence, security invariants (`P1..P7`), observability invariants (`OB1..OB5`), CLI subcommands, MCP tools, error envelopes, and SQLite WAL audit logging.
- Created automated documentation unit test suite `tools/test_base_image_doc.py` covering criteria `D1..D5`.
- Cross-referenced `docs/base_image_build.md` in `docs/README.md` and synchronized evidence ranges.
- Completed security review, threat modeling, and abuse scenario mitigations.
- Enforced zero-volatility hardening (invariant C6) and verified rot-proof integrity.

**Verified:**
- `python tools/test_base_image_doc.py` (D1..D5 PASS).
- `python tools/test_image_suites.py` (B1..B8 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- Evidence chain: `docs/tasks/evidence/T-01181-documentation-research.md` … `T-01190-verify.md`.
- Milestone: **Base Image Build / documentation CLOSED — 10/10 tasks** (T-01181..T-01190). Pointer $\to$ **T-01191** (`Base Image Build / recovery & validation: Research`).


## 2026-09-04 — T-01171..T-01180 SHIPPED: Base Image Build Observability CLOSED (Criteria B8, 10/10 tasks)

**What shipped:**
- Created `BaseImageObservabilityReport` in `code/aiosh-rust/aiosh-core/src/base_image_observability.rs` aggregating total images, distribution counts, architecture breakdowns, format distributions, policy compliance rates, unique kernel inventories, and total/average storage budgets.
- Implemented and validated mathematical invariants `OB1..OB5` (`validate_observability_report`).
- Integrated CLI subcommand `aiosh image report [--json] [--store <path>]`.
- Integrated MCP tool `aios.image.report`.
- Enforced hardening bounds (max 16 formats, 64 archs, 256 distros, 256 kernels) with control-character / null-byte sanitization.
- Extended standalone test runner `tools/test_image_suites.py` with criterion `B8`.
- Created unit and negative test suite in `code/aiosh-rust/aiosh-core/tests/test_base_image_observability.rs`.
- Updated documentation in `docs/README.md`.

**Verified:**
- `python tools/test_image_suites.py` (B1..B8 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_base_image_observability` (5/5 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh test_cmd_image_flow` (PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh-mcp test_mcp_image_tools` (PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- Evidence chain: `docs/tasks/evidence/T-01171-base-image-observability-research.md` … `T-01180-verify.md`.
- Milestone: **Base Image Build / observability CLOSED — 10/10 tasks** (T-01171..T-01180). Pointer $\to$ **T-01181** (`Base Image Build / documentation: Research`).


## 2026-09-01 — T-01001..T-01010 SHIPPED: Distro Selection & Justification Data Model CLOSED (Phase 1 Inception, Criteria D1, 10/10 tasks)

**What shipped:**
- Created `DistroProfile`, `DistroEvaluation`, `DistroFamily`, `InitSystem`, `ArchTarget`, and `CLibrary` in `code/aiosh-rust/aiosh-core/src/distro.rs`.
- Implemented `validate_distro_profile` enforcing semver kernel parsing, profile ID character whitelisting, and field bounds.
- Implemented `DistroEvaluation::evaluate` with weighted multi-criteria scoring algorithm.
- Created standalone test runner `tools/test_distro_suites.py` with criterion `D1`.
- Created behavioral unit test suite `tools/test_distro_unit.py` (U01..U04).
- Updated documentation in `docs/README.md`.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 2400+ evidence files).
- `python tools/test_distro_suites.py` (D1 PASS).
- `python tools/test_distro_unit.py` (U01..U04 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib distro` (PASS).
- Evidence chain: `docs/tasks/evidence/T-01001-data-model-research.md` … `T-01010-verify.md`.
- Milestone: **Distro Selection & Justification / data model CLOSED — 10/10 tasks** (T-01001..T-01010). Pointer $\to$ **T-01011** (`Distro Selection & Justification / core service: Research`).


## 2026-08-31 — T-00991..T-01000 SHIPPED: Agent Handoff Protocol Documentation CLOSED (Full Epic Complete 100/100, Criteria H1..H8, TASK 1000 ACHIEVED!)

**What shipped:**
- Completed comprehensive documentation across `docs/README.md` covering all 8 criteria of Agent Handoff Protocol:
  - Data Model (`H1`), Core Service Store (`H2`), CLI Surface (`H3`), MCP/API Surface (`H4`), Configuration (`H5`), Automated Tests (`H6`), Security Policy (`H7`), and Observability (`H8`).
- Verified all rot-proof documentation invariants C1..C6 with zero errors.
- Completed the entire **Agent Handoff Protocol Epic (`T-00911..T-01000` — 100/100 tasks)**.
- Reached **1,000 tasks completed (10.00% of master task ledger)**!

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 2350+ evidence files).
- `python tools/test_handoff_suites.py` (H1..H8 PASS).
- `python tools/test_handoff_unit.py` (U01..U17 PASS).
- Evidence chain: `docs/tasks/evidence/T-00991-documentation-research.md` … `T-01000-verify.md`.
- Milestone: **Agent Handoff Protocol Epic CLOSED — 100/100 tasks (T-00911..T-01000)**. Pointer $\to$ **T-01001** (`Phase 0 / Agent Coordination Protocol / data model: Research`).


## 2026-08-31 — T-00981..T-00990 SHIPPED: Agent Handoff Protocol Observability CLOSED (HandoffReport & Metrics, Criteria H1..H8, 10/10 tasks)

**What shipped:**
- Implemented status aggregation and report generation in `code/aiosh-rust/aiosh-core/src/handoff.rs`:
  - `HandoffReport` with `timestamp_utc`, `total_handoffs`, `active_handoffs`, `completed_handoffs`.
  - Invariant validator `validate_handoff_report` asserting total arithmetic integrity.
- Extended standalone test runner `tools/test_handoff_suites.py` with criterion `H8`.
- Updated behavioral unit test suite `tools/test_handoff_unit.py` (U01..U17).
- Updated documentation in `docs/README.md`.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 2300+ evidence files).
- `python tools/test_handoff_suites.py` (H1..H8 PASS).
- `python tools/test_handoff_unit.py` (U01..U17 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib test_handoff_report_validation_and_serde` (PASS).
- Evidence chain: `docs/tasks/evidence/T-00981-observability-research.md` … `T-00990-verify.md`.
- Milestone: **Agent Handoff Protocol / observability CLOSED — 10/10 tasks** (T-00981..T-00990). Pointer $\to$ **T-00991** (`Agent Handoff Protocol / documentation: Research`).


## 2026-08-31 — T-00971..T-00980 SHIPPED: Agent Handoff Protocol Security Policy CLOSED (PEP Matrix, Criteria H1..H7, 10/10 tasks)

**What shipped:**
- Implemented actor authorization validation in `code/aiosh-rust/aiosh-core/src/handoff.rs`:
  - `can_agent_act` and `verify_handoff_authorization` methods.
  - Role-based policy: Receiver agents only for accept/reject/complete, sender agents only for cancel, universal override for operators/admins.
- Updated `HandoffStore` in `code/aiosh-rust/aiosh-core/src/handoff_service.rs` with actor-verified transitions.
- Extended standalone test runner `tools/test_handoff_suites.py` with criterion `H7`.
- Updated behavioral unit test suite `tools/test_handoff_unit.py` (U01..U15).
- Updated documentation in `docs/README.md`.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 2300+ evidence files).
- `python tools/test_handoff_suites.py` (H1..H7 PASS).
- `python tools/test_handoff_unit.py` (U01..U15 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib test_handoff_authorization_matrix` (PASS).
- Evidence chain: `docs/tasks/evidence/T-00971-security-policy-research.md` … `T-00980-verify.md`.
- Milestone: **Agent Handoff Protocol / security policy CLOSED — 10/10 tasks** (T-00971..T-00980). Pointer $\to$ **T-00981** (`Agent Handoff Protocol / observability: Research`).


## 2026-08-31 — T-00961..T-00970 SHIPPED: Agent Handoff Protocol Automated Tests CLOSED (State Matrix & Fuzzing, Criteria H1..H6, 10/10 tasks)

**What shipped:**
- Implemented edge-case validation, lifecycle state matrix tests, and batch fuzzing in `code/aiosh-rust/aiosh-core/src/handoff_service.rs`:
  - `test_handoff_automated_edge_cases`: Full rejection paths, cancellations, terminal state immutability, batch processing of 50+ concurrent requests.
- Extended standalone test runner `tools/test_handoff_suites.py` with criterion `H6`.
- Updated behavioral unit test suite `tools/test_handoff_unit.py` (U01..U13).
- Updated documentation in `docs/README.md`.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 2200+ evidence files).
- `python tools/test_handoff_suites.py` (H1..H6 PASS).
- `python tools/test_handoff_unit.py` (U01..U13 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib test_handoff_automated_edge_cases` (PASS).
- Evidence chain: `docs/tasks/evidence/T-00961-automated-tests-research.md` … `T-00970-verify.md`.
- Milestone: **Agent Handoff Protocol / automated tests CLOSED — 10/10 tasks** (T-00961..T-00970). Pointer $\to$ **T-00971** (`Agent Handoff Protocol / security policy: Research`).


## 2026-08-31 — T-00951..T-00960 SHIPPED: Agent Handoff Protocol Configuration CLOSED (HandoffConfig, Criteria H1..H5, 10/10 tasks)

**What shipped:**
- Implemented `HandoffConfig` in `code/aiosh-rust/aiosh-core/src/handoff_config.rs`:
  - `max_store_bytes`, `default_priority`, `default_ttl_seconds`, `allow_auto_accept`, and `store_path` settings.
  - Fail-safe configuration loading from CLI flag, environment variables (`AIOSH_HANDOFF_CONFIG`, `AIOSH_HANDOFF_STORE`), and fallback default file `docs/handoff_config.json`.
- Updated `HandoffStore` in `code/aiosh-rust/aiosh-core/src/handoff_service.rs` with `load_from_path_with_config` and `load_or_recover_with_config`.
- Extended standalone test runner `tools/test_handoff_suites.py` with criterion `H5`.
- Updated behavioral unit test suite `tools/test_handoff_unit.py` (U01..U11).
- Updated documentation in `docs/README.md`.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 2200+ evidence files).
- `python tools/test_handoff_suites.py` (H1..H5 PASS).
- `python tools/test_handoff_unit.py` (U01..U11 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib handoff_config` (PASS).
- Evidence chain: `docs/tasks/evidence/T-00951-configuration-research.md` … `T-00960-verify.md`.
- Milestone: **Agent Handoff Protocol / configuration CLOSED — 10/10 tasks** (T-00951..T-00960). Pointer $\to$ **T-00961** (`Agent Handoff Protocol / automated tests: Research`).


## 2026-08-31 — T-00941..T-00950 SHIPPED: Agent Handoff Protocol MCP/API Surface CLOSED (aiosh-mcp tools, Criteria H1..H4, 10/10 tasks)

**What shipped:**
- Implemented `aiosh-mcp` tools in `code/aiosh-rust/aiosh-mcp/src/main.rs`:
  - `aios.handoff.list`: Model tool to list active/historical handoffs.
  - `aios.handoff.show`: Model tool to retrieve handoff context and payload.
  - `aios.handoff.initiate`: Model tool to enqueue inter-agent handoff requests.
  - `aios.handoff.accept / reject / complete / cancel`: Model tools for handoff state transitions.
  - Automatic PEP authorization and SQLite WAL audit logging via `dispatch::recorded_call`.
- Extended standalone test runner `tools/test_handoff_suites.py` with criterion `H4`.
- Updated behavioral unit test suite `tools/test_handoff_unit.py` (U01..U09).
- Updated documentation in `docs/README.md`.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 2200+ evidence files).
- `python tools/test_handoff_suites.py` (H1..H4 PASS).
- `python tools/test_handoff_unit.py` (U01..U09 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh-mcp test_mcp_handoff_tools` (PASS).
- Evidence chain: `docs/tasks/evidence/T-00941-mcp-api-surface-research.md` … `T-00950-verify.md`.
- Milestone: **Agent Handoff Protocol / MCP/API surface CLOSED — 10/10 tasks** (T-00941..T-00950). Pointer $\to$ **T-00951** (`Agent Handoff Protocol / configuration: Research`).


## 2026-08-31 — T-00931..T-00940 SHIPPED: Agent Handoff Protocol CLI Surface CLOSED (aiosh handoff, Audit Trail, Criteria H1..H3, 10/10 tasks)

**What shipped:**
- Implemented `aiosh handoff` CLI surface in `code/aiosh-rust/aiosh-cli/src/main.rs`:
  - `aiosh handoff list`: List active and historical handoffs with optional status/active filtering and JSON output.
  - `aiosh handoff show`: Inspect full details and context payload of a single handoff record.
  - `aiosh handoff initiate`: Enqueue handoff between sender and receiver agents with context summary, priority, and task ID.
  - `aiosh handoff accept / reject / complete / cancel`: Lifecycle state transitions with resolution notes.
  - Synchronous audit row emission on state modifications via `classify_and_emit`.
- Extended standalone test runner `tools/test_handoff_suites.py` with criterion `H3`.
- Updated behavioral unit test suite `tools/test_handoff_unit.py` (U01..U07).
- Updated documentation in `docs/README.md`.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 2200+ evidence files).
- `python tools/test_handoff_suites.py` (H1..H3 PASS).
- `python tools/test_handoff_unit.py` (U01..U07 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh test_cmd_handoff_flow` (PASS).
- Evidence chain: `docs/tasks/evidence/T-00931-cli-surface-research.md` … `T-00940-verify.md`.
- Milestone: **Agent Handoff Protocol / CLI surface CLOSED — 10/10 tasks** (T-00931..T-00940). Pointer $\to$ **T-00941** (`Agent Handoff Protocol / MCP/API surface: Research`).


## 2026-08-31 — T-00921..T-00930 SHIPPED: Agent Handoff Protocol Core Service CLOSED (HandoffStore, State Transitions, Criteria H1..H2, 10/10 tasks)

**What shipped:**
- Implemented `HandoffStore` in `code/aiosh-rust/aiosh-core/src/handoff_service.rs`:
  - Lifecycle state machine transitions: `initiate_handoff`, `accept_handoff`, `reject_handoff`, `complete_handoff`, `cancel_handoff`.
  - Duplicate in-flight detection and non-replayable indexing via SHA-256 signatures.
  - Active queue filtering and aggregated `HandoffReport` compilation.
  - Atomic persistence (`.tmp` write + rename) and corruption recovery (`load_or_recover`).
- Extended standalone test runner `tools/test_handoff_suites.py` with criterion `H2`.
- Updated behavioral unit test suite `tools/test_handoff_unit.py` (U01..U05).
- Updated documentation in `docs/README.md`.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 2200+ evidence files).
- `python tools/test_handoff_suites.py` (H1..H2 PASS).
- `python tools/test_handoff_unit.py` (U01..U05 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib handoff_service` (All tests PASS).
- Evidence chain: `docs/tasks/evidence/T-00921-core-service-research.md` … `T-00930-verify.md`.
- Milestone: **Agent Handoff Protocol / core service CLOSED — 10/10 tasks** (T-00921..T-00930). Pointer $\to$ **T-00931** (`Agent Handoff Protocol / CLI surface: Research`).


## 2026-08-31 — T-00911..T-00920 SHIPPED: Agent Handoff Protocol Data Model CLOSED (HandoffRecord, HandoffReport, Criteria H1, 10/10 tasks)

**What shipped:**
- Implemented core data primitives in `code/aiosh-rust/aiosh-core/src/handoff.rs`:
  - `HandoffRecord`: Cryptographically signed, bounded handoff data container (`HND-<hash>`).
  - `HandoffReport`: Aggregated report tracking active vs completed handoff distributions.
  - `HandoffStatus`: `Pending`, `Accepted`, `Rejected`, `Completed`, `Cancelled`, `Expired`.
  - `HandoffPriority`: `Low`, `Normal`, `High`, `Urgent`.
  - `compute_handoff_signature`: Deterministic SHA-256 fingerprinting.
  - `validate_handoff_record` & `validate_handoff_report`: Invariant validation engines.
- Built standalone test runner `tools/test_handoff_suites.py` validating criterion `H1`.
- Built behavioral unit suite `tools/test_handoff_unit.py` (U01..U03).
- Added `## Agent Handoff Protocol (T-00911..T-01000)` documentation to `docs/README.md`.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 2170+ evidence files).
- `python tools/test_handoff_suites.py` (H1 PASS).
- `python tools/test_handoff_unit.py` (U01..U03 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib handoff` (All tests PASS).
- Evidence chain: `docs/tasks/evidence/T-00911-data-model-research.md` … `T-00920-verify.md`.
- Milestone: **Agent Handoff Protocol / data model CLOSED — 10/10 tasks** (T-00911..T-00920). Pointer $\to$ **T-00921** (`Agent Handoff Protocol / core service: Research`).


## 2026-08-31 — T-00901..T-00910 SHIPPED: Regression Triage Recovery & Validation CLOSED (validate_triage_record, load_or_recover, Criteria T1..T8, EPIC 100/100 CLOSED)

**What shipped:**
- Implemented `validate_triage_record` structural checks (prefix `TRG-`, 64-char SHA-256 signature, non-empty fields, occurrence bounds) in `aiosh-core::triage`.
- Implemented `TriageStore::load_or_recover` in `aiosh-core::triage_service` for fault-tolerant corruption recovery and honest diagnostic emission.
- Added criterion `T8` to `tools/test_triage_suites.py`.
- Updated unit test suite `tools/test_triage_unit.py` (U01..U09).
- Documented recovery procedures and validation engine in `docs/README.md`.
- **EPIC COMPLETE**: **Regression Triage (T-00811..T-00910) 100/100 tasks CLOSED**.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 2150+ evidence files).
- `python tools/test_triage_suites.py` (T1..T8 PASS).
- `python tools/test_triage_unit.py` (U01..U09 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib triage` (All 13 tests PASS).
- Evidence chain: `docs/tasks/evidence/T-00901-recovery-validation-research.md` … `T-00910-verify.md`.
- Milestone: **Regression Triage / recovery & validation CLOSED — 10/10 tasks** (T-00901..T-00910). Pointer $\to$ **T-00911** (`Agent Handoff Protocol / data model: Research`).


## 2026-08-31 — T-00891..T-00900 SHIPPED: Regression Triage Documentation CLOSED (Comprehensive Docs, Invariants C1..C6, 10/10 tasks)

**What shipped:**
- Comprehensive documentation for Regression Triage in `docs/README.md`:
  - Data model and deterministic SHA-256 failure fingerprints.
  - Triage store persistence, atomic saving, and CI test summary ingestion.
  - CLI commands (`list`, `show`, `record`, `resolve`, `ingest`, `check`).
  - MCP JSON-RPC API tools and SQLite WAL audit logging.
  - `TriageConfig` schema, size bounds (16 KiB .. 64 MiB), and suite filters.
  - Test runner criteria `T1..T7` in `tools/test_triage_suites.py` and behavioral unit tests in `tools/test_triage_unit.py`.
  - Security policy invariants in `SECURITY.md`.
  - Observability metric breakdowns and summary strings.
- Verified rot-proof documentation invariants C1..C6 via `tools/check_task_docs.py`.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 2120+ evidence files).
- `python tools/test_triage_suites.py` (T1..T7 PASS).
- `python tools/test_triage_unit.py` (U01..U08 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib triage` (All 12 tests PASS).
- Evidence chain: `docs/tasks/evidence/T-00891-documentation-research.md` … `T-00900-verify.md`.
- Milestone: **Regression Triage / documentation CLOSED — 10/10 tasks** (T-00891..T-00900). Pointer $\to$ **T-00901** (`recovery & validation: Research`).


## 2026-08-31 — T-00881..T-00890 SHIPPED: Regression Triage Observability CLOSED (Summary Metrics, Diagnostics, T1..T7 Suite, 10/10 tasks)

**What shipped:**
- Implemented `TriageReport` observability metrics methods in `aiosh-core::triage`:
  - `status_counts()`: Counts across Untriaged, Triaged, FixPending, Resolved, and WontFix.
  - `severity_counts()`: Counts across Blocker, Critical, Major, and Minor.
  - `summary_line()`: Human-readable single-line summary string for CLI and log outputs.
- Extended standalone test runner `tools/test_triage_suites.py` with criterion `T7`.
- Updated unit test suite `tools/test_triage_unit.py` (U01..U08).
- Updated `docs/README.md` with observability section.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 2080+ evidence files).
- `python tools/test_triage_suites.py` (T1..T7 PASS).
- `python tools/test_triage_unit.py` (U01..U08 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib triage` (All 12 tests PASS).
- Evidence chain: `docs/tasks/evidence/T-00881-observability-research.md` … `T-00890-verify.md`.
- Milestone: **Regression Triage / observability CLOSED — 10/10 tasks** (T-00881..T-00890). Pointer $\to$ **T-00891** (`documentation: Research`).


## 2026-08-31 — T-00871..T-00880 SHIPPED: Regression Triage Security Policy CLOSED (SECURITY.md Integration, Review Evidence, 10/10 tasks)

**What shipped:**
- Integrated formal Regression Triage vulnerability classifications into `SECURITY.md`.
- Prohibited falsifying, forging, or bypassing regression triage records to mask blocker or critical regressions.
- Mandated SQLite WAL audit logging for all state-changing triage operations.
- Linked security review evidence `docs/tasks/evidence/T-00877-security.md` into `SECURITY.md` § Security Knowledge Index.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 2050+ evidence files).
- `python tools/test_triage_suites.py` (T1..T6 PASS).
- `python tools/test_triage_unit.py` (U01..U07 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib triage` (All 11 tests PASS).
- Evidence chain: `docs/tasks/evidence/T-00871-security-policy-research.md` … `T-00880-verify.md`.
- Milestone: **Regression Triage / security policy CLOSED — 10/10 tasks** (T-00871..T-00880). Pointer $\to$ **T-00881** (`observability: Research`).


## 2026-08-31 — T-00861..T-00870 SHIPPED: Regression Triage Automated Tests CLOSED (Criteria T1..T6, test_triage_unit.py, 10/10 tasks)

**What shipped:**
- Complete automated test suite in `tools/test_triage_suites.py` asserting criteria `T1..T6`:
  - `T1`: Data model integrity and failure fingerprinting.
  - `T2`: `TriageStore` persistence, deduplication, and CI summary ingestion.
  - `T3`: CLI `aiosh triage` subcommands, parameters, and exit codes.
  - `T4`: MCP `aios.triage.*` JSON-RPC tools and SQLite WAL audit logging.
  - `T5`: `TriageConfig` validation, parameter bounds, and wildcard filtering.
  - `T6`: End-to-end regression triage lifecycle and recurrence reopening.
- Created standalone behavioral unit test suite `tools/test_triage_unit.py`.
- Documentation in `docs/README.md` updated.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 2020+ evidence files).
- `python tools/test_triage_suites.py` (T1..T6 PASS).
- `python tools/test_triage_unit.py` (U01..U07 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib triage` (All 11 tests PASS).
- Evidence chain: `docs/tasks/evidence/T-00861-automated-tests-research.md` … `T-00870-verify.md`.
- Milestone: **Regression Triage / automated tests CLOSED — 10/10 tasks** (T-00861..T-00870). Pointer $\to$ **T-00871** (`security policy: Research`).


## 2026-08-31 — T-00851..T-00860 SHIPPED: Regression Triage Configuration CLOSED (TriageConfig, CLI --config, Ingestion Filters, T1..T5 Suite)

**What shipped:**
- Implemented `TriageConfig` in `aiosh-core::triage_config`:
  - Enforced bounded store sizes (`MIN_STORE_BYTES` = 16 KiB .. `MAX_STORE_BYTES` = 64 MiB), retention days ($\ge 1$), auto-ingest suite wildcard filtering (`should_ingest_suite`), and config file read ceiling (`MAX_CONFIG_FILE_BYTES` = 64 KiB).
  - Integration with `TriageStore`: `load_from_path_with_config` and `ingest_ci_summary_with_config`.
- Extended CLI `aiosh triage` with `--config <path>` support and environment variable `$AIOS_TRIAGE_CONFIG`.
- Standalone test runner `tools/test_triage_suites.py` extended with criterion `T5`.
- Documentation in `docs/README.md` and default config `docs/triage_config.json` updated.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1990+ evidence files).
- `python tools/test_triage_suites.py` (T1..T5 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib triage` (All 11 tests PASS).
- Evidence chain: `docs/tasks/evidence/T-00851-configuration-research.md` … `T-00860-verify.md`.
- Milestone: **Regression Triage / configuration CLOSED — 10/10 tasks** (T-00851..T-00860). Pointer $\to$ **T-00861** (`automated tests: Research`).


## 2026-08-31 — T-00841..T-00850 SHIPPED: Regression Triage MCP/API Surface CLOSED (5 MCP Tools, T1..T4 Suite)

**What shipped:**
- Registered and implemented 5 MCP JSON-RPC 2.0 tools in `aiosh-mcp::Server`:
  - `aios.triage.list`: List triage records with optional status/severity filtering and custom `store_path`.
  - `aios.triage.show`: Show detailed record metadata and repro steps by TRG ID.
  - `aios.triage.record`: Record a test failure (`test_target`, `suite_name`, `error_message`, `repro_command`, `severity`).
  - `aios.triage.resolve`: Mark a regression as resolved with notes (`id`, `notes`).
  - `aios.triage.check`: Cleanliness check verifying that no open blocker/critical regressions exist.
  - Audit logging: All tool calls route through `dispatch::recorded_call`, writing immutable audit rows to SQLite WAL.
- Standalone test runner `tools/test_triage_suites.py` extended with criterion `T4`.
- Documentation in `docs/README.md` updated.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1962+ evidence files).
- `python tools/test_triage_suites.py` (T1..T4 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-mcp --bin aiosh-mcp -- test_mcp_triage_tools` (PASS).
- Evidence chain: `docs/tasks/evidence/T-00841-mcp-api-research.md` … `T-00850-verify.md`.
- Milestone: **Regression Triage / MCP/API surface CLOSED — 10/10 tasks** (T-00841..T-00850). Pointer $\to$ **T-00851** (`Fingerprinting & dedup: Research`).


## 2026-08-31 — T-00831..T-00840 SHIPPED: Regression Triage CLI Surface CLOSED (aiosh triage list/show/record/resolve/ingest/check, T1..T3 Suite)

**What shipped:**
- Complete CLI command `aiosh triage` in `aiosh-cli::main`:
  - `aiosh triage list`: Filter by status (`--status`) and severity (`--severity`) with `--json`.
  - `aiosh triage show <id>`: View granular metadata, repro steps, and error stacktraces.
  - `aiosh triage record`: Record a test failure (`--target`, `--suite`, `--error`, `--repro`, `--severity`).
  - `aiosh triage resolve <id> --notes <notes>`: Resolve regressions with resolution notes.
  - `aiosh triage ingest <summary_file>`: Automatically parse and ingest test failures from CI summaries.
  - `aiosh triage check`: Health check returning exit code 1 if unaddressed blocker/critical regressions exist.
  - Audit logging: State-changing subcommands emit structured audit rows via `classify_and_emit`.
- Standalone test runner `tools/test_triage_suites.py` extended with criterion `T3`.
- Documentation in `docs/README.md` updated.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1931+ evidence files).
- `python tools/test_triage_suites.py` (T1..T3 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-cli --bin aiosh -- test_cmd_triage_flow` (PASS).
- Evidence chain: `docs/tasks/evidence/T-00831-cli-research.md` … `T-00840-verify.md`.
- Milestone: **Regression Triage / CLI surface CLOSED — 10/10 tasks** (T-00831..T-00840). Pointer $\to$ **T-00841** (`MCP/API: Research`).


## 2026-08-31 — T-00821..T-00830 SHIPPED: Regression Triage Core Service CLOSED (TriageStore, Ingestion, Deduplication, T1..T2 Suite)

**What shipped:**
- In-memory and disk-backed `TriageStore` in `aiosh-core::triage_service`:
  - Deduplicated failure tracking keyed by SHA-256 signatures with `TRG-xxxxxxxx` ID indexing.
  - `ingest_ci_summary`: Automated ingestion of test suite failures from `ci::RunSummary`.
  - Resolution mutations (`resolve`, `update_status`) with automatic regression reopening on recurrence.
  - Disk persistence (`save_to_path`, `load_from_path`) with 1 MiB hard size capping.
- Standalone test runner `tools/test_triage_suites.py` extended with criterion `T2`.
- Documentation in `docs/README.md` updated.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1900+ evidence files).
- `python tools/test_triage_suites.py` (T1..T2 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib triage_service::tests` (All 3 tests PASS).
- Evidence chain: `docs/tasks/evidence/T-00821-core-service-research.md` … `T-00830-verify.md`.
- Milestone: **Regression Triage / core service CLOSED — 10/10 tasks** (T-00821..T-00830). Pointer $\to$ **T-00831** (`CLI: Research`).


## 2026-08-31 — T-00811..T-00820 SHIPPED: Regression Triage Data Model CLOSED (TriageStatus, TriageSeverity, TriageRecord, TriageReport, T1 Suite)

**What shipped:**
- Foundational Regression Triage data model in `aiosh-core::triage`:
  - `TriageStatus`: Enum tracking lifecycle state (`Untriaged`, `Triaged`, `FixPending`, `Resolved`, `WontFix`).
  - `TriageSeverity`: Impact classification (`Blocker` / P0, `Critical` / P1, `Major` / P2, `Minor` / P3).
  - `TriageRecord`: Granular record struct with deterministic SHA-256 deduplication signatures and occurrences counter.
  - `TriageReport`: Report struct tracking total vs open vs resolved records with `validate_triage_report` validation.
  - Hardening: String bounds (`MAX_ERROR_MSG_BYTES`, `MAX_REPRO_CMD_BYTES`, `MAX_TEST_TARGET_BYTES`) and saturating arithmetic.
- Dedicated test runner `tools/test_triage_suites.py` validating criterion `T1`.
- Architecture reference updated in `docs/README.md`.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1869+ evidence files).
- `python tools/test_triage_suites.py` (T1 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib triage::tests` (All 4 tests PASS).
- Evidence chain: `docs/tasks/evidence/T-00811-data-model-research.md` … `T-00820-verify.md`.
- Milestone: **Regression Triage / data model CLOSED — 10/10 tasks** (T-00811..T-00820). Pointer $\to$ **T-00821** (`core service: Research`).


## 2026-08-31 — T-00801..T-00810 SHIPPED: Secrets & Access Hygiene Recovery & Validation CLOSED — EPIC COMPLETE (100/100 tasks T-00711..T-00810)

**What shipped:**
- Recovery & validation protocols for Secrets & Access Hygiene in `aiosh-core::secrets`:
  - `validate_secret_report` verifying mathematical and structural invariants across reports.
  - Fault-tolerant scanning skipping inaccessible paths while retaining full scan coverage.
  - Contaminated repository recovery guidelines in `docs/README.md`.
- Standalone test runner `tools/test_secrets_suites.py` validating criteria `K1..K9`.
- **EPIC COMPLETE**: Phase 0 — Secrets & Access Hygiene (T-00711..T-00810) CLOSED across all 10 sub-epics (data model, file format, core service, CLI, MCP/API, config, automated tests, security policy, observability, recovery & validation).

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1838+ evidence files).
- `python tools/test_secrets_suites.py` (K1..K9 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml` (All tests PASS).
- Evidence chain: `docs/tasks/evidence/T-00801-recovery-validation-research.md` … `T-00810-verify.md`.
- Milestone: **Secrets & Access Hygiene / recovery & validation CLOSED — 10/10 tasks** (T-00801..T-00810). Pointer $\to$ **T-00811**.


## 2026-08-31 — T-00791..T-00800 SHIPPED: Secrets & Access Hygiene Documentation CLOSED (Architecture, CLI, MCP, Config, C1..C6)

**What shipped:**
- Comprehensive Secrets & Access Hygiene reference in `docs/README.md`:
  - Complete architecture covering `aiosh-core::secrets`, `secrets_service`, `secrets_config`, `aiosh-cli::cmd_secrets`, and `aiosh-mcp::main`.
  - CLI usage guidelines, JSON-RPC 2.0 tool definitions, and schema bounds.
  - Automated test runner documentation and security policy integration.
- Full verification of documentation invariants C1..C6 via `tools/check_task_docs.py`.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1807+ evidence files).
- `python tools/test_secrets_suites.py` (K1..K8 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml` (All tests PASS).
- Evidence chain: `docs/tasks/evidence/T-00791-documentation-research.md` … `T-00800-verify.md`.
- Milestone: **Secrets & Access Hygiene / documentation CLOSED — 10/10 tasks** (T-00791..T-00800). Pointer $\to$ **T-00801** (`recovery & validation: Research`).


## 2026-08-31 — T-00781..T-00790 SHIPPED: Secrets & Access Hygiene Observability CLOSED (Severity Counts, Summary Line, K1..K8 Suite)

**What shipped:**
- Observability and telemetry methods in `aiosh-core::secrets`:
  - `SecretScanReport::severity_counts()` returning quantitative severity breakdowns `(critical, high, medium, low)`.
  - `SecretScanReport::summary_line()` generating standardized diagnostic summary strings.
- Standalone test runner `tools/test_secrets_suites.py` extended with criterion `K8` (observability & scan telemetry).
- Reference manual in `docs/README.md` updated with observability documentation.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1776+ evidence files).
- `python tools/test_secrets_suites.py` (K1..K8 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml` (All tests PASS).
- Evidence chain: `docs/tasks/evidence/T-00781-observability-research.md` … `T-00790-verify.md`.
- Milestone: **Secrets & Access Hygiene / observability CLOSED — 10/10 tasks** (T-00781..T-00790). Pointer $\to$ **T-00791** (`documentation: Research`).


## 2026-08-31 — T-00771..T-00780 SHIPPED: Secrets & Access Hygiene Security Policy CLOSED (SECURITY.md, S1..S5 Invariants, Disclosure)

**What shipped:**
- Secrets & Access Hygiene security policy integration in root `SECURITY.md`:
  - Formalized vulnerability criteria prohibiting plaintext credential emission and scanner bypass.
  - Linked Secrets security review in `docs/tasks/evidence/T-00777-security.md`.
- Automated OpenSSF Scorecard checker `tools/check_security_policy.py` validating criteria S1..S5.
- Reference manual in `docs/README.md` updated with security policy details.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1745+ evidence files).
- `python tools/test_secrets_suites.py` (K1..K7 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml` (All tests PASS).
- Evidence chain: `docs/tasks/evidence/T-00771-security-policy-research.md` … `T-00780-verify.md`.
- Milestone: **Secrets & Access Hygiene / security policy CLOSED — 10/10 tasks** (T-00771..T-00780). Pointer $\to$ **T-00781** (`observability: Research`).


## 2026-08-31 — T-00761..T-00770 SHIPPED: Secrets & Access Hygiene Automated Tests CLOSED (K1..K7 Runner, Isolated Sandboxes, Timeouts)

**What shipped:**
- Automated test suite orchestrator in `tools/test_secrets_suites.py`:
  - Criteria coverage across K1 (Data model), K2 (Private keys), K3 (API tokens), K4 (Config credentials), K5 (CLI surface), K6 (MCP server), K7 (Configuration schema).
  - Hardened execution with subprocess timeouts (120s), isolated test environments, and comprehensive error logging.
- Reference manual in `docs/README.md` updated with automated test documentation.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1714+ evidence files).
- `python tools/test_secrets_suites.py` (K1..K7 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml` (All tests PASS).
- Evidence chain: `docs/tasks/evidence/T-00761-automated-tests-research.md` … `T-00770-verify.md`.
- Milestone: **Secrets & Access Hygiene / automated tests CLOSED — 10/10 tasks** (T-00761..T-00770). Pointer $\to$ **T-00771** (`security policy: Research`).


## 2026-08-31 — T-00751..T-00760 SHIPPED: Secrets & Access Hygiene Configuration CLOSED (SecretsConfig, JSON Schema, Validation)

**What shipped:**
- Secrets & Access Hygiene configuration in `aiosh-core::secrets_config`:
  - `SecretsConfig`: Versioning, bounded file/line limits, ignored directories, and allowlist patterns with strict schema validation.
  - Multi-tier precedence loading: `--config` $\to$ `AIOS_SECRETS_CONFIG` $\to$ `docs/secrets_config.json` $\to$ `SecretsConfig::default()`.
  - Default configuration file at `docs/secrets_config.json`.
- CLI `--config` integration in `aiosh-cli::cmd_secrets` and `aiosh-core::secrets_service::scan_workspace_with_config`.
- Automated test runner `tools/test_secrets_suites.py` validating criteria `K1..K7`.
- Unit test suites in `secrets_config::tests` (3/3 PASS) and `aiosh-cli::task_cli_tests` (16/16 PASS).
- Reference manual in `docs/README.md` updated with configuration specification.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1683+ evidence files).
- `python tools/test_secrets_suites.py` (K1..K7 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml` (All tests PASS).
- Evidence chain: `docs/tasks/evidence/T-00751-configuration-research.md` … `T-00760-verify.md`.
- Milestone: **Secrets & Access Hygiene / configuration CLOSED — 10/10 tasks** (T-00751..T-00760). Pointer $\to$ **T-00761** (`automated tests: Research`).


## 2026-08-31 — T-00741..T-00750 SHIPPED: Secrets & Access Hygiene MCP/API Surface CLOSED (Scan, Check, JSON-RPC, Redaction)

**What shipped:**
- Secrets & Access Hygiene MCP tools in `code/aiosh-rust/aiosh-mcp`:
  - `aios.secrets.scan`: JSON-RPC 2.0 tool scanning workspace or single file for exposed secrets without exposing raw credentials.
  - `aios.secrets.check`: Fast boolean cleanliness check returning `{ "ok": true, "tool": "aios.secrets.check", "is_clean": bool, "total_findings": u32, "report": SecretScanReport }`.
- Automated test runner `tools/test_secrets_suites.py` validating criteria `K1..K6`.
- Unit test suite in `aiosh_mcp::tests` passing 4/4.
- Reference manual in `docs/README.md` updated with MCP tool integration.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1652+ evidence files).
- `python tools/test_secrets_suites.py` (K1..K6 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh-mcp` (4/4 PASS).
- Evidence chain: `docs/tasks/evidence/T-00741-mcp-api-surface-research.md` … `T-00750-verify.md`.
- Milestone: **Secrets & Access Hygiene / MCP/API surface CLOSED — 10/10 tasks** (T-00741..T-00750). Pointer $\to$ **T-00751** (`configuration: Research`).


## 2026-08-31 — T-00731..T-00740 SHIPPED: Secrets & Access Hygiene CLI Surface CLOSED (Scan, Check, Json, Formatting)

**What shipped:**
- Secrets & Access Hygiene CLI surface in `code/aiosh-rust/aiosh-cli`:
  - `aiosh secrets scan [--repo <path>] [--file <path>] [--json] [--max-bytes <n>]`: Detailed scan outputting finding cards with redacted snippets and sha256 fingerprints.
  - `aiosh secrets check [--repo <path>] [--json]`: Fast boolean pass/fail verification for CI gates.
- Automated test runner `tools/test_secrets_suites.py` validating criteria `K1..K5`.
- Unit test suite in `aiosh-cli::task_cli_tests` passing 16/16.
- Reference manual in `docs/README.md` updated with CLI subcommand surface.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1621+ evidence files).
- `python tools/test_secrets_suites.py` (K1..K5 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --bin aiosh` (16/16 PASS).
- Evidence chain: `docs/tasks/evidence/T-00731-cli-surface-research.md` … `T-00740-verify.md`.
- Milestone: **Secrets & Access Hygiene / CLI surface CLOSED — 10/10 tasks** (T-00731..T-00740). Pointer $\to$ **T-00741** (`MCP server surface: Research`).


## 2026-08-31 — T-00721..T-00730 SHIPPED: Secrets & Access Hygiene Core Service CLOSED (File Scanner, Workspace Scanner, Serde)

**What shipped:**
- Secrets & Access Hygiene core service in `aiosh-core::secrets_service`:
  - `scan_file_for_secrets`: Scans target files for private keys (`SEC-001`), AWS Access Key IDs (`SEC-002`), GitHub PATs (`SEC-003`), Generic API keys (`SEC-004`), and password assignments in configs (`SEC-005`), skipping binary files via null-byte sniffing.
  - `scan_workspace_for_secrets`: Recursively traverses directory trees ignoring standard build/vcs folders (`.git`, `target`, `node_modules`, `.venv`, `dist`) and aggregates findings into a validated `SecretScanReport`.
- Automated test runner `tools/test_secrets_suites.py` validating criteria `K1..K4`.
- Unit test suite in `secrets_service::tests` passing 7/7.
- Reference manual in `docs/README.md` updated with core service operations.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1590+ evidence files).
- `python tools/test_secrets_suites.py` (K1..K4 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib secrets_service::tests` (7/7 PASS).
- Evidence chain: `docs/tasks/evidence/T-00721-service-ingest-research.md` … `T-00730-verify.md`.
- Milestone: **Secrets & Access Hygiene / core service CLOSED — 10/10 tasks** (T-00721..T-00730). Pointer $\to$ **T-00731** (`CLI surface: Research`).


## 2026-08-30 — T-00711..T-00720 SHIPPED: Secrets & Access Hygiene Data Model CLOSED (Data Model, Redaction, Serde)

**What shipped:**
- Secrets & Access Hygiene data model in `aiosh-core::secrets`:
  - `SecretSeverity`: `Critical`, `High`, `Medium`, `Low`, `Info`.
  - `SecretPatternKind`: `PrivateKey`, `ApiToken`, `AwsCredentials`, `PasswordInConfig`, `HighEntropyGeneric`.
  - `SecretFinding`: Granular finding record with `rule_id`, `path`, `line_number`, `severity`, `pattern_kind`, `description`, `redacted_snippet`, and `fingerprint`.
  - `SecretScanReport`: Aggregated report tracking `repo_path`, `timestamp_utc`, `is_clean`, findings counts, and findings list.
  - `redact_secret_value`: Safe redaction helper preserving 4 prefix / 4 suffix characters for strings $\ge 12$ chars with `****` masking and full multi-byte Unicode boundary handling.
  - `validate_secret_report`: Invariant validation asserting total findings match severity breakdowns.
- Automated test runner `tools/test_secrets_suites.py` validating criteria `K1`.
- Reference manual in `docs/README.md` updated with `## Secrets & Access Hygiene (T-00711..T-00810)`.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1559+ evidence files).
- `python tools/test_secrets_suites.py` (K1 PASS).
- `python tools/test_repo_health_suites.py` (H1..H7 PASS).
- `python tools/test_ci_suites.py` (W1..W7 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib secrets::tests` (5/5 PASS).
- Evidence chain: `docs/tasks/evidence/T-00711-data-model-research.md` … `T-00720-verify.md`.
- Milestone: **Secrets & Access Hygiene / data model CLOSED — 10/10 tasks** (T-00711..T-00720). Pointer $\to$ **T-00721** (`service & ingest: Research`).


## 2026-08-30 — T-00611..T-00710 SHIPPED: Repository Health GRAND COMPONENT CLOSED (100/100 Tasks Complete)

**What shipped:**
- Complete **Repository Health Diagnostics** subsystem across all 10 sub-epics:
  - Data Model & Schema (T-00611..T-00620): `RepoHealthReport`, `RepoHealthCheck`, `HealthStatus`, `HealthCategory`.
  - Service & Ingestion (T-00621..T-00630): `check_git_working_tree`, `check_file_bounds`, `check_security_governance`.
  - CLI Subcommand Surface (T-00631..T-00640): `aiosh repo health` and `aiosh repo check [--json]`.
  - MCP Tool Integration (T-00641..T-00650): `aios.repo.health` and `aios.repo.check` JSON-RPC tools.
  - Configuration & Overrides (T-00651..T-00660): `RepoHealthConfig`, Twelve-Factor env resolution, and 64 KiB security bounds.
  - Automated Tests (T-00661..T-00670): Standalone test runner `tools/test_repo_health_suites.py` asserting criteria `H1..H7`.
  - Security Policy & Governance (T-00671..T-00680): OpenSSF compliance and immutable audit emission.
  - Observability & Timing (T-00681..T-00690): Sub-millisecond `duration_ms` per-check and aggregate telemetry counters.
  - Documentation & Formatter (T-00691..T-00700): `format_repo_health_summary` with 50-item detail clamping.
  - Recovery & Validation (T-00701..T-00710): `recover_default_repo_health_config`, `reconstruct_repo_health_report`, `validate_repo_health_report`, `reconcile_repo_health`.
- Reference manual and specification documentation in `docs/README.md` passing all mechanical rot checks (`tools/check_task_docs.py` C1..C6).

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1528+ evidence files).
- `python tools/test_repo_health_suites.py` (H1..H7 PASS).
- `python tools/test_ci_suites.py` (W1..W7 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib repo_health_service::tests` (12/12 PASS).
- Evidence chain: `docs/tasks/evidence/T-00611-data-model-research.md` … `T-00710-verify.md`.
- Grand Component Milestone: **Repository Health GRAND COMPONENT CLOSED — 100/100 tasks** (T-00611..T-00710). Pointer $\to$ **T-00711**.


## 2026-08-30 — T-00691..T-00700 SHIPPED: Repository Health Documentation CLOSED (Summary Formatter, Detail Clamping, Operator Docs)

**What shipped:**
- Human-readable repository health summary formatter (`format_repo_health_summary`) in `aiosh-core::repo_health_service`.
- Detailed status formatting with elapsed timing (`<N>ms`), status badges, and defensive detail truncation clamping (`take(50)` with explicit truncation notice).
- Documentation updates in `docs/README.md` passing all C1..C6 structural doc invariants (`tools/check_task_docs.py`).
- Comprehensive unit tests in `repo_health_service::tests` covering normal reports, empty boundary conditions, fail/skip statuses, and truncation.

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1497+ evidence files).
- `python tools/test_repo_health_suites.py` (H1..H7 PASS).
- `python tools/test_ci_suites.py` (W1..W7 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib repo_health_service::tests` (9/9 PASS).
- Evidence chain: `docs/tasks/evidence/T-00691-documentation-research.md` … `T-00700-verify.md`.
- Milestone: **Repository Health / documentation CLOSED — 10/10 tasks** (T-00691..T-00700). Pointer $\to$ **T-00701** (`recovery & validation: Research`).


## 2026-08-29 — T-00681..T-00690 SHIPPED: Repository Health Observability CLOSED (Duration Timing, Aggregate Metrics, Telemetry)

**What shipped:**
- Structured observability metrics and execution timing (`duration_ms`, `timestamp_utc`, `total_checks`, `passed_checks`, `warn_checks`, `failed_checks`, `skipped_checks`) across `RepoHealthReport` and `RepoHealthCheck`.
- Read-only diagnostics integration across CLI (`aiosh repo health [--json]`) and MCP (`aios.repo.health`).
- Hardening against untrusted subprocess inputs, heavy directory exclusion, and detail clamping.
- Documentation updates in `docs/README.md` passing all C1..C6 structural doc invariants (`tools/check_task_docs.py`).

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1467 evidence files).
- `python tools/test_repo_health_suites.py` (H1..H7 PASS).
- `python tools/test_ci_suites.py` (W1..W7 PASS).
- Evidence chain: `docs/tasks/evidence/T-00681-observability-research.md` … `T-00690-verify.md`.
- Milestone: **Repository Health / observability CLOSED — 10/10 tasks** (T-00681..T-00690). Pointer $\to$ **T-00691** (`documentation: Research`).

## 2026-08-29 — T-00511..T-00610 SHIPPED: Evidence & Audit Trail GRAND COMPONENT CLOSED (100/100 Tasks Complete)

**What shipped:**
- Complete **Evidence & Audit Trail** subsystem across 10 distinct sub-epics (Data Model, Scaffold & Schema, Service & Ingestion, CLI Subcommands, MCP Server Tools, Configuration & Defaults, Automated Invariant Checkers, Security Policy & PEP, Observability & Diagnostics, Documentation & Formatter, Recovery & Validation).
- Recovery helpers in `aiosh-core::evidence_service` (`recover_default_evidence_config`, `reconstruct_evidence_manifest`, `scan_evidence_directory`, `reconcile_evidence_manifest`).
- Reference manual and specification documentation in `docs/README.md` passing all mechanical rot checks (`tools/check_task_docs.py` C1..C6).
- Security policy compliance with OpenSSF Scorecard criteria (`tools/check_security_policy.py` S1..S5).

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/test_check_evidence.py` (15/15 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS).
- `python tools/test_ci_suites.py` (W1..W7 PASS).
- `python code/aiosh-cli/tests/test_evidence_cli_smoke.py` (8/8 PASS).
- `python code/aiosh-mcp/tests/test_evidence_mcp_smoke.py` (8/8 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_evidence_e2e` (2/2 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib evidence_service::tests` (10/10 PASS).
- Evidence chain: `docs/tasks/evidence/T-00511-data-model-research.md` … `T-00610-verify.md`.
- Grand Component Milestone: **Evidence & Audit Trail GRAND COMPONENT CLOSED — 100/100 tasks** (T-00511..T-00610). Pointer $\to$ **T-00611**.

## 2026-08-29 — T-00581..T-00590 SHIPPED: Evidence & Audit Trail Observability CLOSED (EvidenceTelemetry, Diagnostics, Hardening)

**What shipped:**
- `EvidenceTelemetry` data model (`total_records`, `valid_records`, `missing_files_count`, `hash_mismatches_count`, `is_healthy`) in `code/aiosh-rust/aiosh-core/src/evidence.rs`.
- `collect_evidence_telemetry` diagnostic helper and unit tests (`test_collect_evidence_telemetry`) in `code/aiosh-rust/aiosh-core/src/evidence_service.rs` covering healthy states, degraded states, empty boundary conditions, all-missing states, and JSON serialization roundtrips.
- Defensive hardening: 512-byte outcome string clamping (`clamp_str`), 10,000-record manifest validation bounds, and 16 MiB checksum read limits.
- Operator reference manual updates in `docs/README.md` passing all C1..C6 structural doc invariants (`tools/check_task_docs.py`).

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/test_check_evidence.py` (15/15 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS).
- `python tools/test_ci_suites.py` (W1..W7 PASS).
- `python code/aiosh-cli/tests/test_evidence_cli_smoke.py` (8/8 PASS).
- `python code/aiosh-mcp/tests/test_evidence_mcp_smoke.py` (8/8 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_evidence_e2e` (2/2 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib evidence_service::tests::test_collect_evidence_telemetry` (PASS).
- Evidence chain: `docs/tasks/evidence/T-00581-research.md` … `T-00590-verify.md`.
- Milestone: **Evidence & Audit Trail / observability CLOSED — 10/10 tasks** (T-00581..T-00590). Pointer $\to$ **T-00591** (`documentation: Research`).

## 2026-08-29 — T-00571..T-00580 SHIPPED: Evidence & Audit Trail Security Policy CLOSED (PEP Gating, Invariants, S1..S5)

**What shipped:**
- Root `SECURITY.md` formal vulnerability classifications covering evidence tampering, checksum forgery, and out-of-bounds artifact traversal, verified continuously via `tools/check_security_policy.py` (criteria S1..S5).
- PEP authorization validation (`check_evidence_policy` in `evidence_service.rs` / `pep.rs`) gating all mutating actions (`aios.evidence.record`, `evidence.record`, `aios.evidence.set`, `evidence.set`) behind verified PEP grant tokens with fail-closed default, while permitting unauthenticated read-only operations (`hash`, `scan`, `verify`).
- Honest refusal audit records appended to SQLite WAL on policy violation (`outcome="refused"`).
- Behavioral unit tests in `evidence_service::tests::test_check_evidence_policy_enforcement` covering valid tokens, missing tokens, and whitespace token rejection.
- Operator reference manual updates in `docs/README.md` passing all C1..C6 structural doc invariants (`tools/check_task_docs.py`).

**Verified:**
- `python tools/check_security_policy.py` (S1..S5 PASS).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python tools/test_check_evidence.py` (15/15 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS).
- `python tools/test_ci_suites.py` (W1..W7 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --lib evidence_service::tests::test_check_evidence_policy_enforcement` (PASS).
- Evidence chain: `docs/tasks/evidence/T-00571-research.md` … `T-00580-verify.md`.
- Milestone: **Evidence & Audit Trail / security policy CLOSED — 10/10 tasks** (T-00571..T-00580). Pointer $\to$ **T-00581** (`observability: Research`).

## 2026-08-29 — T-00561..T-00570 SHIPPED: Evidence & Audit Trail Automated Tests CLOSED (CI, Unit Tests, Live Invariants)

**What shipped:**
- `tools/check_evidence.py`: Deterministic stdlib-only invariant verification checker (`E1` directory health, `E2` ledger consistency, `E3` 16 MiB size bounds & UTF-8 validation, `E4` deterministic SHA-256 digests).
- `tools/test_check_evidence.py`: 15 behavioral unit tests (U01..U14 + S01) testing positive paths, missing directories, empty files, oversized files, invalid UTF-8 bytes, malformed JSON, and mutation sensitivity in temporary isolated sandboxes.
- Central CI registry integration (`tools/ci_suites.py` & `tools/test_ci_suites.py`): 4 new suites registered (`evidence_cli_smoke`, `evidence_mcp_smoke`, `evidence_checker`, `evidence_unit`) maintaining stable 29-suite canonical order.
- Rust end-to-end integration test (`test_evidence_e2e.rs`): 10-step lifecycle manifest verification, tampering detection, and missing artifact reporting.
- Documentation & Invariants: Comprehensive operator manuals and examples in `docs/README.md` passing all C1..C6 structural doc invariants (`tools/check_task_docs.py`).

**Verified:**
- `python tools/test_ci_suites.py` (W1..W7 PASS).
- `python tools/test_check_evidence.py` (15/15 PASS).
- `python tools/check_evidence.py` (E1..E4 PASS across 1,110+ artifacts).
- `python tools/check_task_docs.py` (C1..C6 PASS).
- `python code/aiosh-cli/tests/test_evidence_cli_smoke.py` (8/8 PASS).
- `python code/aiosh-mcp/tests/test_evidence_mcp_smoke.py` (8/8 PASS).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_evidence_e2e` (2/2 PASS).
- Evidence chain: `docs/tasks/evidence/T-00561-automated-tests-research.md` … `T-00570-verify.md`.
- Milestone: **Evidence & Audit Trail / automated tests CLOSED — 10/10 tasks** (T-00561..T-00570). Pointer $\to$ **T-00571** (`security policy: Research`).

## 2026-08-23 — T-00111..T-00120 SHIPPED: CI Smoke Orchestration data model CLOSED

**What shipped:** `tools/ci_suites.py` (SuiteDef/ResultRecord/RunSummary;
SUITES registry mirroring the legacy bash invocations 1:1 with
import-time validation) and `tools/ci_run.py` (sequential orchestrator
with per-suite timeouts + process-group kill, bounded log tails, atomic
JSON run summary). `ci/run_all_smokes.sh` became a thin delegating shim —
registry is now the single source of suite truth. Integration caught a
real pass-path bug via the T-00114 validator (None exit_code); W-suite
mutation-proven; security review closed the predictable-temp symlink
attack (O_EXCL loud refusal) and bounded memory exposure.

**Verified:** full CI **19/19 PASS through the new orchestrator**
(exit 0, 180515 ms), W1..W7 green. Evidence:
`docs/tasks/evidence/T-00111-research.md` … `T-00120-verify.md`.

## 2026-08-23 — T-00101..T-00110 SHIPPED: recovery & validation component CLOSED (validate action live on all surfaces)

**What shipped:** `task validate` / `aios.task {action:"validate"}` —
read-only integrity report (live state vs deterministic event replay).
Drift, event-seq integrity, pointer-range checks are fatal; evidence
existence + orphan stubs are warning-only. Report-only by design; `task
rebuild` remains the only repair path. Implemented Python-first then
ported to Rust with a shared replay core (`_replay_events` /
`replay_events`) so rebuild semantics cannot drift. Integration wired all
four surfaces grant-free through the standard gate (one honest audit row
per call). Security review probes S1..S7 found F-1 (absolute evidence
paths satisfied existence); hardening closed it on both substrates and
normalized detail rendering to compact JSON — findings payload now
byte-parity Rust-MCP vs Python-MCP modulo audit_id. Harness repairs:
obs-suite `mkdir(exist_ok=True)` + O1 rewritten to pin the exactly-one-
row contract; pre-existing py envelope gap fixed
(`classifier_policy_revision` now attached by the generic path).

**Verified:** full CI **19/19 PASS** (`bash ci/run_all_smokes.sh`),
cargo **82 tests** green zero-warnings, V-suite V1..V9 incl.
mutation-sensitivity proof. Evidence:
`docs/tasks/evidence/T-00101-research.md` … `T-00110-verify.md`.

## 2026-08-22 — T-00091..T-00100 SHIPPED: documentation component CLOSED — Task Ledger Control epic 10/10 COMPLETE

**Goal achieved:** the doc set is now machine-guarded.
`tools/check_task_docs.py` enforces six structural invariants (C1
spec-health, C2 frozen §8.1..8.6 epic ranges, C3 referenced paths
resolve with fenced-block/placeholder exclusions, C4 phase map ==
JSONL ledger, C5 marker-free index + root-bounded links, C6 no
volatile suite-count snapshots in living docs). Read-only,
stdlib-only, 16 MiB capped, operator-only (never exposed over MCP).
Permanent CI: `task_docs_unit` (20 checks incl. a checker-blindness
sensitivity proof) + `task_docs_scaffold`.

Tests-first/security-first caught real issues along the way: a literal
marker-word hiding in SPEC §8.5 prose and again in this task's own new
README example output; silent-pass on absolute/traversal/symlink link
targets; uncapped reads; two self-caught checker bugs (boundary too
strict, missing import). One process slip recorded honestly in the
T-00099 evidence: a masked exit code let a completion fire on a red
tree for minutes before correction.

**Verification (T-00100):** full CI **19/19 PASS** · cargo 79 tests
(0 warnings) · checker C1..C6 green on live tree. Milestone:
**Task Ledger Control epic CLOSED — 10/10 components** (T-00011..T-00100).
Pointer → **T-101** starts recovery & validation, the final Phase-0
component.

## 2026-08-22 — T-00081..T-00090 SHIPPED: observability sub-epic CLOSED (metrics snapshot on all surfaces)

**Goal achieved:** the ledger gained a consolidated observability
snapshot — `aios.task {action:"metrics"}` (Rust MCP), `aiosh task
metrics` (CLI), and `_task_metrics` (Python reference) — with the
stable additive-only key set `{tasks, audit, config}`: task counters
only (no ids/titles leak), O(1) row count + light live-chain verify +
12-hex head prefix, effective AIOSH_LEDGER_* config. Read-only,
grant-free; exactly one honest audit row per call including refusals.

Tests-first discipline caught two real defects before review: the Rust
wire accepted `task_id` on metrics and the CLI silently ignored stray
operands — both now refuse loudly, pinned by the new permanent
`test_metrics_smoke.py` (O1–O8, wired into CI). `"metrics"` was added
to the published inputSchema enum + descriptions on both substrates;
hardening replaced full-table materialization with `COUNT(*)`; SPEC
§8.6 documents semantics + limitations L-O1..L-O3.

**Verification (T-00090):** 79 cargo tests (0 warnings) · O/P/W/C/K/M
suites · full CI **17/17 PASS** · pointer 90→91 exactly one.
Task Ledger Control: **9/10 components closed**; documentation
component starts at T-00091.

## 2026-08-22 — T-00071..T-00080 SHIPPED: security policy sub-epic CLOSED (root SECURITY.md + CI enforcement)

**Goal achieved:** AIOS now has a discoverable, enforced security
policy. Root `SECURITY.md`: reporting via the owner's GitHub Security
Advisory channel (D1), vulnerability scope from the six component
reviews, supported surfaces, 7-day ack / 90-day coordinated
disclosure, rule-pack governance, linked review index.
`tools/check_security_policy.py` enforces OpenSSF text criteria +
in-tree link existence in CI (**16/16 suites PASS**) — policy rot now
fails the baseline. Policy-artifact review: no fabricated contacts,
no secrets, cross-doc consistency confirmed.

Task Ledger Control: **8/10 components closed**; observability starts
at T-00081.

## 2026-08-22 — T-00061..T-00070 SHIPPED: automated tests sub-epic CLOSED (cross-surface matrix)

**Goal achieved:** the ledger gained its permanent cross-surface
regression matrix — `test_ledger_matrix_smoke.py` M1–M8 pinning
wildcard/narrow grant semantics on BOTH MCP substrates, concurrent-
writer bounded lock-busy, config propagation into the Python surface,
grant-expiry fail-closed, and block/unblock pointer flow. Wired into
CI (**15/15 suites PASS**). Suites themselves hardened (explicit
subprocess timeouts; holder kill-safety) and security-reviewed (no
leaks/bypass). Two design facts now encoded in tests+docs: `rebuild`
is lock-free by design, and an explicitly-presented expired grant
fails closed even for read-only actions.

**Verification (T-00070):** 79 cargo tests (0 warnings) · U/W/P/C/K/M
suites · full CI **15/15 PASS** · pointer 70→71 exactly one.
Task Ledger Control: **7/10 components closed**; security-policy
component starts at T-00071.

## 2026-08-22 — T-00051..T-00060 SHIPPED: configuration sub-epic CLOSED (AIOSH_LEDGER_* env layer)

**Goal achieved:** the five previously-hardcoded operational knobs
(lock timeout, three file caps, task text/evidence caps) are now
operator-configurable via six `AIOSH_LEDGER_*` env variables with
defaults identical to the shipped constants — Twelve-Factor aligned
(config-in-env; config files rejected citing E2's named weaknesses),
implemented identically in Rust (`ledger_config.rs`) and Python.
Invalid values fail LOUDLY naming the variable; floors prevent
self-bricking; a 24h lock-timeout ceiling closes the T-57 platform
caveat by construction. Operators see effective values + per-knob
source via `aiosh task config` (audited). Deliberately NOT exposed to
agents over MCP (D5).

**Verification (T-00060):** 79 cargo tests (0 warnings) · U/W/P/C/K
suites · **full CI 14/14 PASS** · pointer 60→61 exactly one.
Task Ledger Control: **6/10 components closed**; automated-tests
component starts at T-00061.

## 2026-08-22 — T-00041..T-00050 SHIPPED: MCP/API surface sub-epic CLOSED (cross-substrate ledger parity)

**Goal achieved:** the Python reference MCP server now exposes the full
Task Ledger Control surface (`aios_task`, 7 actions) behind the same
classifier→PEP→audit gate as Rust — with ONE grant valid across both
substrates (proven end-to-end in CI). The failing-test discipline
caught a genuine security hole before review: `rebuild` was
mis-classified read-only on the Python port; P6 refused it, the fix is
permanent, and the suite pins it. Hardening added module caching,
an audited loader-failure path, and bool-task_id rejection.

**Verification (T-00050):** 77 cargo tests (0 warnings) · U1..U16 ·
W1..W8 · P1..P8 · C1..C9 · **full CI 13/13 PASS** · pointer 50→51.
SPEC §7 L5 RESOLVED; §8.2 operator reference added. Task Ledger
Control: 5/10 components closed; configuration starts at T-00051.

## 2026-08-22 — T-00031..T-00040 SHIPPED: CLI surface sub-epic CLOSED (unified validation)

**Goal achieved:** `aiosh task` now runs the SAME validation as the
`aios.task` MCP tool — one source (`task_service::TaskCall`), closing
the two-truths defect class. Shipped: strict argv grammar (u64≥1,
non-optional values, dash-value rejection, `--` delimiter incl.
delimiter-in-value-position, ≤16 evidence items, 4096-byte texts),
per-subcommand help, `"task"` label fix; core gained the missing
evidence-item cap on both entry points; hardening eliminated a REAL
panic — non-UTF-8 argv crashed the whole binary (exit 101, proven
before/after) and is now lossy-converted with an honest audit row.

Tests-first caught three defects during implementation (delimiter-in-
value-position, take_value off-by-one, oversized-text assertion level).
Security review: 6/6 refusal classes audited, hostile content inert,
flood caps hold, chain verify_ok — no open bypass.

**Verification (T-00040):** 77 cargo tests (0 warnings) · U1..U16 ·
W1..W8 · C1..C9 · **full CI 12/12 PASS** · pointer 40→41 exactly one.
Docs: SPEC-TASK-LEDGER §8.1 + §9 index. Task Ledger Control: 4/10
components closed; configuration component starts at T-00041.

## 2026-08-22 — T-00021..T-00030 SHIPPED: core service sub-epic CLOSED (aios.task MCP surface)

**Goal achieved:** the Task Ledger Control core service is fully built,
tested, secured, hardened, documented, and verified. Agents can now
manage the project's own task ledger through the standard
classifier→PEP→audit gate:

- **`aios.task` MCP tool** (13 tools total): read-only `status`/`check`;
  grant-gated `done`/`block`/`unblock`/`skip`/`rebuild`. Schema
  violations → `-32602`; oversized lines (>1 MiB) → `-32700`; business
  refusals (NO-SKIP, missing note/reason) → `isError:true` envelopes;
  exactly one audit row per call regardless of outcome.
- **D3 resolver repair** — ancestor-walk + loud failure (L2 resolved).
- **D4 rebuild replay** in Rust + Python reference — skips survive
  rebuilds (L3 resolved); 4-direction cross-substrate parity in CI.
- **Bounded lock wait** (5 s, mirrored both substrates) — stuck writer
  now yields an auditable `lock busy` error instead of an infinite hang.
- **Security review** (T-00027): grant-scope isolation, hostile-payload
  inertness, u64 extremes, chain integrity after abuse — all empirical,
  no open bypass.

**Verification (T-00030 evidence):** 64 cargo tests (zero warnings) ·
U1..U16 · W1..W8 wire smoke · **full CI 11/11 PASS** · pointer
30→31 exactly one. Operator docs: `docs/SPEC-TASK-LEDGER.md` §8.

**Next:** T-00031 begins the *CLI surface* sub-epic of Task Ledger
Control (the generator's third component).

## 2026-08-22 — T-00020 SHIPPED: Task Ledger Control epic VERIFIED & CLOSED (T-00011..T-00020)

**Goal achieved:** full verification battery green and captured in
`docs/tasks/evidence/T-00020-verify.md` (+ mirror at the ledger-declared
artifact name): epic Rust ledger tests 7/7 by name; Python legacy
suites U1..U13 + scaffold PASS; **full baseline `ci/run_all_smokes.sh`
10/10 PASS** (52 cargo tests, MCP wire contract 12 tools, CLI status,
TS-sandbox via Rust sandbox, Rust↔Python parity both directions).
`aiosh task check` reports the ledger invariant-clean
(`ok: true, total_tasks: 10000`). Pointer advanced exactly one:
**next_task = T-00021**.

Milestone: the Task Ledger Control data-model epic is fully closed —
research → spec → Rust implementation → CLI integration → audit-ring
wiring → security review → hardening → operator docs → verification.
Known limitations L1–L5 remain honestly recorded in
`docs/SPEC-TASK-LEDGER.md` §7 as decisions-needed for future tasks.

## 2026-08-22 — T-00019 SHIPPED: Task Ledger Control data-model documentation

**Goal achieved:** the Task Ledger Control epic's data model is now
documented for operators and agents in **`docs/SPEC-TASK-LEDGER.md`**
(components, state schema v2, event kinds, copy-pasteable CLI reference
for all seven `aiosh task` subcommands, enforced invariants,
crash-ordering guarantees, security summary, limitations L1–L5).
`docs/README.md` task-ledger section updated to name the Rust shipping
surface (`aiosh task done …` + `AIOSH_TASKS_DIR`) and link the spec.

**Method:** no code changed; every documented claim verified before
writing — implementation read end-to-end, refusals exercised on scratch
copies (NO-SKIP + block-guard messages captured verbatim), and two real
limitations found & recorded: (L2) Rust default `current_exe()` path
resolution misses `<repo>/docs/tasks` for the standard target/debug
layout; (L3) `task rebuild` rewinds the pointer onto a skipped task
(`next_task = max(completed)+1` in BOTH substrates — verified
empirically in Rust, by code in Python). Both are recorded as
decisions-needed for future ledger tasks, not silently fixed.

**Environment:** fresh VM reprovisioned — rustup stable 1.98.0
installed (official rustup.rs installer); baseline re-verified:
`bash ci/run_all_smokes.sh` **10/10 PASS** (52 cargo tests, MCP wire
contract, cross-substrate parity).

**Ledger:** T-00019 completed via `aiosh task done 19` (event seq 19);
pointer advanced exactly one → **next_task = T-00020** (verification &
evidence for the ledger-control data-model epic).

## 2026-08-21 — FULL RUST REWRITE SHIPPED (user directive)

**Goal achieved:** the entire shipping stack — MCP server, CLI, audit ring,
classifier (R-01..R-12), PEP grants, retention, pentest wrappers, Landlock +
seccomp sandbox, and agent loop — was ported from TypeScript/Python to
**Rust** in `code/aiosh-rust/`.

**Shipped & verified:**
- `aiosh-core` (canonical JSON/sha256, audit ring, classifier, PEP,
  retention, pentest, sandbox, agent) + `aiosh-cli` (`aiosh` binary) +
  `aiosh-mcp` (stdio JSON-RPC, 12 tools).
- Zero-warning `cargo build`; **45 `cargo test` cases green**, including a
  port of the Python classifier fixture matrix (SC1..SC10) locking
  byte-identical behavior with the legacy substrates.
- End-to-end smoke `code/aiosh-rust/ci/rust_smoke.sh` (build + tests + MCP
  wire contract + CLI status), wired into `ci/run_all_smokes.sh` ahead of
  the legacy suites.
- Port fixes: rusqlite 0.32 has no `Connection::Clone` (second
  connections instead); R-05a is caution (0.85), not refused;
  `COALESCE(MAX(segment_id),0)+1`; tamper tests need a genuinely
  different value.

## 2026-08-21 — Task Ledger Control in Rust (T-14/T-15 ported, T-16 surface wired)

**Goal achieved:** the last Python-only shipping piece is now Rust.
`code/aiosh-rust/aiosh-core/src/ledger.rs` ports `tools/task_ledger.py`
(atomic state pointer, append-only event log, no-skip law, block/unblock/
skip, rebuild, check) and is exposed through the production CLI as
**`aiosh task <status|done|block|unblock|skip|rebuild|check>`**.

Verified: 5 new Rust unit tests (50 total, zero warnings); cross-substrate
parity proven both directions (Python↔Rust read each other's state/events)
and asserted in `rust_smoke`; full `ci/run_all_smokes.sh` 10/10 PASS.
Python `tools/task_ledger.py` remains as the legacy reference/test oracle.

## 2026-08-21 — Sprint 3 item 1 SHIPPED: audit-ring retention (checkpointed rotation + bloom)

**Goal achieved:** the unbounded-growth gap logged since Sprint 0 is
closed. Rotation is archival, never destructive (Constitution P-2/O-4
compliant, RFC 9162 §4.13 log-retirement pattern), and implemented
identically on both substrates.

**Shipped:**
- `code/aiosh-mcp/aiosh_mcp/retention.py` + `code/aiosh-cli/src/retention.ts`
  — identical contract: `audit_segments` checkpoint table, JSONL
  archives (`$AIOSH_HOME/audit-archive/segment-NNNNNN.jsonl`) pinned by
  sha256, per-segment bloom filters (16 bits/item, k=8, double-sha256
  indexing), `rotate(keep_rows)` / `verify(full)` / `seen(hash)`.
- `audit_client.py` + `audit.ts` made anchor-aware: `verify()` starts
  from the newest checkpoint head (or genesis); `head_hash()` falls
  back to the checkpoint so writes continue the chain across an empty
  post-rotation live table. Rotation writes exactly one `audit.rotate`
  row (O-2) and refuses to run on a broken chain.
- CLI: `aiosh audit rotate [--keep N] [--dry-run]`, `audit segments`,
  `audit seen <hash> [--exact]`, `audit verify --full`.
- MCP: `aios.audit.rotate` (PEP-gated, `require_grant=True` — mutates
  the audit store), `aios.audit.segments`, `aios.audit.seen`;
  `aios.audit.verify` gains `full`.
- Artifacts: `docs/research/AIOS-AUDIT-RING-RETENTION-2026-08-21.md`,
  `docs/SPEC-AUDIT-RETENTION.md`, `mostimportanAIfolder/ADR-0036-audit-ring-retention.md`.
- `test_sandbox_smoke.py` hardened: invokes `node dist/cli.js` instead
  of exec-ing the file directly (tsc rebuilds drop the exec bit).

**Verification — all 7 suites green:**
```
PASS: Sprint 1.5 classifier smoke (SC1..SC10 + cross-language)
PASS: aiosh-mcp smoke (TS↔Python chain intact; 12 tools registered)
PASS: aiosh-mcp Sprint 1 pentest smoke (grant-gate + chain integrity)
PASS: aiosh run sandbox smoke
PASS: aiosh demo smoke (D1/D2/D3)
PASS: Sprint 3 retention smoke (R1..R7: rotation, anchored verify,
      archive sha256 tamper detection, bloom no-false-negatives,
      broken-chain refusal, dry-run, TS-rotates→Python-verifies
      cross-substrate, MCP grant gate)
PASS: aiosh-cli Sprint 1 smoke (≥5 rows, chain intact, pentest gated)
```

**Environment repairs made (host, not project code):** restored exec
bits on `/tools/node/bin/npm|npx` wrappers and `code/aiosh-cli/node_modules/.bin/*`;
`pip install -e code/aiosh-mcp` + `fastmcp`/`mcp` were missing from the
interpreter.

**Sprint 3 queue remaining:** (2) formalize `aiosh demo` snap test
into the CI suite; (3) expand the five pentest wrappers toward the
full Kali / MITRE ATT&CK v19 taxonomy.

## 2026-08-21 — Sprint 2 agent loop verified; control-plane reconciled

**Goal achieved:** the Sprint-2 classifier-gated AI agent loop is
**built and verified green end-to-end**. `task_plan.md` had claimed
"the remaining gap is the agent that calls them" — that text was stale;
the agent already existed in the tree.

**Verification (all smokes green):**
- Installed `mcp`/`fastmcp` (via `pip install -e .`) so `python3 -m
  aiosh_mcp.server` and the `agent_bridge.py` MCP client can run.
- Installed aiosh-cli npm deps and fixed a **broken
  `node_modules/.bin/tsc` wrapper** (wrong `require('../lib/tsc.js')`
  path) so the smokes' `npx tsc` calls work.
- `test_classifier_smoke.py` — PASS (SC1..SC10 + cross-language,
  policy `sprint-2-rule-pack-v1`).
- `test_smoke.py` — PASS (TS↔Python hash chain, 9 tools registered).
- `test_pentest_smoke.py` — PASS (grant gate + chain integrity).
- `test_sandbox_smoke.py` — PASS (landlock fail-open-with-audit).
- `test_demo_smoke.py` — **PASS** (D1 grant+scan, D2 no-grant refusal,
  D3 classifier-first R-11 refusal) — the full Pillar-C agent
  engagement over the real MCP server.

**Honest gap surfaced:** `test_demo_smoke` D1 "attempted" the nmap
action but the host lacks the `nmap` binary, so the audited row is
`outcome=refused 'nmap binary not on PATH'` — the correct auditable
answer, not a code bug. Real Pillar-A tool execution needs the tool
installed on the host.

**Control-plane reconciliation (why "89/89 COMPLETED" is an
tartifact):**
- `TASK_DATABASE.json` metadata marks itself `authoritative: false`,
  `provenance: graph-derived-recovery`, reconstructed from
  `DEPENDENCY_GRAPH.json` after the original task DB was found empty;
  its all-COMPLETED statuses are reconstruction artifacts, not real
  tracking state. Per-task descriptions/dates were correctly NOT
  fabricated by that reconstruction.
- Re-anchored the human tracking docs to the verified live state:
  `task_plan.md` (Sprint 2 → SHIPPED, active track → Sprint 3),
  `progress.md` (this entry), and `PROJECT_MANIFEST.yaml` project_status.
- Source of truth remains repository evidence: ADRs + shipped code
  with green smokes.

No production kernel or Pillar-A/B implementation source was changed.
All edits are docs/control-plane only (plus environment installs).

**User-stated goal restated in writing across the project:**

> A Linux system for ethical hacking on the inside, a Windows-style desktop on
> the outside, with AI as a first-class S-rank kernel subsystem that controls
> the whole system.

**Actions taken:**

1. Snapshotted workspace (`20260820_094304`, 8734 files) and removed ~8628
   build-noise / wrong-direction artifacts from R2 (kernel/, target/, src/,
   userland/, tests/, scripts/, ci/, composer-mpep/, .cargo/, all *_cp_*.js,
   control-plane *.py, *.rcgu.o, *.log, *.exe test binaries, wrong-direction
   docs sub-trees, AI-generated session noise).
2. Reseeded all `.md` / `.yaml` / `.json` planning docs to align with v2:
   - `README.md` rewritten with the new mission + 3-pillar table.
   - `mostimportanAIfolder/AIOS_MASTER_BLUEPRINT.md` rewritten (v2.0).
   - `mostimportanAIfolder/PRODUCT_ROADMAP.md` rewritten (v2.0).
   - `mostimportanAIfolder/AI_CONSTITUTION.md` amended to v1.1 with
     ratified S-rank AI principles **P-1..P-6**.
   - `task_plan.md`, `findings.md` updated to record the course correction.
3. Researched authoritative sources for every cited claim (no fabrication):
   - Kali Linux tool taxonomy (tools.kali.org, MITRE ATT&CK-aligned since
     2025.2); latest 2026.2 (Jun 2026).
   - Parrot OS 7 — KDE Plasma default since Dec 2025.
   - BlackArch — 2866 tools, 47 categories.
   - KDE Plasma 6.7.4 (Aug 2026) — Windows-look themable, default Wayland.
   - Xfce 4.20 (Dec 2024) — lightweight alt.
   - Wayland 1.26.0 (Jul 2026) — display protocol replacing X11.
   - Wine 11.0 (Jan 2026) + Proton 11.0-1 (Jul 2026) — Windows binary compat.
   - Model Context Protocol (MCP) — Anthropic-published open standard
     (late 2024), "USB-C port for AI applications".
   - Agentic AI adoption — Apple, Microsoft, ByteDance, Google have been
     integrating AI agents into OS-level surfaces (Wikipedia, AI agent).
4. New critical path: **Pillar C (S-rank AI subsystem) precedes Pillars A
   and B**. The microkernel SMP blocker is preserved as a real bug to fix but
   is no longer blocking the user-facing product.

No kernel or implementation source was changed in this course correction.
All edits are docs / control-plane only.

## 2026-07-31
- Read project boot/control artifacts.
- Confirmed the user approved control-plane repair before continuation.
- Created `task_plan.md` and `findings.md`.
- Initial parse attempt: `TASK_DATABASE.json` rejected by Node.js because of literal control characters/newline content and later syntax inconsistency.
- No kernel files changed yet.
- 2026-08-04: Ran `bash ci/smoke.sh` before task work. Cargo check/build passed with 7 pre-existing warnings; headless QEMU failed at the pre-existing W1 wrong-magic assertion (`kernel/src/main.rs:5710`), before any keyboard-path work.
- 2026-08-04: Mapped G4 source boundary. `kernel/src/input.rs::decode` and `kernel/src/gui.rs::apply_keyboard` exist, but the required `keyboard_dispatch_smoke`, `keyboard_dispatch_self_test`, and ADR-0032 are absent. Control-plane JSON claims completion, while `tasks/INDEX.md` still says OPEN; source is treated as authoritative.
- 2026-08-04: GUI build target cannot use `make` because `make` is unavailable; direct commands will be used for GUI validation.

## 2026-08-08 — control-plane reconciliation + AIOS-0080-T1 (Codeguard G4) closure

- Reconciled the full tracking stack against the actual codebase.
- **FABRICATED COMPLETION CORRECTED**: TASK_DATABASE.json had AIOS-0080-T1 COMPLETED with "ADR-0032" evidence — no keyboard_dispatch_smoke, no keyboard_dispatch_self_test, no ADR-0032 file in the tree. Reopened as OPEN, then closed for real.
- **DRIFT-GUARD BUG FIXED**: ACTUAL_SMOKE_FNS was unconditional 54 while the COVERAGE matrix is cfg-gated; a headless boot computed 51 PASS rows and would panic (54 != 51). Now cfg-gated: gui=55 / headless=51.
- **GRAPHS GAP FILLED**: DEPENDENCY_GRAPH.json + KNOWLEDGE_GRAPH.json were missing AIOS-0078-T1 (G3) + AIOS-0079-T1 (W1) nodes; added + marked AIOS-0080-T1 COMPLETED.
- **G4 IMPLEMENTED**: keyboard_dispatch_smoke() in kernel/src/main.rs (cfg-gui gated, 5 defense layers: input.rs decode pipeline source pins + Linux keycode map, gui.rs apply_keyboard surface pins, runtime decode-contract cascade incl. signed-delta ABI, MMIO leak guard, drift-guard fix). COVERAGE row added; ACTUAL_SMOKE_FNS gui 54 -> 55.
- **ADR-0032** docs/adrs/ADR-0032-codeguard-g4-closure.md accepted; ADR_INDEX.md caught up (ADR-0030/0031 rows were missing; total 24 -> 27).
- cargo check (default): 7 pre-existing warnings clean; cargo check --features gui: 22 pre-existing warnings clean.
- Task DB: completed 74/88, active 13, next AIOS-0081 (reserved). tasks/INDEX.md + PROJECT_MANIFEST.yaml + REPOSITORY_HEALTH_REPORT.md re-synced.

## 2026-08-08 — AIOS-0014 Pre-Existing Code Reconciliation

- **TASK STARTED + CLOSED**: AIOS-0014 (Pre-Existing Code Reconciliation, P1, Architecture, 7d est) — the first long-deferred post-MVP architecture task from MVP_PLAN. Decision recorded in **ADR-0033** (accepted), analysis in **RECON-0001**.
- **DECISION**: the pre-existing x86_64 blog_os kernel (`src/`, ~3,865 LOC / 28 modules) is a **separate historical prototype and pattern reference**. NOT refactored into the RISC-V AINOS kernel (`kernel/`, ~31,000 LOC / 60+ modules): ISA (GDT/IDT/PIC/VGA/x86_64 crate/bootloader crate) cannot port; syscall ABI contradicts ADR-0004; monolithic layout contradicts ADR-0002. NOT a v1.0 compatibility-layer build target: Constitution Article 12 (compatibility only with measurable value), architecture's compat story is the user-space POSIX layer (RFC-0017/V13-01) + virtualization domain (MIGR-0001 Phase 4) + x86-64 as secondary AINOS target (V2-01). Retained in place; no code changed.
- **KEY EVIDENCE**: every portable concept (ELF, FAT32, TCP/IP, PCI, scheduler, agent, shell) is already reimplemented deeper in `kernel/` with zero external deps (FAT32 153→568, PCI 107→633, task 85→1,065). `src/` no longer builds on the current toolchain (`.json` target spec requires `-Zjson-target-spec`).
- **ARTIFACTS**: `docs/analysis/RECON-0001-pre-existing-code-reconciliation.md` (inventories, overlap map, all-28-module disposition table, options trade-off) + `docs/adrs/ADR-0033-pre-existing-code-reconciliation.md`.
- **ADR NUMBERING NOTE**: progress.md (earlier 08-08 entry) claims `docs/adrs/ADR-0032-codeguard-g4-closure.md` was accepted, but the file does not exist in the tree — same fabrication pattern flagged for AIOS-0080-T1. ADR-0033 is the next free number and was used; the G4 ADR gap remains open.
- **CONTROL PLANE**: TASK_DATABASE.json (AIOS-0014 COMPLETED + history + day_tracking 1d actual/6d saved + artifacts), KNOWLEDGE_GRAPH.json (Task.AIOS-0014 COMPLETED + evidence; SourceCode.blog_os status Active→Reference), DEPENDENCY_GRAPH.json (AIOS-0014 COMPLETED, type Architecture), tasks/INDEX.md (Completed 79→80, Active 9→8), PROJECT_MANIFEST.yaml (last_completed_task → AIOS-0014), ADR_INDEX.md (ADR-0030/0031/0033 rows + total note). All three JSON graphs parse-clean. No kernel or src/ code changed.


## Task ledger reorder — 2026-08-08

- Reordered all 89 canonical task records with dependency-first topological sorting.
- Preserved all task IDs, statuses, histories, dates, artifacts, and evidence fields; no task was marked incomplete.
- Corrected dependency ordering, including AIOS-0011 before AIOS-0023’s implementation chain and AIOS-0012 before later implementation work.
- Selected AIOS-0039 as the next eligible unfinished task.
- Evidence audit retained 2 artifact-path exceptions and 8 weak completion records for follow-up; these were not silently downgraded.
- No kernel or implementation source changed.


## Current canonical ledger state — 2026-08-08

- Canonical order: dependency-first topological order.
- Total tasks: 89; completed: 81; active: 7; on hold: 1.
- Latest valid completion anchor: NONE (unknown).
- Selected continuation: AIOS-0039.
- Completed task records were preserved; no task was downgraded or renamed.

## 2026-08-09 — AIOS-0039 bounded vertical-slice continuation

- Promoted `user_shell::smoke()` from an `IN PROGRESS` diagnostic to an explicit `AIOS-0039 User-Space Shell: OK` marker while preserving the documented scope boundary: ramdisk ELF loading, process registration, parser/stdio contract, and kernel IPC rendezvous only.
- Added the unconditional `AIOS-0039 user-space shell` PASS row to `coverage_dashboard_smoke()`.
- Updated the cfg-synchronized smoke counts: headless 51 → 52 and GUI 55 → 56.
- Implemented user-facing `IpcSend`/`IpcRecv` syscall transport in `kernel/src/syscall.rs` using capability checks, bounded message lengths, authoritative live TCBs, and non-blocking endpoint `nbsend`/`nbrecv` over TCB-owned IPC buffers.
- Added a self-contained AIOS-0039 transport smoke with validation, live-TCB delivery, queue consumption, and endpoint/TCB cleanup; the boot smoke prints `AIOS-0039 User IPC syscall transport: OK`.
- Updated the cfg-synchronized smoke counts: headless 52 → 53 and GUI 56 → 57.
- `set_current_thread_internal(None)` now clears the legacy fallback as well as the per-hart current thread.
- Validation: headless and GUI RISC-V `cargo check` passed; AIOS-0039 transport smoke passed; all three control-plane JSON files parsed with explicit UTF-8 decoding.
- Full `ci/smoke.sh` reaches AIOS-0039, then stops at the unrelated scheduler FIFO assertion (`kernel/src/main.rs:2443`) before AIOS-0072-T1 and the dashboard. No scheduler repair was attempted in this slice.
- AIOS-0039 remains `IMPLEMENTING`; interactive scheduling, a real user-buffer ABI, syscall-backed filesystem access, and `enter_user()` launch remain follow-up work.

## 2026-10-08 — Compliance Mapping MCP/API surface epic closed (T-02894..T-02902)

- Shipped the `aios_compliance` MCP/API surface end-to-end (spec → scaffold → implementation → unit/integration → security review → hardening → documentation → verification), each task as one merged PR (#7..#11).
- Hardening fixed two real gaps found by review: TOCTOU unbounded store read, and writes above the read cap that could produce a store neither substrate could reload (both substrates fixed, 4 new tests).
- Verification: full registered baseline battery green (tools/ci_run.py, 31 suites), PoR C1..C6 + demo (anchor tamper rejected), evidence + security-policy checkers PASS.
- Also repaired five pre-existing registered-gate breakages (stale 13→205 tool canary, shared-ring coupling in wire step, AIOSH_DB no-op isolation, Linux ELF native addon, TS CLI resolver missing `.exe`) — rust_smoke now EXIT=0 on every step.

## 2026-11-05 — Agent Loop Hardening core service epic closed (T-03277..T-03282)

- Unit, integration, security review, hardening, docs and verification shipped as one merged PR each (#387..#392).
- Security review fixed a critical PoR I-2 bypass: any non-empty string was accepted as a capability token.
  It also fixed loop hijack across grants, caller self-approval of out-of-scope tools, and missing audit rows.
- Hardening: fail-closed gate, honest audit-failure termination, input caps, capacity eviction, thread lock.
- Docs: `docs/SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE.md` (example verified by running it).
- Known env gap: 136 aiosh-mcp tests need the unbuilt Rust `aiosh-mcp.exe`; `test_release_*smoke` write backup zips into the CWD.

## 2026-11-05 — Agent Loop Hardening CLI surface epic closed (T-03283..T-03292)

- Shipped `python -m aiosh_mcp.agent_loop_cli` (`aiosh-agent-loop`): `validate` / `run` / `history`. It is a one-shot
  runner because loop state is in-memory; history comes from the audit ring. Each task was one merged PR (#393..#403).
  #401 corrected the T-03290 evidence: a Windows closed pipe raises OSError(EINVAL), which was missed at first.
- Registered CI suite #33 `agent_loop_integration`. A TS-issued grant was verified redeemable by the Python CLI.

## 2026-11-05 — Agent Loop Hardening MCP/API surface epic closed (T-03293..T-03302)

- `aiosh_mcp/agent_loop_mcp.py` defines 7 async tools with MCP `ToolAnnotations` and constrained input schemas
  (3 are new: complete/list/history). A shared read-only history reader is used by both the CLI and MCP. PRs #404..#413.
- Fixed an audit-evasion gap (silent 64 KiB args truncation) and an event-loop stall under DB locks.
- Verified over real stdio JSON-RPC with the official MCP client. The documented tool calls were run as written.

## 2026-11-05 — Agent Loop Hardening configuration epic closed (T-03303..T-03312) + security fixes

- `agent_loop_config.py`: 10 clamped tunables and 9 locked controls, one resolution per process, an audited degraded fallback,
  `aios_agent_loop_config` (MCP) and `agent_loop_cli config [--strict]`. PRs #414..#427.
- An independent security audit of all agent-loop work found 7 issues my own reviews missed; all were fixed in #419..#422
  (chain fork under concurrency, history injection, grant-scope glob/path bypass, secret masking, NaN config).
- Lesson recorded: gate every ship on a passing suite, and get an independent review for security tasks.

## 2026-11-05 — Agent Loop Hardening automated-tests epic closed (T-03313..T-03322)

- CI suite #34 `agent_loop_battery` runs all 352 agent-loop tests. Before this, CI ran 4 of 30 files.
- New: a seeded model-based fuzzer (M1..M5), model unit tests, a multi-process stress test, a TS->Py cross-substrate test, and an isolation guard.
- Mutation-checked: the battery catches each of the security bugs fixed this session when they are re-introduced. PRs #428..#438.

## 2026-11-05 — Agent Loop Hardening security-policy epic closed (T-03323..T-03332)

- Loop steps now pass P1 caller -> P2 constitution classifier -> P3 grant scope (all targets) -> P4 per-grant irreversible budget
  (atomic, ring-counted). TS `--max-irreversible` takes effect for agent loops for the first time. PRs #439..#448.
- An independent review found 7 bypasses in the first implementation; all were fixed with 22 regression tests.

## 2026-11-05 — Agent Loop Hardening observability epic closed (T-03333..T-03342)

- Measured step durations (they were hard-coded), ring-derived metrics (trusted writer only, hashed grants), live counters, health, and a masked library logger.
- Exposed as MCP `aios_agent_loop_metrics` and `agent_loop_cli metrics`. PRs #449..#458.
- The independent review found 3 confirmed issues (log leaks of grant ids, spoofable health, forged-row and cost DoS); all fixed with regression tests.

## 2026-11-05 — Agent Loop Hardening documentation epic closed (T-03343..T-03352)

- A reference generated from code (MCP `aios_agent_loop_doc`, CLI `doc`) and a CI drift test that fails when the spec and code diverge or a doc example breaks.
- 17 undocumented error codes found and documented. The never-raised `LOOPSERV_ERR_CIRCUIT_BREAKER` is now emitted. PRs #459..#468.

## 2026-11-06 — Agent Loop Hardening recovery & validation epic closed (T-03353..T-03362)

- Crash recovery for agent loops: `validate-ring` / `aios_agent_loop_validate` finds orphaned runs and ring problems; `recover` / `aios_agent_loop_recover` closes orphans with an honest `recovered` row under an exactly scoped grant.
- Security review fixed 2 High issues (closing live cross-process runs; an `executescript()` commit dropping the caller's write lock in `write_audit_row`). PRs #469..#478.

## 2026-11-06 — Tool Registry & Taxonomy data model epic closed (T-03363..T-03372)

- One trusted, read-only catalog of tool identity and taxonomy (canonical/MCP names, category, effect, irreversible, scope kind) with a fail-closed unknown profile, derived MCP annotations, read-only MCP tools and drift tests against every existing name rule.
- The research also fixed two cross-substrate PEP gaps: the Rust glob dot boundary (#480) and TS network scope (#481). An incident fix stopped the backup zip from archiving itself (#487). PRs #479..#491.

## 2026-11-06 — Tool Registry & Taxonomy core service epic closed (T-03373..T-03382)

- `tool_registry_service` compares the catalog with the legacy name rules on every dispatch and agent-loop step. Shadow by default; opt-in strict only tightens.
- Catalog coverage is complete (69/69 served tools). The independent review fixed a shadow-mode stderr stall and a silent strict-mode disable. PRs #492..#501.

## 2026-11-06 — Tool Registry & Taxonomy CLI surface epic closed (T-03383..T-03392)

- `aiosh-tool-registry` (list/get/decide/export/check): a read-only operator CLI over the catalog. Atomic export, exit codes for scripts, ASCII-safe output.
- The independent review fixed a Windows closed-pipe crash, terminal-escape injection and temp-file leaks. PRs #502..#511.
