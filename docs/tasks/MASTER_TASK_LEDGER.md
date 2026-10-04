# MASTER TASK LEDGER — 10,062 sequential tasks

**Law:** execute strictly in numeric order. Task N+1 starts only when task N is complete.
Never jump to a later task. If blocked, record the blocker and stop.

Full machine-readable ledger: `MASTER_TASK_LEDGER.jsonl` (one task per line).
Live pointer: `TASK_STATE.json` (`next_task` = the only task allowed to start).

## Phase map

| Phase | Task range |
|---|---|
| Phase 0 — Governance, Repo, CI, Task Execution | T-00001 .. T-01000 |
| Phase 1 — Linux Base System & Bootable Target | T-01001 .. T-02000 |
| Phase 2 — Security Kernel & PEP Fabric | T-02001 .. T-03062 |
| Phase 3 — AI Control Plane (Pillar C Spine) | T-03063 .. T-04062 |
| Phase 4 — Pillar A: Ethical Hacking Toolchain | T-04063 .. T-05062 |
| Phase 5 — Pillar B: Windows-Style Desktop | T-05063 .. T-06062 |
| Phase 6 — AI Kernel-Level Control Integration | T-06063 .. T-07062 |
| Phase 7 — Storage, Networking, Devices | T-07063 .. T-08062 |
| Phase 8 — Reliability, Observability, Performance | T-08063 .. T-09062 |
| Phase 9 — Release, Certification, User Docs | T-09063 .. T-10062 |

## First 25 tasks (detail)

### T-00001 — Mission lock + sequential execution law  `[done]`
**Goal:** Confirm the project mission and create the binding no-skip task law.
**Instructions:**
- Read START_HERE.md, PROJECT_MANIFEST.yaml, AI_CONSTITUTION.md, ADR-0035, ADR-0036.
- Create docs/tasks/GOALS.md with the mission, pillars, and execution law.
- Record that tasks execute strictly in numeric order (task N+1 only after N done).
**Acceptance:**
- docs/tasks/GOALS.md exists and states the no-skip rule.

### T-00002 — Environment + baseline verification  `[done]`
**Goal:** Prove the toolchain and all existing smoke suites are green before new work.
**Instructions:**
- Install/verify python deps (pip install -e code/aiosh-mcp) and node deps.
- Run all existing smokes: classifier, mcp, pentest, sandbox, demo, cli bash.
- Record PASS output in docs/tasks/evidence/T-00002-baseline.md.
**Acceptance:**
- All baseline suites PASS; evidence captured.

### T-00003 — Generate canonical 10,000-task ledger  `[done]`
**Goal:** Create the machine-readable sequential ledger and live task pointer.
**Instructions:**
- Run tools/generate_master_tasks.py to produce MASTER_TASK_LEDGER.jsonl + TASK_STATE.json.
- Verify exactly 10,000 tasks, IDs T-00001..T-10000, each with instructions + acceptance.
- Verify next_task pointer equals 4.
**Acceptance:**
- Ledger has 10,000 well-formed tasks; pointer file exists.

### T-00004 — Create fail-fast CI runner  `[ready]`
**Goal:** Give the project one command that runs every smoke suite sequentially and fails loudly.
**Instructions:**
- Create ci/run_all_smokes.sh invoking each suite in order with set -euo pipefail.
- Print a per-suite PASS/FAIL summary and exit non-zero on any failure.
- Make it executable and run it once; capture output as evidence.
**Acceptance:**
- bash ci/run_all_smokes.sh exits 0 with all suites PASS.

### T-00005 — Task-state completion tool  `[pending]`
**Goal:** Provide a single command to mark the active task complete and advance the pointer.
**Instructions:**
- Create tools/complete_task.py <task_id>: validate task_id == current next_task.
- On success, move task to completed set and increment next_task by exactly 1.
- Refuse out-of-order completion (this mechanically enforces the no-skip law).
**Acceptance:**
- complete_task.py rejects wrong-order IDs and advances pointer correctly.

### T-00006 — Index task system from README  `[pending]`
**Goal:** Make the task ledger discoverable from the repo entry points.
**Instructions:**
- Add a short section to README.md and docs/README.md pointing at docs/tasks/.
- State the rule: agents must read TASK_STATE.json and execute only next_task.
**Acceptance:**
- README links the ledger and states the no-skip rule.

### T-00007 — Retention operations runbook  `[pending]`
**Goal:** Document day-2 operations for the Sprint-3 retention system.
**Instructions:**
- Write docs/RUNBOOK-AUDIT-RETENTION.md covering rotate, verify --full, seen, disaster recovery.
- Include copy-paste CLI + MCP examples and what each alarm means.
**Acceptance:**
- Runbook exists with working examples for all four operations.

### T-00008 — Backup & sync verification  `[pending]`
**Goal:** Prove the Drive/R2 backup path captures the current tree reproducibly.
**Instructions:**
- Re-create the AIOS_MERGED.zip snapshot and verify key files byte-match the tree.
- Record the procedure + checksums in docs/tasks/evidence/T-00008-backup.md.
**Acceptance:**
- Backup archive verified; procedure documented.

### T-00009 — Retention security review  `[pending]`
**Goal:** Threat-model the rotation/archive/seen surfaces shipped in Sprint 3.
**Instructions:**
- Review rotate/seen/verify_full for injection, path traversal, and covert-erasure abuse.
- Confirm MCP rotate requires grant and refusal rows are written.
- Record findings in docs/tasks/evidence/T-00009-security.md.
**Acceptance:**
- Security review evidence file exists; no open bypass.

### T-00010 — Audit-ring performance baseline  `[pending]`
**Goal:** Measure verify/rotate cost at 10k and 100k rows to size retention cadence.
**Instructions:**
- Generate synthetic rings (10k, 100k rows) in a temp DB; time verify and verify --full.
- Record numbers + recommended rotation cadence in docs/tasks/evidence/T-00010-perf.md.
**Acceptance:**
- Benchmark table exists with a recommended max live-row threshold.

### T-00011 — Phase 0 — Governance, Repo, CI, Task Execution / Task Ledger Control / data model: Research  `[pending]`
**Goal:** Establish facts, constraints, and prior art for the data model of Task Ledger Control.
**Instructions:**
- Read the existing code and docs related to data model before assuming anything is missing.
- Collect authoritative sources (upstream docs, man pages, RFCs) and record fact vs assumption.
- Write findings to docs/tasks/evidence/T-00011-research.md with citations.
- List unknowns and decisions needed before any implementation task.
**Acceptance:**
- Evidence file exists and separates facts from assumptions.
- No code changed; decisions needed are listed explicitly.

### T-00012 — Phase 0 — Governance, Repo, CI, Task Execution / Task Ledger Control / data model: Specification  `[pending]`
**Goal:** Specify the exact contract for the data model of Task Ledger Control.
**Instructions:**
- Define inputs, outputs, error cases, and persistence effects for data model.
- State which existing interfaces are reused and which are new.
- Write the spec section to docs/tasks/evidence/T-00012-spec.md.
- Do not invent APIs that do not exist upstream; mark any proposal as AIOS-specific.
**Acceptance:**
- Spec covers happy path, failure path, and audit effects.
- Spec is reviewable without reading the implementation.

### T-00013 — Phase 0 — Governance, Repo, CI, Task Execution / Task Ledger Control / data model: Scaffold  `[pending]`
**Goal:** Create the module skeleton and interfaces for the data model of Task Ledger Control.
**Instructions:**
- Create or extend the appropriate source file(s) under code/ following existing module style.
- Define typed function signatures / interfaces only; bodies fail loudly (throw/NotImplementedError).
- Wire exports/imports so the project still compiles or imports cleanly.
- Run the build (npm run build / python -c import) and fix all errors.
**Acceptance:**
- Project builds/imports with zero errors.
- New interfaces exist and are referenced by at least one call site or test stub.

### T-00014 — Phase 0 — Governance, Repo, CI, Task Execution / Task Ledger Control / data model: Implementation  `[pending]`
**Goal:** Implement the minimal working behavior for the data model of Task Ledger Control.
**Instructions:**
- Write a failing test first where feasible (smoke or unit).
- Implement the smallest change that passes; follow existing patterns in code/aiosh-cli and code/aiosh-mcp.
- Reuse existing helpers (audit ring, dispatch gate, classifier) instead of duplicating logic.
- Do not add new dependencies unless the Research task for this epic approved one.
- Keep all audit/PEP invariants: consequential actions write exactly one audit row.
**Acceptance:**
- Targeted test passes.
- No regression in existing smoke suites for touched modules.

### T-00015 — Phase 0 — Governance, Repo, CI, Task Execution / Task Ledger Control / data model: Unit Test  `[pending]`
**Goal:** Add focused automated tests for the data model of Task Ledger Control.
**Instructions:**
- Cover: valid input, invalid input, boundary values, and the primary failure mode.
- Add tests under the matching tests/ directory using the existing smoke-test style.
- Assert observable behavior (return values, DB state, files), not implementation details.
- Run the new test file in isolation and confirm it fails when the feature is broken.
**Acceptance:**
- New test file runs standalone and passes.
- Negative cases are asserted, not just happy path.

### T-00016 — Phase 0 — Governance, Repo, CI, Task Execution / Task Ledger Control / data model: Integration  `[pending]`
**Goal:** Integrate the data model of Task Ledger Control with the surrounding system.
**Instructions:**
- Wire the feature into its real call path (CLI command, MCP tool, or service hook).
- Confirm cross-substrate parity where the feature touches the shared SQLite DB or canonical JSON.
- Update the relevant server/CLI registration point so the surface is discoverable.
- Run the closest existing smoke suite that exercises the integrated path.
**Acceptance:**
- Feature reachable through its production surface.
- Integration smoke passes end-to-end.

### T-00017 — Phase 0 — Governance, Repo, CI, Task Execution / Task Ledger Control / data model: Security Review  `[pending]`
**Goal:** Security-review the data model of Task Ledger Control.
**Instructions:**
- Check input validation, path/argument injection, and untrusted-content handling.
- Verify PEP gating and audit-row emission for every state-changing path.
- Document abuse scenarios in docs/tasks/evidence/T-00017-security.md.
- If any scenario bypasses policy, create a blocking note and fix before proceeding.
**Acceptance:**
- Security evidence file exists with abuse scenarios.
- No known policy bypass remains open.

### T-00018 — Phase 0 — Governance, Repo, CI, Task Execution / Task Ledger Control / data model: Hardening  `[pending]`
**Goal:** Harden the data model of Task Ledger Control against failure and misuse.
**Instructions:**
- Add timeouts, size caps, and bounded retries where external processes or files are involved.
- Ensure errors are reported in the standard result envelope (never silent failure).
- Confirm resource cleanup (DB connections, temp files, child processes).
- Fail-open behavior must always write an honest audit row (per ADR-0035 §F-2).
**Acceptance:**
- Failure modes produce explicit, auditable errors.
- No temp/connection leaks on the error path.

### T-00019 — Phase 0 — Governance, Repo, CI, Task Execution / Task Ledger Control / data model: Documentation  `[pending]`
**Goal:** Document the data model of Task Ledger Control for operators and agents.
**Instructions:**
- Update the relevant README/spec with what shipped and how to invoke it.
- Include at least one copy-pasteable example command or tool call.
- Record constraints and known limitations honestly.
- Link the task evidence files from the doc.
**Acceptance:**
- Docs updated with working example.
- Limitations are stated, not omitted.

### T-00020 — Phase 0 — Governance, Repo, CI, Task Execution / Task Ledger Control / data model: Verification & Evidence  `[pending]`
**Goal:** Verify the data model of Task Ledger Control and close the task with evidence.
**Instructions:**
- Run all test suites relevant to this epic plus the full baseline smoke set.
- Capture PASS output into docs/tasks/evidence/T-00020-verify.md.
- Update task_plan.md / progress.md if this task completes a milestone.
- Only then mark the task complete and advance to the next numeric task.
**Acceptance:**
- Full relevant suite green with captured output.
- State files updated; next task pointer advanced.

### T-00021 — Phase 0 — Governance, Repo, CI, Task Execution / Task Ledger Control / core service: Research  `[pending]`
**Goal:** Establish facts, constraints, and prior art for the core service of Task Ledger Control.
**Instructions:**
- Read the existing code and docs related to core service before assuming anything is missing.
- Collect authoritative sources (upstream docs, man pages, RFCs) and record fact vs assumption.
- Write findings to docs/tasks/evidence/T-00021-research.md with citations.
- List unknowns and decisions needed before any implementation task.
**Acceptance:**
- Evidence file exists and separates facts from assumptions.
- No code changed; decisions needed are listed explicitly.

### T-00022 — Phase 0 — Governance, Repo, CI, Task Execution / Task Ledger Control / core service: Specification  `[pending]`
**Goal:** Specify the exact contract for the core service of Task Ledger Control.
**Instructions:**
- Define inputs, outputs, error cases, and persistence effects for core service.
- State which existing interfaces are reused and which are new.
- Write the spec section to docs/tasks/evidence/T-00022-spec.md.
- Do not invent APIs that do not exist upstream; mark any proposal as AIOS-specific.
**Acceptance:**
- Spec covers happy path, failure path, and audit effects.
- Spec is reviewable without reading the implementation.

### T-00023 — Phase 0 — Governance, Repo, CI, Task Execution / Task Ledger Control / core service: Scaffold  `[pending]`
**Goal:** Create the module skeleton and interfaces for the core service of Task Ledger Control.
**Instructions:**
- Create or extend the appropriate source file(s) under code/ following existing module style.
- Define typed function signatures / interfaces only; bodies fail loudly (throw/NotImplementedError).
- Wire exports/imports so the project still compiles or imports cleanly.
- Run the build (npm run build / python -c import) and fix all errors.
**Acceptance:**
- Project builds/imports with zero errors.
- New interfaces exist and are referenced by at least one call site or test stub.

### T-00024 — Phase 0 — Governance, Repo, CI, Task Execution / Task Ledger Control / core service: Implementation  `[pending]`
**Goal:** Implement the minimal working behavior for the core service of Task Ledger Control.
**Instructions:**
- Write a failing test first where feasible (smoke or unit).
- Implement the smallest change that passes; follow existing patterns in code/aiosh-cli and code/aiosh-mcp.
- Reuse existing helpers (audit ring, dispatch gate, classifier) instead of duplicating logic.
- Do not add new dependencies unless the Research task for this epic approved one.
- Keep all audit/PEP invariants: consequential actions write exactly one audit row.
**Acceptance:**
- Targeted test passes.
- No regression in existing smoke suites for touched modules.

### T-00025 — Phase 0 — Governance, Repo, CI, Task Execution / Task Ledger Control / core service: Unit Test  `[pending]`
**Goal:** Add focused automated tests for the core service of Task Ledger Control.
**Instructions:**
- Cover: valid input, invalid input, boundary values, and the primary failure mode.
- Add tests under the matching tests/ directory using the existing smoke-test style.
- Assert observable behavior (return values, DB state, files), not implementation details.
- Run the new test file in isolation and confirm it fails when the feature is broken.
**Acceptance:**
- New test file runs standalone and passes.
- Negative cases are asserted, not just happy path.
