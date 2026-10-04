#!/usr/bin/env python3
"""Generate the canonical 10,000-task sequential master ledger.

Outputs:
  docs/tasks/MASTER_TASK_LEDGER.jsonl   — one task per line (full detail)
  docs/tasks/MASTER_TASK_LEDGER.md      — human index (laws + first tasks + phase map)
  docs/tasks/TASK_STATE.json            — live pointer: next task, completed set

Rules encoded in every task:
  - strict numeric order; a task may start only when task_id-1 is done
  - research before implementation (REP binding)
  - every implementation task requires a failing test first where possible
  - every task lists acceptance criteria; evidence must be recorded
"""
import json, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "tasks")
os.makedirs(OUT, exist_ok=True)
os.makedirs(os.path.join(OUT, "evidence"), exist_ok=True)

PHASES = [
    ("Phase 0 — Governance, Repo, CI, Task Execution", [
        "Task Ledger Control", "CI Smoke Orchestration", "Release Packaging & Backup",
        "Dependency & Toolchain Pinning", "Documentation Index Control",
        "Evidence & Audit Trail", "Repository Health", "Secrets & Access Hygiene",
        "Regression Triage", "Agent Handoff Protocol"]),
    ("Phase 1 — Linux Base System & Bootable Target", [
        "Distro Selection & Justification", "Base Image Build", "Package Management",
        "Init & Service Supervision", "User Session Bootstrap", "Filesystem Layout",
        "Kernel Module Management", "Hardware Detection", "Network Bootstrap",
        "System Update Mechanism"]),
    ("Phase 2 — Security Kernel & PEP Fabric", [
        "Capability Model", "PEP Decision Engine", "Grant Lifecycle",
        "Audit Chain Extensions", "Sandbox Enforcement", "Privilege Escalation Prevention",
        "Secrets Handling", "Threat Model Maintenance", "Compliance Mapping",
        "Incident Response Runbooks"]),
    ("Phase 3 — AI Control Plane (Pillar C Spine)", [
        "MCP Server Core", "Model Backend Adapters", "Agent Loop Hardening",
        "Tool Registry & Taxonomy", "Context & Episodic Memory",
        "Prompt-Injection Defense", "Policy Bridge (PEP↔AI)", "Session Isolation",
        "Long-Horizon Tasking", "Evaluation Harness"]),
    ("Phase 4 — Pillar A: Ethical Hacking Toolchain", [
        "Reconnaissance Tools", "Vulnerability Scanning", "Exploitation Frameworks",
        "Password Auditing", "Wireless Auditing", "Web Application Testing",
        "Network Traffic Analysis", "Forensics & Evidence", "Engagement Reporting",
        "Engagement Workflow & Consent"]),
    ("Phase 5 — Pillar B: Windows-Style Desktop", [
        "Desktop Shell (KDE Plasma)", "Window Management Behavior", "Taskbar & Launcher",
        "Settings Application", "File Manager Experience", "Terminal Integration",
        "Windows-Look Theme Engine", "Accessibility", "Win App Compatibility (Wine/Proton)",
        "GUI Session Security"]),
    ("Phase 6 — AI Kernel-Level Control Integration", [
        "Syscall Mediation", "Process Policy Hooks", "File Access Governance",
        "Network Egress Control", "Device Control", "Secure Boot Chain",
        "Kernel Observability", "AI Decision Logging", "Fail-Safe Modes",
        "Trusted Path & Consent UI"]),
    ("Phase 7 — Storage, Networking, Devices", [
        "Storage Layout & Encryption", "Backup & Snapshots", "Network Manager",
        "VPN & Tunnels", "Firewall Policy", "Peripherals", "Display & Input Stack",
        "Virtualization Support", "Container Support", "Remote Access"]),
    ("Phase 8 — Reliability, Observability, Performance", [
        "Metrics Collection", "Log Pipeline", "Trace Correlation", "Crash Recovery",
        "Health Checks", "Performance Baselines", "Resource Limits", "Chaos Testing",
        "Upgrade Safety", "Support Diagnostics"]),
    ("Phase 9 — Release, Certification, User Docs", [
        "Release Engineering", "Artifact Signing", "Installer Media", "User Onboarding",
        "Administrator Guide", "Security Certification Pack", "Pentest Readiness",
        "Accessibility Review", "Localization", "Public Roadmap & Changelog"]),
]

COMPONENTS = ["data model", "core service", "CLI surface", "MCP/API surface",
              "configuration", "automated tests", "security policy",
              "observability", "documentation", "recovery & validation"]

TASK_TYPES = [
    ("Research",
     "Establish facts, constraints, and prior art for the {component} of {epic}.",
     ["Read the existing code and docs related to {component} before assuming anything is missing.",
      "Collect authoritative sources (upstream docs, man pages, RFCs) and record fact vs assumption.",
      "Write findings to docs/tasks/evidence/T-{task_id:05d}-research.md with citations.",
      "List unknowns and decisions needed before any implementation task."],
     ["Evidence file exists and separates facts from assumptions.",
      "No code changed; decisions needed are listed explicitly."]),
    ("Specification",
     "Specify the exact contract for the {component} of {epic}.",
     ["Define inputs, outputs, error cases, and persistence effects for {component}.",
      "State which existing interfaces are reused and which are new.",
      "Write the spec section to docs/tasks/evidence/T-{task_id:05d}-spec.md.",
      "Do not invent APIs that do not exist upstream; mark any proposal as AIOS-specific."],
     ["Spec covers happy path, failure path, and audit effects.",
      "Spec is reviewable without reading the implementation."]),
    ("Scaffold",
     "Create the module skeleton and interfaces for the {component} of {epic}.",
     ["Create or extend the appropriate source file(s) under code/ following existing module style.",
      "Define typed function signatures / interfaces only; bodies fail loudly (throw/NotImplementedError).",
      "Wire exports/imports so the project still compiles or imports cleanly.",
      "Run the build (npm run build / python -c import) and fix all errors."],
     ["Project builds/imports with zero errors.",
      "New interfaces exist and are referenced by at least one call site or test stub."]),
    ("Implementation",
     "Implement the minimal working behavior for the {component} of {epic}.",
     ["Write a failing test first where feasible (smoke or unit).",
      "Implement the smallest change that passes; follow existing patterns in code/aiosh-cli and code/aiosh-mcp.",
      "Reuse existing helpers (audit ring, dispatch gate, classifier) instead of duplicating logic.",
      "Do not add new dependencies unless the Research task for this epic approved one.",
      "Keep all audit/PEP invariants: consequential actions write exactly one audit row."],
     ["Targeted test passes.",
      "No regression in existing smoke suites for touched modules."]),
    ("Unit Test",
     "Add focused automated tests for the {component} of {epic}.",
     ["Cover: valid input, invalid input, boundary values, and the primary failure mode.",
      "Add tests under the matching tests/ directory using the existing smoke-test style.",
      "Assert observable behavior (return values, DB state, files), not implementation details.",
      "Run the new test file in isolation and confirm it fails when the feature is broken."],
     ["New test file runs standalone and passes.",
      "Negative cases are asserted, not just happy path."]),
    ("Integration",
     "Integrate the {component} of {epic} with the surrounding system.",
     ["Wire the feature into its real call path (CLI command, MCP tool, or service hook).",
      "Confirm cross-substrate parity where the feature touches the shared SQLite DB or canonical JSON.",
      "Update the relevant server/CLI registration point so the surface is discoverable.",
      "Run the closest existing smoke suite that exercises the integrated path."],
     ["Feature reachable through its production surface.",
      "Integration smoke passes end-to-end."]),
    ("Security Review",
     "Security-review the {component} of {epic}.",
     ["Check input validation, path/argument injection, and untrusted-content handling.",
      "Verify PEP gating and audit-row emission for every state-changing path.",
      "Document abuse scenarios in docs/tasks/evidence/T-{task_id:05d}-security.md.",
      "If any scenario bypasses policy, create a blocking note and fix before proceeding."],
     ["Security evidence file exists with abuse scenarios.",
      "No known policy bypass remains open."]),
    ("Hardening",
     "Harden the {component} of {epic} against failure and misuse.",
     ["Add timeouts, size caps, and bounded retries where external processes or files are involved.",
      "Ensure errors are reported in the standard result envelope (never silent failure).",
      "Confirm resource cleanup (DB connections, temp files, child processes).",
      "Fail-open behavior must always write an honest audit row (per ADR-0035 §F-2)."],
     ["Failure modes produce explicit, auditable errors.",
      "No temp/connection leaks on the error path."]),
    ("Documentation",
     "Document the {component} of {epic} for operators and agents.",
     ["Update the relevant README/spec with what shipped and how to invoke it.",
      "Include at least one copy-pasteable example command or tool call.",
      "Record constraints and known limitations honestly.",
      "Link the task evidence files from the doc."],
     ["Docs updated with working example.",
      "Limitations are stated, not omitted."]),
    ("Verification & Evidence",
     "Verify the {component} of {epic} and close the task with evidence.",
     ["Run all test suites relevant to this epic plus the full baseline smoke set.",
      "Capture PASS output into docs/tasks/evidence/T-{task_id:05d}-verify.md.",
      "Update task_plan.md / progress.md if this task completes a milestone.",
      "Only then mark the task complete and advance to the next numeric task."],
     ["Full relevant suite green with captured output.",
      "State files updated; next task pointer advanced."]),
]

def slug(s, n=60):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:n]

CUSTOM = [
    (1, "Mission lock + sequential execution law",
     "Confirm the project mission and create the binding no-skip task law.",
     ["Read START_HERE.md, PROJECT_MANIFEST.yaml, AI_CONSTITUTION.md, ADR-0035, ADR-0036.",
      "Create docs/tasks/GOALS.md with the mission, pillars, and execution law.",
      "Record that tasks execute strictly in numeric order (task N+1 only after N done)."],
     ["docs/tasks/GOALS.md exists and states the no-skip rule."], "done"),
    (2, "Environment + baseline verification",
     "Prove the toolchain and all existing smoke suites are green before new work.",
     ["Install/verify python deps (pip install -e code/aiosh-mcp) and node deps.",
      "Run all existing smokes: classifier, mcp, pentest, sandbox, demo, cli bash.",
      "Record PASS output in docs/tasks/evidence/T-00002-baseline.md."],
     ["All baseline suites PASS; evidence captured."], "done"),
    (3, "Generate canonical 10,000-task ledger",
     "Create the machine-readable sequential ledger and live task pointer.",
     ["Run tools/generate_master_tasks.py to produce MASTER_TASK_LEDGER.jsonl + TASK_STATE.json.",
      "Verify exactly 10,000 tasks, IDs T-00001..T-10000, each with instructions + acceptance.",
      "Verify next_task pointer equals 4."],
     ["Ledger has 10,000 well-formed tasks; pointer file exists."], "done"),
    (4, "Create fail-fast CI runner",
     "Give the project one command that runs every smoke suite sequentially and fails loudly.",
     ["Create ci/run_all_smokes.sh invoking each suite in order with set -euo pipefail.",
      "Print a per-suite PASS/FAIL summary and exit non-zero on any failure.",
      "Make it executable and run it once; capture output as evidence."],
     ["bash ci/run_all_smokes.sh exits 0 with all suites PASS."], "ready"),
    (5, "Task-state completion tool",
     "Provide a single command to mark the active task complete and advance the pointer.",
     ["Create tools/complete_task.py <task_id>: validate task_id == current next_task.",
      "On success, move task to completed set and increment next_task by exactly 1.",
      "Refuse out-of-order completion (this mechanically enforces the no-skip law)."],
     ["complete_task.py rejects wrong-order IDs and advances pointer correctly."], "pending"),
    (6, "Index task system from README",
     "Make the task ledger discoverable from the repo entry points.",
     ["Add a short section to README.md and docs/README.md pointing at docs/tasks/.",
      "State the rule: agents must read TASK_STATE.json and execute only next_task."],
     ["README links the ledger and states the no-skip rule."], "pending"),
    (7, "Retention operations runbook",
     "Document day-2 operations for the Sprint-3 retention system.",
     ["Write docs/RUNBOOK-AUDIT-RETENTION.md covering rotate, verify --full, seen, disaster recovery.",
      "Include copy-paste CLI + MCP examples and what each alarm means."],
     ["Runbook exists with working examples for all four operations."], "pending"),
    (8, "Backup & sync verification",
     "Prove the Drive/R2 backup path captures the current tree reproducibly.",
     ["Re-create the AIOS_MERGED.zip snapshot and verify key files byte-match the tree.",
      "Record the procedure + checksums in docs/tasks/evidence/T-00008-backup.md."],
     ["Backup archive verified; procedure documented."], "pending"),
    (9, "Retention security review",
     "Threat-model the rotation/archive/seen surfaces shipped in Sprint 3.",
     ["Review rotate/seen/verify_full for injection, path traversal, and covert-erasure abuse.",
      "Confirm MCP rotate requires grant and refusal rows are written.",
      "Record findings in docs/tasks/evidence/T-00009-security.md."],
     ["Security review evidence file exists; no open bypass."], "pending"),
    (10, "Audit-ring performance baseline",
     "Measure verify/rotate cost at 10k and 100k rows to size retention cadence.",
     ["Generate synthetic rings (10k, 100k rows) in a temp DB; time verify and verify --full.",
      "Record numbers + recommended rotation cadence in docs/tasks/evidence/T-00010-perf.md."],
     ["Benchmark table exists with a recommended max live-row threshold."], "pending"),
]

def make_custom(tid, title, goal, ins, acc, status):
    return {
        "id": tid, "title": title, "phase": PHASES[0][0], "status": status,
        "goal": goal, "instructions": ins, "acceptance": acc,
        "artifacts": [f"docs/tasks/evidence/T-{tid:05d}.md"],
    }


def build_component_tasks(phase, epic, components, start_id,
                          pre=(), post=(), focus=None):
    """Expand epic x components x TASK_TYPES into ledger task dicts.

    Shared by the original generator and tools/ledger_insert_block.py so
    inserted feature blocks follow the exact same REP 10-step shape.
    `pre`/`post` are extra instruction lines (templated like TASK_TYPES)
    placed before/after each task's standard instructions; `focus` maps
    component -> one extra instruction line. depends_on/next_task are
    NOT set here (the caller relinks the whole ledger).
    """
    out = []
    tid = start_id
    for comp in components:
        for (tname, goal_t, ins_t, acc_t) in TASK_TYPES:
            ctx = {"component": comp, "epic": epic, "phase": phase, "task_id": tid}
            ins = [s.format(**ctx) for s in pre]
            ins += [s.format(**ctx) for s in ins_t]
            if focus and comp in focus:
                ins.append(focus[comp].format(**ctx))
            ins += [s.format(**ctx) for s in post]
            out.append({
                "id": tid,
                "title": f"{phase} / {epic} / {comp}: {tname}",
                "phase": phase, "status": "pending",
                "goal": goal_t.format(**ctx),
                "instructions": ins,
                "acceptance": [s.format(**ctx) for s in acc_t],
                "artifacts": [f"docs/tasks/evidence/T-{tid:05d}-{slug(comp)}-{slug(tname,20)}.md"],
            })
            tid += 1
    return out


def main(argv=None):
    import sys
    argv = sys.argv[1:] if argv is None else argv
    ledger_path = os.path.join(OUT, "MASTER_TASK_LEDGER.jsonl")
    # Guard: the ledger is now amended in place (tools/ledger_insert_block.py)
    # and carries real completion statuses. Regenerating would silently
    # reset all of that, so require an explicit --force.
    if os.path.exists(ledger_path) and "--force" not in argv:
        print("refusing to overwrite existing ledger (has live progress and "
              "inserted feature blocks). Use tools/ledger_insert_block.py to "
              "amend it, or pass --force to regenerate from scratch.")
        return 2

    tasks = []
    for (tid, title, goal, ins, acc, status) in CUSTOM:
        tasks.append(make_custom(tid, title, goal, ins, acc, status))

    next_id = 11
    for pi, (phase, epics) in enumerate(PHASES):
        need = 990 if pi == 0 else 1000
        made = 0
        for epic in epics:
            for comp in COMPONENTS:
                for (tname, goal_t, ins_t, acc_t) in TASK_TYPES:
                    if made >= need:
                        break
                    ctx = {"component": comp, "epic": epic, "phase": phase, "task_id": next_id}
                    t = {
                        "id": next_id,
                        "title": f"{phase} / {epic} / {comp}: {tname}",
                        "phase": phase, "status": "pending",
                        "goal": goal_t.format(**ctx),
                        "instructions": [s.format(**ctx) for s in ins_t],
                        "acceptance": [s.format(**ctx) for s in acc_t],
                        "artifacts": [f"docs/tasks/evidence/T-{next_id:05d}-{slug(comp)}-{slug(tname,20)}.md"],
                    }
                    tasks.append(t)
                    next_id += 1
                    made += 1
                if made >= need:
                    break
            if made >= need:
                break

    assert len(tasks) == 10000, f"expected 10000, got {len(tasks)}"

    for i, t in enumerate(tasks):
        t["depends_on"] = [tasks[i-1]["id"]] if i > 0 else []
        t["next_task"] = tasks[i+1]["id"] if i + 1 < len(tasks) else None

    with open(ledger_path, "w", encoding="utf-8") as f:
        for t in tasks:
            f.write(json.dumps(t, ensure_ascii=False, separators=(",", ":")) + "\n")

    phase_ranges = {}
    for t in tasks:
        phase_ranges.setdefault(t["phase"], [t["id"], t["id"]])[1] = t["id"]

    md = []
    md.append("# MASTER TASK LEDGER — 10,000 sequential tasks\n")
    md.append("**Law:** execute strictly in numeric order. Task N+1 starts only when task N is complete.")
    md.append("Never jump to a later task. If blocked, record the blocker and stop.\n")
    md.append("Full machine-readable ledger: `MASTER_TASK_LEDGER.jsonl` (one task per line).")
    md.append("Live pointer: `TASK_STATE.json` (`next_task` = the only task allowed to start).\n")
    md.append("## Phase map\n")
    md.append("| Phase | Task range |")
    md.append("|---|---|")
    for ph, (lo, hi) in phase_ranges.items():
        md.append(f"| {ph} | T-{lo:05d} .. T-{hi:05d} |")
    md.append("\n## First 25 tasks (detail)\n")
    for t in tasks[:25]:
        md.append(f"### T-{t['id']:05d} — {t['title']}  `[{t['status']}]`")
        md.append(f"**Goal:** {t['goal']}")
        md.append("**Instructions:**")
        for s in t["instructions"]:
            md.append(f"- {s}")
        md.append("**Acceptance:**")
        for s in t["acceptance"]:
            md.append(f"- {s}")
        md.append("")
    with open(os.path.join(OUT, "MASTER_TASK_LEDGER.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    state = {
        "ledger": "docs/tasks/MASTER_TASK_LEDGER.jsonl",
        "total_tasks": len(tasks),
        "next_task": 4,
        "completed": [1, 2, 3],
        "rule": "Execute ONLY next_task. On completion run tools/complete_task.py <id> to advance by exactly 1. Never skip.",
    }
    with open(os.path.join(OUT, "TASK_STATE.json"), "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

    print(f"generated {len(tasks)} tasks; next_task={state['next_task']}")
    print("phase ranges:")
    for ph, (lo, hi) in phase_ranges.items():
        print(f"  T-{lo:05d}..T-{hi:05d}  {ph}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
