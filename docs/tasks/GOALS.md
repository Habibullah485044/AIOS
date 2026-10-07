# AIOS — Mission, Goal, and Sequential Execution Law

**Version:** 1.0 (2026-08-21) — binding for every agent session.

## Main goal (mission)

Build **AIOS**: a Linux system for **ethical hacking on the inside**, a
**Windows-style desktop on the outside**, with **AI as a first-class
S-rank kernel subsystem** that controls the whole system.

Three pillars drive every decision (v2 framing, `PROJECT_MANIFEST.yaml`):

- **Pillar A — Linux ethical-hacking platform** (foundation, kernel-side)
- **Pillar B — Windows-style desktop** (surface, user-facing)
- **Pillar C — AI as S-rank first-class kernel subsystem** (cross-cutting,
  controls both, critical-path priority)

## Governing documents (precedence order)

1. `mostimportanAIfolder/AI_CONSTITUTION.md` (P-1..P-6, O-1..O-5, C-1..C-4)
2. `mostimportanAIfolder/ADR-0035-aios-s-rank-agent-architecture.md`
3. `mostimportanAIfolder/ADR-0036-audit-ring-retention.md`
4. `mostimportanAIfolder/MASTER_PROJECT_EXECUTION_PROTOCOL.md`
5. `mostimportanAIfolder/RESEARCH_EXECUTION_PROTOCOL.md`
6. `task_plan.md` (live sprint state)

## Sequential execution law (NO SKIP)

All work is driven by `docs/tasks/MASTER_TASK_LEDGER.jsonl`
(T-00001 .. T-10000) and the live pointer `docs/tasks/TASK_STATE.json`.

1. **Only `next_task` may be started.** Task N+1 begins only after task N
   is marked complete. Jumping to task 56 or 89 while task 2 is undone is
   forbidden — this is the failure mode this law exists to prevent.
2. **Completion is mechanical:** run `python3 tools/complete_task.py <id>`.
   The tool refuses any `id` that is not the current `next_task`, advances
   the pointer by exactly one, and appends one event to
   `docs/tasks/COMPLETIONS.jsonl` (append-only event log; the pointer file
   is derived state and can be rebuilt with
   `python3 tools/task_ledger.py rebuild`).
   Full surface: `python3 tools/task_ledger.py {done|block|unblock|skip|rebuild|check|status}`.
3. **Every task carries its own instructions and acceptance criteria.**
   Follow the task's `instructions` list; prove the `acceptance` list
   before completing; write evidence under `docs/tasks/evidence/`.
4. **Research before implementation** (REP): each component runs
   Research → Specification → Scaffold → Implementation → Unit Test →
   Integration → Security Review → Hardening → Documentation →
   Verification, in that order, as separate sequential tasks.
5. **If blocked:** record the blocker in `docs/tasks/evidence/`, stop, and
   report. Do not silently skip to a later task.
6. **Baseline gate:** before ANY implementation task, the smoke suites must
   be green (`bash ci/run_all_smokes.sh`). Never regress the chain
   invariants (canonical-JSON cross-substrate, audit hash chain, PEP gate).

## What is already done (do not redo)

- Sprint 0: CLI + MCP + hash-chained audit ring + cross-substrate invariant
- Sprint 1: 5 pentest wrappers (nmap, nikto, sqlmap, tshark, aircrack-ng)
- Sprint 1.5: deterministic rule-pack classifier (R-01..R-12)
- Sprint 2: classifier-gated agent loop over MCP (Ollama + stub)
- Sprint 3 item 1: **audit-ring retention** (checkpointed rotation + bloom
  filter, ADR-0036, `test_retention_smoke.py` R1–R7)
- Proof of Restraint **SHIPPED** (ADR-0037, T-02831..T-02892): mint ->
  anchor -> prove -> verify chain with signed Ed25519 checkpoints, Bloom
  absence proofs, zero-DB standalone verifier, and the `por_conformance`
  CI gate (docs/proof-of-restraint/PLAN.md). Status: Shipped - maintained
  by standing rules.

## Next queue (from task_plan.md)

1. Formalize `aiosh demo` snap test into the CI suite
2. Expand the five pentest wrappers toward the full Kali / MITRE ATT&CK
   v19 taxonomy
3. Continue through the ledger in strict numeric order
