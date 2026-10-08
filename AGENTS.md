# Agent instructions — AIOS

## Shipping a ledger task (since T-02899)

Every task in `docs/tasks/MASTER_TASK_LEDGER.jsonl` ships as **one merged
pull request**, not a direct push to `main`:

```bash
git checkout -b task/tNNNN-slug main
# ... implement, write evidence, then:
python3 tools/complete_task.py done NNNN --note "..." --evidence docs/tasks/evidence/...
python3 tools/task_pr.py "T-NNNN: <task title>"
```

Why: GitHub's **Pair Extraordinaire** achievement (gold = 48) only credits
an account listed in a `Co-authored-by:` trailer of a commit inside a
**merged PR** (community discussion #208463), and **Pull Shark** credits the
PR opener. Direct pushes earn neither. `tools/task_pr.py` therefore commits
**authored by Codebuff** with a `Co-Authored-By: Habibullah485044
<310129783+Habibullah485044@users.noreply.github.com>` trailer, opens the PR
with the stored credential (owner = PR author), merges with a merge commit,
then returns to `main` and deletes the branch.

Rules:

- Never direct-push task commits to `main`; use `tools/task_pr.py`.
- Never change the co-author trailer to a username-based noreply address —
  the ID form (`310129783+...`) survives account renames.
- Keep one task = one PR = one merge commit (reviewable history).
- If `task_pr.py` fails after committing, the work is safe on the branch;
  re-run it or open the PR manually — do not reset the branch.
- Achievement counters on the profile refresh every 24–48 h:
  <https://github.com/Habibullah485044?tab=achievements>

## Standing task loop

- Ledger: `docs/tasks/MASTER_TASK_LEDGER.jsonl`; state: `docs/tasks/TASK_STATE.json`.
- Complete with `python3 tools/complete_task.py done NNNN --note "..." --evidence <path>`
  (evidence file must exist first; `tools/check_evidence.py` must pass).
- Run the relevant test suites before shipping; a green build is required,
  not optional.
