#!/usr/bin/env python3
"""Ship the current task branch as one merged pull request.

Why this exists (AGENTS.md has the short version):
  GitHub's *Pair Extraordinaire* achievement only credits an account listed
  in a ``Co-authored-by:`` trailer of a commit included in a **merged** pull
  request (GitHub community discussion #208463), and *Pull Shark* credits
  the account that **opens** the merged PR.  Direct pushes to ``main`` earn
  neither, so since T-02899 every ledger task ships through this script:

      git checkout -b task/tNNNN-slug main
      ... do the task, run tools/complete_task.py ...
      python3 tools/task_pr.py "T-NNNN: <task title>"

What it does:
  1. refuses to run on ``main`` or with a clean tree, stages every change,
  2. commits it **authored by Codebuff** (the agent that wrote the change)
     and **co-authored by the repository owner** via their ID-based noreply
     address (stable across username renames),
  3. pushes the branch and opens a PR with the owner's stored GitHub
     credential (owner = PR author -> Pull Shark credit),
  4. merges with a merge commit (keeps every commit + trailer on ``main``),
  5. returns to ``main``, fast-forwards, and deletes the branch.

The GitHub token is read from ``git credential fill`` and is never printed
or written to disk (curl receives it on stdin via ``-K -``).

If a step fails after the commit exists, the work stays safe on the branch:
re-run the script or open the PR manually.  Achievement counters on the
profile refresh every 24-48 h.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BRANCH = "main"
AGENT_NAME = "Codebuff"
AGENT_EMAIL = "noreply@codebuff.com"
#: Account 310129783 = Habibullah485044; ID-based noreply survives renames.
CO_AUTHOR_TRAILER = (
    "Co-Authored-By: Habibullah485044 "
    "<310129783+Habibullah485044@users.noreply.github.com>"
)
API = "https://api.github.com"


def git(*args: str, check: bool = True, env: dict | None = None) -> str:
    p = subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                       text=True, env=env)
    if check and p.returncode != 0:
        sys.exit(f"[-] git {' '.join(args)} failed:\n{p.stderr.strip()}")
    return p.stdout.strip()


def github_slug() -> str:
    url = git("remote", "get-url", "origin")
    marker = "github.com/"
    if marker not in url:
        sys.exit(f"[-] remote is not on github.com: {url}")
    return url.split(marker, 1)[1].rstrip("/").removesuffix(".git")


def github_token() -> str:
    p = subprocess.run(["git", "credential", "fill"],
                       input="protocol=https\nhost=github.com\n\n",
                       capture_output=True, text=True, cwd=ROOT)
    for line in p.stdout.splitlines():
        if line.startswith("password=") and len(line) > len("password="):
            return line[len("password="):]
    sys.exit("[-] no stored github credential; push once first (credential helper)")


def api(token: str, method: str, path: str, payload: dict | None = None) -> dict:
    cmd = ["curl", "-sS", "-o", "-", "-w", "\n%{http_code}",
           "-X", method, "-K", "-",
           "-H", "Accept: application/vnd.github+json",
           "-H", "X-GitHub-Api-Version: 2022-11-28"]
    if payload is not None:
        cmd += ["--data-binary", json.dumps(payload)]
    cmd.append(f"{API}{path}")

    for attempt in range(4):
        p = subprocess.run(cmd, input=f'header = "Authorization: Bearer {token}"\n',
                           capture_output=True, text=True, cwd=ROOT)
        if p.returncode != 0:
            if attempt < 3:
                time.sleep(2 ** attempt)
                continue
            sys.exit(f"[-] curl {method} {path} failed: {p.stderr.strip()}")
        body, _, code = p.stdout.rpartition("\n")
        if code.startswith("5") and attempt < 3:
            time.sleep(2 ** attempt)
            continue
        try:
            data = json.loads(body) if body.strip() else {}
        except json.JSONDecodeError:
            sys.exit(f"[-] {method} {path}: non-JSON response (HTTP {code}): {body[:300]}")
        if not code.startswith("2"):
            msg = data.get("message", body[:200]) if isinstance(data, dict) else body[:200]
            sys.exit(f"[-] {method} {path} -> HTTP {code}: {msg}")
        return data
    sys.exit(f"[-] {method} {path} failed after retries")


def commit_message(title: str, body: str | None) -> str:
    msg = title.strip() + "\n"
    if body:
        msg += "\n" + body.strip() + "\n"
    msg += ("\nGenerated with Codebuff \U0001f916\n"
            f"Co-Authored-By: {AGENT_NAME} <{AGENT_EMAIL}>\n"
            f"{CO_AUTHOR_TRAILER}\n")
    return msg


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Ship the current task branch as one merged pull request.")
    ap.add_argument("title", help='PR/commit title, e.g. "T-02899: ..."')
    ap.add_argument("--body", default=None, help="optional PR body text")
    ap.add_argument("--keep-branch", action="store_true",
                    help="do not delete the branch locally or on the remote")
    ap.add_argument("--dry-run", action="store_true",
                    help="stage + show what would ship, then stop")
    args = ap.parse_args()

    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    if branch == DEFAULT_BRANCH:
        sys.exit(f"[-] on {DEFAULT_BRANCH}: create the task branch first "
                 f"(git checkout -b task/... {DEFAULT_BRANCH})")
    if git("status", "--porcelain"):
        git("add", "-A")
        staged = subprocess.run(["git", "diff", "--cached", "--quiet"],
                                cwd=ROOT)
        if staged.returncode == 0:
            sys.exit("[-] nothing staged (index already matches HEAD)")

        msg = commit_message(args.title, args.body)
        if args.dry_run:
            print("[dry-run] would commit:")
            print(git("diff", "--cached", "--stat"))
            print("---- message ----")
            print(msg)
            return 0

        env = os.environ | {
            "GIT_AUTHOR_NAME": AGENT_NAME,
            "GIT_AUTHOR_EMAIL": AGENT_EMAIL,
            "GIT_COMMITTER_NAME": AGENT_NAME,
            "GIT_COMMITTER_EMAIL": AGENT_EMAIL,
        }
        git("commit", "-m", msg, env=env)
        sha = git("rev-parse", "--short", "HEAD")
        print(f"[+] committed {sha} as {AGENT_NAME} <{AGENT_EMAIL}> + owner co-author")
    else:
        ahead = git("rev-list", f"origin/{DEFAULT_BRANCH}..HEAD", "--count")
        if ahead == "0":
            sys.exit("[-] nothing to ship (clean tree and not ahead of origin/main)")
        print(f"[+] working tree clean; branch is already committed ({ahead} commit ahead of origin/{DEFAULT_BRANCH})")

    git("push", "-u", "origin", branch)
    print(f"[+] pushed origin/{branch}")

    token = github_token()
    slug = github_slug()
    owner = slug.split("/")[0]
    existing = api(token, "GET", f"/repos/{slug}/pulls?head={owner}:{branch}&state=open")
    if isinstance(existing, list) and existing:
        pr = existing[0]
        print(f"[+] using existing open PR #{pr['number']}: {pr['html_url']}")
    else:
        pr = api(token, "POST", f"/repos/{slug}/pulls", {
            "title": args.title,
            "head": branch,
            "base": DEFAULT_BRANCH,
            "body": args.body or
                    "Task shipped through `tools/task_pr.py` (see AGENTS.md).\n"
                    "Commits are authored by the agent and co-authored by the "
                    "repository owner.",
        })
        print(f"[+] opened PR #{pr['number']}: {pr['html_url']}")

    merged = api(token, "PUT", f"/repos/{slug}/pulls/{pr['number']}/merge",
                 {"merge_method": "merge"})
    if not merged.get("merged"):
        sys.exit(f"[-] PR #{pr['number']} not merged "
                 f"({merged.get('message', 'unknown reason')}); "
                 f"work is safe on branch {branch!r} - merge it manually, then "
                 f"re-run without the commit step.")
    print(f"[+] merged PR #{pr['number']} ({merged.get('sha', '')[:7]})")

    git("checkout", DEFAULT_BRANCH)
    try:
        git("pull", "--ff-only", "origin", DEFAULT_BRANCH)
    except Exception:
        time.sleep(1)
        git("fetch", "origin", DEFAULT_BRANCH)
        git("reset", "--hard", f"origin/{DEFAULT_BRANCH}")
    if not args.keep_branch:
        git("branch", "-D", branch, check=False)
        subprocess.run(["git", "push", "origin", "--delete", branch],
                       cwd=ROOT, capture_output=True, text=True)
        print(f"[+] back on {DEFAULT_BRANCH} (fast-forwarded), branch deleted")
    else:
        print(f"[+] back on {DEFAULT_BRANCH} (fast-forwarded), branch kept")

    print("[+] Pair Extraordinaire / Pull Shark counters refresh in 24-48 h:\n"
          "    https://github.com/Habibullah485044?tab=achievements")
    return 0


if __name__ == "__main__":
    sys.exit(main())
