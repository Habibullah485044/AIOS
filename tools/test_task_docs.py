#!/usr/bin/env python3
"""Behavioral unit tests for tools/check_task_docs.py (T-00095).

Style parity: tools/test_task_ledger.py (PASS/FAIL lines, exit code,
isolated temp fixtures). The checker reads module-level artifact paths,
so each case injects fixture paths by rebinding module attributes and
restores them afterwards — production signatures untouched.

Coverage:
  U01/U02/U03  C1 ok / missing SPEC / TODO marker        (valid·invalid)
  U04/U05/U06  C2 ok / missing section / wrong range     (valid·invalid)
  U07/U08/U09  C3 fenced-path ignored / missing flagged /
               placeholder ignored                       (boundary)
  U10          strip_fenced_blocks unterminated fence     (boundary)
  U11/U12      C4 ok / range mismatch                     (valid·failure)
  U13/U14/U15  C5 ok / TODO / broken link                 (valid·invalid)
  U16/U17      C6 ok / volatile count flagged             (valid·failure)
  S1           sensitivity: blinding C6 must be detectable (broken-feature)

Primary failure mode of a CHECKER is silent blindness — S1 proves the
suite catches it.
"""

import importlib.util
import json
import os
import re
import shutil
import sys

# T-02902: pin stdout/stderr to UTF-8 — this suite prints non-ASCII
# markers that the Windows ANSI codepage (cp1252) cannot encode.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
import tempfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.join(HERE, "check_task_docs.py")

spec = importlib.util.spec_from_file_location("check_task_docs_ut", MOD)
cd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cd)

PASS, FAIL = "[✓]", "[✗]"
RESULTS = []


def check(label, ok, detail=""):
    print(f"{PASS if ok else FAIL} {label}" + (f"\n    {detail}" if detail and not ok else ""))
    RESULTS.append((label, ok))


class Sandbox:
    """Temp docs-tree + module rebinding, restored on exit."""

    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="task-docs-ut-")
        self.docs = os.path.join(self.tmp, "docs")
        os.makedirs(os.path.join(self.docs, "tasks"))
        self.saved = {}

    def write(self, rel, text):
        p = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def bind(self):
        for name, val in (("ROOT", Path(self.tmp)),
                          ("SPEC", Path(self.tmp) / "docs/SPEC-TASK-LEDGER.md"),
                          ("INDEX_MD", Path(self.tmp) / "docs/tasks/MASTER_TASK_LEDGER.md"),
                          ("LEDGER_JSONL", Path(self.tmp) / "docs/tasks/MASTER_TASK_LEDGER.jsonl"),
                          ("GOALS", Path(self.tmp) / "docs/tasks/GOALS.md"),
                          ("DOCS_README", Path(self.tmp) / "docs/README.md")):
            self.saved[name] = getattr(cd, name)
            setattr(cd, name, val)

    def close(self):
        for name, val in self.saved.items():
            setattr(cd, name, val)
        shutil.rmtree(self.tmp, ignore_errors=True)


def six_headings():
    return "".join(
        f"### {sec} — component ({rng})\ntext\n"
        for sec, rng in cd.COMPONENT_SECTIONS.items())


def two_phase_ledger():
    lines = [
        {"id": 1, "phase": "Phase 0 — Alpha"},
        {"id": 2, "phase": "Phase 0 — Alpha"},
        {"id": 3, "phase": "Phase 1 — Beta"},
    ]
    return "".join(json.dumps(l) + "\n" for l in lines)


def main() -> int:
    # ---- C1 --------------------------------------------------------------
    s = Sandbox(); s.bind()
    try:
        s.write("docs/SPEC-TASK-LEDGER.md", "# spec\nclean\n")
        ok, _ = cd.check_c1_spec_exists()
        check("U01 C1 ok on pristine spec", ok)

        os.remove(cd.SPEC)  # fixture path only — never the production file
        ok, d = cd.check_c1_spec_exists()
        check("U02 C1 fails on missing SPEC", not ok and "missing" in d, d)

        s.write("docs/SPEC-TASK-LEDGER.md", "# spec\nTODO fix later\n")
        ok, d = cd.check_c1_spec_exists()
        check("U03 C1 fails on TODO marker", not ok and "TODO" in d, d)
    finally:
        s.close()

    # ---- C2 --------------------------------------------------------------
    s = Sandbox(); s.bind()
    try:
        s.write("docs/SPEC-TASK-LEDGER.md", six_headings())
        ok, d = cd.check_c2_component_sections()
        check("U04 C2 ok with all six sections+ranges", ok, d)

        s.write("docs/SPEC-TASK-LEDGER.md",
                six_headings().replace("### 8.4", "### 9.4"))
        ok, d = cd.check_c2_component_sections()
        check("U05 C2 fails when a heading is absent",
              not ok and "8.4" in d, d)

        s.write("docs/SPEC-TASK-LEDGER.md",
                six_headings().replace("(T-00061..T-00070)", "(T-00999..T-01000)"))
        ok, d = cd.check_c2_component_sections()
        check("U06 C2 fails on wrong frozen range",
              not ok and "T-00061..T-00070" in d, d)
    finally:
        s.close()

    # ---- C3 + fences -----------------------------------------------------
    s = Sandbox(); s.bind()
    try:
        body = ("# spec\n"
                "```bash\ncat docs/definitely/not/here.bin\n```\n"
                f"### 8.1 x ({cd.COMPONENT_SECTIONS['8.1']})\n")
        s.write("docs/SPEC-TASK-LEDGER.md", body)
        ok, d = cd.check_c3_referenced_paths()
        check("U07 C3 ignores paths inside fenced blocks", ok, d)

        s.write("docs/SPEC-TASK-LEDGER.md",
                body + "\nsee `docs/void/ghost.md` for details\n")
        ok, d = cd.check_c3_referenced_paths()
        check("U08 C3 flags missing referenced path outside fence",
              not ok and "docs/void/ghost.md" in d, d)

        s.write("docs/SPEC-TASK-LEDGER.md",
                body + "\nexample: `docs/tasks/evidence/x.md`\n")
        ok, d = cd.check_c3_referenced_paths()
        check("U09 C3 ignores documented placeholder x.md", ok, d)

        out = cd.strip_fenced_blocks("a```b\nc\nd")
        check("U10 unterminated fence strips to EOF", out == "a", repr(out))
    finally:
        s.close()

    # ---- C4 --------------------------------------------------------------
    s = Sandbox(); s.bind()
    try:
        s.write("docs/tasks/MASTER_TASK_LEDGER.jsonl", two_phase_ledger())
        s.write("docs/tasks/MASTER_TASK_LEDGER.md",
                "| Phase | Task range |\n|---|---|\n"
                "| Phase 0 — Alpha | T-00001 .. T-00002 |\n"
                "| Phase 1 — Beta | T-00003 .. T-00003 |\n")
        ok, d = cd.check_c4_phase_map()
        check("U11 C4 ok on consistent mini map", ok, d)

        s.write("docs/tasks/MASTER_TASK_LEDGER.md",
                "| Phase | Task range |\n|---|---|\n"
                "| Phase 0 — Alpha | T-00001 .. T-00099 |\n"
                "| Phase 1 — Beta | T-00003 .. T-00003 |\n")
        ok, d = cd.check_c4_phase_map()
        check("U12 C4 fails on range mismatch", not ok and "Phase 0" in d, d)
    finally:
        s.close()

    # ---- C5 --------------------------------------------------------------
    s = Sandbox(); s.bind()
    try:
        s.write("docs/tasks/GOALS.md", "# goals\n")
        s.write("docs/README.md", "[spec](tasks/GOALS.md)\n")
        ok, d = cd.check_c5_index_health()
        check("U13 C5 ok on clean index", ok, d)

        s.write("docs/tasks/GOALS.md", "# goals\nTODO soon\n")
        ok, d = cd.check_c5_index_health()
        check("U14 C5 fails on TODO in GOALS", not ok and "TODO" in d, d)

        s.write("docs/tasks/GOALS.md", "# goals\n")
        s.write("docs/README.md", "[ghost](tasks/nope.md)\n")
        ok, d = cd.check_c5_index_health()
        check("U15 C5 fails on broken relative link",
              not ok and "tasks/nope.md" in d, d)
    finally:
        s.close()

    # ---- C6 + sensitivity --------------------------------------------------
    s = Sandbox(); s.bind()
    try:
        s.write("docs/SPEC-TASK-LEDGER.md", "stable prose only\n")
        s.write("docs/tasks/GOALS.md", "law text\n")
        s.write("docs/README.md", "# docs\n")
        ok, d = cd.check_c6_no_volatile_counts()
        check("U16 C6 ok without counts", ok, d)

        s.write("docs/SPEC-TASK-LEDGER.md", "baseline is CI 17/17 green\n")
        ok, d = cd.check_c6_no_volatile_counts()
        check("U17 C6 flags volatile count in living doc",
              not ok and "SPEC-TASK-LEDGER.md" in d and ":1" in d, d)

        # S1 broken-feature proof: blind the checker, the hostile doc
        # must then PASS silently — i.e. our U17 assertion is what stands
        # between rot and the tree. Restore immediately after.
        saved_re = cd._VOLATILE
        try:
            cd._VOLATILE = re.compile(r"NEVER-MATCHES-ZZ")
            blind_ok, _ = cd.check_c6_no_volatile_counts()
        finally:
            cd._VOLATILE = saved_re
        check("S1 sensitivity: blinded C6 passes silently (detectable)",
              blind_ok is True)

        # ---- T-00098 hardening regressions --------------------------------
        s.write("docs/tasks/GOALS.md", "# goals\n")
        s.write("docs/README.md",
                "[abs](/etc/passwd)\n[trav](../../outside/x.md)\n")
        ok, d = cd.check_c5_index_health()
        check("U18 C5 flags external/escaping link targets (F1)",
              not ok and "external link" in d and "/etc/passwd" in d, d)

        s.write("docs/README.md", "[spec](tasks/GOALS.md)\n")
        big = os.path.join(s.tmp, "docs/SPEC-TASK-LEDGER.md")
        with open(big, "wb") as f:
            f.write(b"x" * (cd.MAX_DOC_BYTES + 1))
        ok, d = cd.check_c1_spec_exists()
        check("U19 C1 fails loudly on oversized doc (F2)",
              not ok and "too large" in d and str(cd.MAX_DOC_BYTES) in d, d)
    finally:
        s.close()

    passed = sum(1 for _, ok in RESULTS if ok)
    print(f"\n{passed}/{len(RESULTS)} checks pass")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
