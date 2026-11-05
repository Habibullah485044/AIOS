#!/usr/bin/env python3
"""TS PEP enforces grant scope.networks (fix found in T-03363 research).

Before the fix `PepStore.check` checked only scope.paths, so a pentest grant scoped to
10.0.0.0/8 also authorised any other host. These tests drive the built `dist/pep.js`
with node and compare `networkAllowed` with Python `audit_client.network_allowed`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

CLI = Path(__file__).resolve().parents[1]
PEP_JS = CLI / "dist" / "pep.js"
sys.path.insert(0, str(CLI.parent / "aiosh-mcp"))

pytestmark = pytest.mark.skipif(shutil.which("node") is None or not PEP_JS.exists(),
                                reason="node or dist/pep.js missing (run `npm run build` in code/aiosh-cli)")

CASES = [
    ("10.1.2.3", ["10.0.0.0/8"]), ("11.0.0.1", ["10.0.0.0/8"]), ("10.0.0.5", ["10.0.0.5"]),
    ("10.0.0.6", ["10.0.0.5"]), ("10.0.0.200", ["10.0.0.7/24"]), ("::1", ["::1/128"]),
    ("::1", ["127.0.0.0/8"]), ("example.com", ["example.com"]), ("evil.com", ["example.com"]),
    ("10.0.0.1", ["10.0.0.0/33"]), ("10.0.0.1", ["garbage"]), (None, ["10.0.0.0/8"]), ("8.8.8.8", []),
]


def node(script: str, tmp_path: Path) -> object:
    path = tmp_path / "probe.mjs"
    path.write_text(script, encoding="utf-8")
    out = subprocess.run(["node", str(path)], capture_output=True, text=True, timeout=60, cwd=CLI)
    assert out.returncode == 0, out.stderr[-1500:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_network_allowed_matches_python(tmp_path):
    from aiosh_mcp.audit_client import network_allowed
    js_cases = json.dumps([[t, n] for t, n in CASES])
    got = node(f"""import {{ networkAllowed }} from {json.dumps(PEP_JS.as_uri())};
const cases = {js_cases};
console.log(JSON.stringify(cases.map(([t, n]) => networkAllowed(t ?? undefined, n))));""", tmp_path)
    assert got == [network_allowed(t, n) for t, n in CASES]


def test_check_enforces_scope_networks(tmp_path):
    db = (tmp_path / "audit.db").as_posix()
    got = node(f"""import {{ createRequire }} from "node:module";
const Database = createRequire({json.dumps((CLI / "package.json").as_uri())})("better-sqlite3");
import {{ PepStore }} from {json.dumps(PEP_JS.as_uri())};
const pep = new PepStore(new Database({json.dumps(db)}));
const g = pep.create({{ issued_to: "test", constitution_rev: "rev", single_use: false,
  scope: {{ tools: ["pentest.*"], networks: ["10.0.0.0/8"] }} }});
const fs = pep.create({{ issued_to: "test", constitution_rev: "rev", single_use: false,
  scope: {{ tools: ["fs.read"], paths: {{ allow: ["/tmp"] }} }} }});
console.log(JSON.stringify([
  pep.check(g.grant_id, "pentest.nmap", "10.9.9.9").ok,
  pep.check(g.grant_id, "pentest.nmap", "192.168.1.1").ok,
  pep.check(g.grant_id, "pentest.nmap", "scanme.example").ok,
  pep.check(fs.grant_id, "fs.read", "/tmp/x").ok,
  pep.check(fs.grant_id, "fs.read", "/etc/passwd").ok,
]));""", tmp_path)
    # in-scope host allowed; out-of-scope IP and unlisted hostname refused; path grants unchanged
    assert got == [True, False, False, True, False]
