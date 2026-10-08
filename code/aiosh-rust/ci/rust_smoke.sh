#!/usr/bin/env bash
# AIOS Rust smoke suite — the Rust rewrite of the MCP server + CLI.
#
# Covers the shipped surfaces in one pass:
#   1. cargo build  (zero-warning compile of aiosh-core/aiosh-cli/aiosh-mcp)
#   2. cargo test   (45+ unit tests: audit ring, classifier R-01..R-12,
#      PEP grants, retention, pentest wrappers, sandbox, agent loop)
#   3. MCP stdio wire contract: initialize / tools/list / tools/call
#      through the real binary, asserting the JSON-RPC envelope.
#   4. CLI status smoke against a scratch DB.
#   5. TS CLI `aiosh run` resolves the RUST sandbox (aiosh-sandbox) so
#      the legacy mcp_smoke never depends on the Python package.
#
# Usage: bash code/aiosh-rust/ci/rust_smoke.sh
# Exit:  0 = all checks pass; 1 = first failure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
export AIOSH_CONSTITUTION="${AIOSH_CONSTITUTION:-/content/AIOS_MERGED/mostimportanAIfolder/AI_CONSTITUTION.md}"

echo "== [rust_smoke] building workspace =="
(cd "$ROOT" && cargo build 2>&1 | tail -5)

echo "== [rust_smoke] cargo test =="
(cd "$ROOT" && cargo test 2>&1 | grep -E "test result" )

echo "== [rust_smoke] MCP stdio wire contract =="
# Isolate the wire contract on a scratch ring (same pattern as the CLI
# step below): the server defaults to $AIOSH_HOME/audit.db, and asserting
# verify-ok against a developer's long-lived shared ring couples this gate
# to whatever state that DB happens to be in (T-02900 found a historical
# concurrent-write fork at row 55 of the real ~/.aios/audit.db from
# 2026-09-16 — detected honestly by aios.audit.verify, but it makes this
# smoke fail for reasons unrelated to the code under test).
WIRE_HOME="$(mktemp -d /tmp/aiosh-rust-smoke-wire-XXXX)"
AIOSH_HOME="$WIRE_HOME" python3 - "$ROOT/target/debug/aiosh-mcp" << 'EOF'
import json, subprocess, sys

bin = sys.argv[1]
reqs = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "rust-smoke", "version": "1"}}},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
     "params": {"name": "aios.audit.verify", "arguments": {"full": False}}},
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
     "params": {"name": "aios.task", "arguments": {"action": "status"}}},
    {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
     "params": {"name": "aios.task",
                "arguments": {"action": "done", "task_id": 9999, "note": "smoke"}}},
]
payload = "".join(json.dumps(r) + "\n" for r in reqs)
proc = subprocess.run([bin], input=payload, capture_output=True, text=True, timeout=30)
assert proc.returncode == 0, f"mcp exited {proc.returncode}: {proc.stderr}"
out = {}
for line in proc.stdout.splitlines():
    line = line.strip()
    if not line:
        continue
    m = json.loads(line)
    out[m["id"]] = m

m1 = out[1]
assert m1["result"]["serverInfo"]["name"] == "aiosh-mcp", m1
assert m1["result"]["protocolVersion"] == "2025-06-18", m1
m2 = out[2]
names = [t["name"] for t in m2["result"]["tools"]]
for want in ["aios.fs.read", "aios.audit.tail", "aios.audit.verify",
             "aios.audit.rotate", "aios.pentest.nmap", "aios.pentest.sqlmap",
             "aios.task"]:
    assert want in names, f"missing tool {want}"
# Count canary: re-frozen at 205 on 2026-10-08 (T-02900) — the original
# ==13 froze at T-190 (2026-08-26) while tool_manifest() legitimately grew
# to 205 unique tools (verified: 0 duplicates, all 7 contract members
# above present). Update ONLY when a task intentionally adds/removes a
# manifest tool — every other change to the count is a registration bug.
assert len(names) == 205, f"expected 205 tools, got {len(names)}"
assert len(names) == len(set(names)), "duplicate tool names in tools/list"
m3 = out[3]
text = m3["result"]["content"][0]["text"]
d = json.loads(text)
assert d["ok"] is True, d
assert "audit_id" in d and d["audit_id"] > 0, d
m4 = out[4]
d4 = json.loads(m4["result"]["content"][0]["text"])
assert m4["result"]["isError"] is False, m4
assert d4["ok"] is True, d4
assert d4["action"] == "status" and "next_task" in d4["data"], d4
m5 = out[5]
d5 = json.loads(m5["result"]["content"][0]["text"])
assert m5["result"]["isError"] is True, m5
assert d5["ok"] is False and d5.get("gate") == "pep", d5
assert d5["reason"] == "tool 'aios.task' requires explicit PEP grant", d5
assert d5["audit_id"] > 0, d5
print(f"wire ok: server={m1['result']['serverInfo']['name']} tools={len(names)} verify_audit_id={d['audit_id']} task_status_next={d4['data']['next_task']} task_refusal_audit={d5['audit_id']}")
EOF
rm -rf "$WIRE_HOME"

echo "== [rust_smoke] CLI status smoke =="
# Scratch ring via AIOSH_HOME (T-02900): the previous AIOSH_DB="$DB" was
# a silent no-op — nothing reads AIOSH_DB — so this step verified the
# machine's shared ~/.aios/audit.db instead of a fresh ring.
CLI_HOME="$(mktemp -d /tmp/aiosh-rust-smoke-home-XXXX)"
(cd "$ROOT" && AIOSH_HOME="$CLI_HOME" ./target/debug/aiosh status 2>&1 | python3 -c "
import json, sys
d = json.load(sys.stdin)
assert d['ok'] is True, d
assert d['data']['rust'] == 'aiosh-rust/0.1.0', d
assert d['data']['audit_ring']['verify_ok'] is True, d
print('cli ok: version', d['data']['aiosh_version'])
")
rm -rf "$CLI_HOME"

echo "== [rust_smoke] TS CLI run via Rust sandbox (pip-free) =="
CLI_DIR="$ROOT/../aiosh-cli"
if [ -f "$CLI_DIR/dist/cli.js" ]; then
  HOME_TMP="$(mktemp -d /tmp/aiosh-ts-sandbox-XXXX)"
  (cd "$CLI_DIR" && AIOSH_HOME="$HOME_TMP" node dist/cli.js run echo hi-from-rust-sandbox \
    | python3 -c "
import json, platform, sys
d = json.load(sys.stdin)
assert d['ok'] is True, d
sb = d.get('data', {}).get('sandbox') or {}
assert sb.get('event') == 'sandbox_applied', d
comps = dict(sb.get('components', []))
if platform.system() == 'Linux':
    assert comps.get('no_new_privs') == 'ok', comps
    assert comps.get('seccomp') == 'ok', comps
else:
    # T-02900: on non-Linux the Rust sandbox runs the command and
    # honestly records each kernel primitive as 'FAIL: ...unsupported
    # on non-Linux' — degradation must be explicit, never a silent ok.
    for _n, _st in comps.items():
        assert _st == 'ok' or str(_st).startswith('FAIL:'), comps
print('ts-cli run ok: sandbox via', comps)
")
  rm -rf "$HOME_TMP"
else
  echo "skip: code/aiosh-cli/dist/cli.js not built (legacy TS surface absent)"
fi

echo "== [rust_smoke] task-ledger cross-substrate parity (Rust <-> Python) =="
TASKS_DIR="$(mktemp -d /tmp/aiosh-ledger-parity-XXXX)"
cp "$ROOT/../../docs/tasks/MASTER_TASK_LEDGER.jsonl" "$TASKS_DIR/"
cp "$ROOT/../../docs/tasks/TASK_STATE.json" "$TASKS_DIR/"
cp "$ROOT/../../docs/tasks/COMPLETIONS.jsonl" "$TASKS_DIR/"
# Rust writes (complete the CURRENT next_task on the copy) -> Python must
# read the same state. Works at any pointer position (not hardcoded to 16).
NEXT="$(AIOSH_TASKS_DIR="$TASKS_DIR" python3 -c "
import json, os, sys
st = json.load(open(os.path.join(os.environ['AIOSH_TASKS_DIR'], 'TASK_STATE.json')))
print(st['next_task'])")"
AIOSH_TASKS_DIR="$TASKS_DIR" "$ROOT/target/debug/aiosh" task done "$NEXT" --note rust-writes-py-reads >/dev/null
PY_STATE="$(AIOSH_TASKS_DIR="$TASKS_DIR" python3 "$ROOT/../../tools/task_ledger.py" status 2>&1)"
echo "$PY_STATE" | EXP_NEXT="$((NEXT + 1))" python3 -c "
import json, sys, os
d = json.load(sys.stdin)
exp_next = int(os.environ['EXP_NEXT'])
assert d['next_task'] == exp_next, d
assert d['last_event_seq'] == exp_next - 1, d
print('parity ok: python read rust-written state (next_task=%s)' % d['next_task'])
"
# Python writes (block the new next_task) -> Rust must read the same state.
EXP_NEXT2="$(AIOSH_TASKS_DIR="$TASKS_DIR" python3 -c "
import json, os, sys
st = json.load(open(os.path.join(os.environ['AIOSH_TASKS_DIR'], 'TASK_STATE.json')))
print(st['next_task'])")"
AIOSH_TASKS_DIR="$TASKS_DIR" python3 "$ROOT/../../tools/task_ledger.py" block "$EXP_NEXT2" --reason parity-check >/dev/null
RUST_STATE="$(AIOSH_TASKS_DIR="$TASKS_DIR" "$ROOT/target/debug/aiosh" task status 2>&1)"
echo "$RUST_STATE" | EXP_NEXT2="$EXP_NEXT2" python3 -c "
import json, sys, os
d = json.load(sys.stdin)
assert d['ok'] is True, d
assert d['data']['next_task'] == int(os.environ['EXP_NEXT2']), d
assert d['data']['blocked'] == [int(os.environ['EXP_NEXT2'])], d
print('parity ok: rust read python-written state (next_task=%s blocked=%s)' % (d['data']['next_task'], d['data']['blocked']))
"
# D4 replay parity: Python writes unblock+skip -> Rust rebuild must keep
# the pointer PAST the skipped task (replay == live transitions).
AIOSH_TASKS_DIR="$TASKS_DIR" python3 "$ROOT/../../tools/task_ledger.py" unblock "$EXP_NEXT2" --reason parity-check >/dev/null
AIOSH_TASKS_DIR="$TASKS_DIR" python3 "$ROOT/../../tools/task_ledger.py" skip "$EXP_NEXT2" --reason parity-check >/dev/null
echo '{}' > "$TASKS_DIR/TASK_STATE.json"
RUST_STATE="$(AIOSH_TASKS_DIR="$TASKS_DIR" "$ROOT/target/debug/aiosh" task rebuild 2>&1)"
echo "$RUST_STATE" | EXP_NEXT2="$EXP_NEXT2" python3 -c "
import json, sys, os
d = json.load(sys.stdin)
exp = int(os.environ['EXP_NEXT2'])
assert d['ok'] is True and d['data']['next_task'] == exp + 1, d
assert d['data']['skipped'] == [exp] and d['data']['blocked'] == [], d
print('parity ok: rust rebuilt python-written events (skip replayed, next_task=%s)' % d['data']['next_task'])
"
# Reverse direction: Rust writes the skip -> Python must see pointer past it.
EXP_NEXT3="$(AIOSH_TASKS_DIR="$TASKS_DIR" "$ROOT/target/debug/aiosh" task status 2>&1 | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['next_task'])")"
AIOSH_TASKS_DIR="$TASKS_DIR" "$ROOT/target/debug/aiosh" task skip "$EXP_NEXT3" --reason parity-check >/dev/null
PY_STATE="$(AIOSH_TASKS_DIR="$TASKS_DIR" python3 "$ROOT/../../tools/task_ledger.py" status 2>&1)"
echo "$PY_STATE" | EXP_NEXT3="$EXP_NEXT3" python3 -c "
import json, sys, os
d = json.load(sys.stdin)
exp = int(os.environ['EXP_NEXT3'])
assert d['next_task'] == exp + 1, d
assert d['skipped'][-1] == exp, d
print('parity ok: python read rust-written skip (next_task=%s skipped_tail=%s)' % (d['next_task'], d['skipped'][-1]))
"
rm -rf "$TASKS_DIR"

echo "== RUST SMOKE SUITE PASS =="
