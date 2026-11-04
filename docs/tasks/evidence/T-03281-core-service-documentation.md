# T-03281 Evidence: Agent Loop Hardening Core Service — Documentation

- Date: 2026-11-05
- New: `docs/SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE.md` (operator/agent doc for what shipped in T-03276..T-03280)
- Updated: `code/aiosh-mcp/README.md`, which now has an "Agent Loop Tools" section linking the spec

## Contents
FSM diagram; the capability model (grant redemption, loop binding, scope re-check); the real issuer
command (`aiosh grant create --to ... --tools ...`, checked against `code/aiosh-cli/src/cli.ts`);
the 4 MCP tools with arguments and envelopes; a JSON tool-call example; a self-contained Python example;
audit row names; 11 error codes; 5 known limitations; links to all evidence files.

## Example verified
The single python block was extracted from the doc and run from `code/aiosh-mcp`:
```
$ python doc_example.py
ok refused ABORTED
```
That matches the `# -> ok refused ABORTED` line in the doc.

## Links verified
Every `tasks/evidence/...` link in the doc resolves to an existing file (scripted check, 0 missing).

## Limitations stated
In-memory state, unenforced per-step timeout, one grant per loop, two registries (data-model init vs
service), and caller-reported metrics.
