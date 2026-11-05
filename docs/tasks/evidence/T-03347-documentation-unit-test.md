# T-03347 Evidence: Agent Loop Hardening — documentation Unit Test

- Date: 2026-11-05
- New `code/aiosh-mcp/tests/test_agent_loop_doc_drift.py` (10 cases, in CI suite #34 through `-k agent_loop`). It enforces LOOPDOC-INV1 and INV3 against
  `docs/SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE.md`:
  - every error code, MCP tool, config key, config env var, locked key and CLI subcommand from `reference()` appears in the doc
  - the reverse direction: no code in the doc that the code no longer defines
  - every `python` block **runs** (subprocess, temp `AIOSH_HOME`, 120 s timeout); there are 2: the §4 example and the §5b logging snippet
  - every `json` block is valid by kind: `tools/call` examples are validated against the **live server's published schemas**, plan examples go through
    `load_plan`, config examples through `validate` (each kind must occur at least once)
- Doc fix required by the test: spec §6 now documents the **17 previously missing codes** (T-03343 F2), generated from `ERROR_MEANINGS`.

## Fails when broken
| Mutation | Result |
|---|---|
| doc reverted to `main` (17 codes missing) | `FAILED ...[error code-items0]`: lists the 17 undocumented codes |
| a new constant `LOOPSERV_ERR_BRAND_NEW` added to the service with no meaning or doc | 2 failed: the drift test **and** the two-way `ERROR_MEANINGS` completeness test |

```
10 passed in 3.20s
```
