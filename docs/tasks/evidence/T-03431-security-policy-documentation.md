# T-03431 Evidence: Tool Registry & Taxonomy — security policy Documentation

- Date: 2026-11-13
- Doc: [docs/SPEC-TOOL-REGISTRY-DATA-MODEL.md](../../SPEC-TOOL-REGISTRY-DATA-MODEL.md), §6g (new), §6d (updated), §8 (links)

## What the doc now says
- **§6g Security policy and capability tokens:**
  - which surfaces use the single policy point;
  - the five rules (never weaker, shadow adds nothing, fail closed iff strict, attributed refusals, `policy_revision`),
    with their invariant ids;
  - the capability-token gate from T-03429/T-03430: what is checked, the audit row, the fail-closed caps and timeout,
    the error codes.
- **§6d:** decide returns a `policy` block; stats returns `policy_revision`.
- **§8:** links all nine evidence files of this epic (T-03423..T-03431).

## Copy-pasteable examples (all executed by the doc test)
- A Python block, run in a subprocess with its `# ->` output checked.
- A CLI line, `python -m aiosh_mcp.tool_registry_cli decide aios.anchor.create --mode strict --json`, with its exit
  code checked.
- A JSON tool call (`aios_tool_registry_decide`), validated against the live schema.

## Limitations stated in the doc
- `aios_mcp_policy_evaluate` is advisory and still trusts any non-empty token (T-03429 F2).
- The Rust `recover_mcp_store` and the Rust policy engine keep the non-empty check; neither has a served caller.
- `policy_revision` is informational and 64-bit.
- The mode is fixed per process.
- Scope kinds are reported, not enforced (D5).

## Drift test
New `test_documented_security_policy_matches_the_code` in `tests/test_tool_registry_doc.py` pins §6g to the code:
- the surface names, the revision prefix and length, and both refusal suffixes;
- every documented cap and the timeout value;
- that the six listed tools are actually served;
- that every linked evidence file exists.

Mutation: changing the documented timeout to `9 s` made it fail; reverting made it pass.
```
$ python -m pytest tests/test_tool_registry_doc.py -q
18 passed in 25.83s
$ python -m pytest tests/ -q -k tool_registry        (CI suite #35)
694 passed, 1 skipped, 1462 deselected, 1 warning in 115.24s
```

## Security audit (standing rule)
- **Docs and tests only;** no production code changed.
- **No secrets** in the examples: they use catalog names only, and no token or grant id appears.
- **Honest limitations:** the residual advisory and Rust non-empty-token checks are named, not hidden, so an operator
  cannot mistake `aios_mcp_policy_evaluate` for an enforcing gate.
- **The examples are safe to paste:** the CLI is read-only and the decide tool needs no token.
- **PoR (I-2):** unchanged. **No bypass.**
