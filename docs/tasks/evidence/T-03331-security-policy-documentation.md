# T-03331 Evidence: Agent Loop Hardening — security policy Documentation

- Date: 2026-11-05
- `docs/SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE.md`, new **§2b Per-step security policy**: the P1..P4 order and what each gate refuses; normalisation and
  target extraction; per-grant ring-counted atomic budget; what every step row records (incl. `tool_args_sha256`); a copy-pasteable TS-grant plus CLI-run example
  with its verbatim output; limitations. §6 adds the `LOOPPOL_ERR_*` codes; §8 links the 7 policy evidence files (all resolve).

## Example verified (real TS issuer, real Python CLI, fresh AIOSH_HOME)
`jq` is not installed here, so `grant_id` was extracted with Python (same `.data.grant_id` path). The grant id is replaced by `<grant>`.
```
[0] ok      pentest.nmap  [R-01,R-07]
[1] refused pentest.nmap  [R-01,R-07]  LOOPSERV_ERR_POLICY_REFUSED: Policy evaluation refused tool invocation: LOOPPOL_ERR_IRREVERSIBLE_BUDGET: used 1 of 1
[2] refused pentest.nmap  [R-01,R-07]  LOOPSERV_ERR_POLICY_REFUSED: Policy evaluation refused tool invocation: target '8.8.8.8' blocked by grant scope.networks
[3] refused fs.write  [R-03,R-07]  LOOPSERV_ERR_POLICY_REFUSED: Policy evaluation refused tool invocation: LOOPPOL_ERR_CONSTITUTION: c2=0.95 (R-03) (rules R-03,R-07; policy sprint-2-rule-pack-v1)
loop loop-pol-docs-01: COMPLETED (4 turn(s), 3 refused, 0 skipped)
```
One run shows all three new gates firing: P4 budget (step 1), P3 network scope (step 2) and P2 constitution (step 3), plus rule ids on the ok step.

## Limitations stated
The caller executes tools; the normalisation fixes are agent-loop only; rule-pack gaps need a cross-substrate change; `--max-irreversible` is enforced only for agent loops.
