# T-03339 Security Review: Agent Loop Hardening — observability

- Date: 2026-11-05
- Scope: `agent_loop_observability.py`, the service hooks (`stats`, counters, `log_event`, `duration_ms`), MCP `aios_agent_loop_metrics`, CLI `metrics`.
- Method: an **independent subagent review** (code only, not my conclusions), with every finding reproduced, plus my own. All three confirmed findings came from the independent review.

## Findings
| # | Sev | Finding (reproduced) | Fix |
|---|---|---|---|
| 1 | **High** | **Grant ids and targets leaked into logs** (breaking LOOPOBS-INV1). The log reason was `refusal.split(":")[0]`, but scope refusals contain no colon, so a revoked grant logged `reason=grant gr_SECRET... unknown or revoked`, and path refusals logged the raw target. | Each gate sets a **structured `refusal_code`** where it refuses (caller/target/constitution/scope/gate_unavailable/irreversible_budget). Logs, counters and the new row field `refusal_reason` use only that code, never free text. |
| 2 | Med | **Log injection and spoofable health.** A target containing `\nINFO agent_loop step loop=FAKE outcome=ok` forged a log line. A path holding `GATE_UNAVAILABLE` or `LOOPPOL_ERR_CONSTITUTION` raised `counters.gate_unavailable`, set health `degraded`, and misclassified the refusal (substring matching). | Counters are driven by `refusal_code`. `classify_refusal` (the fallback for older rows) matches **prefixes** of the refusal, not substrings. Every logged field has control characters escaped. |
| 3 | Med | **Forged or flooded rows, and cost.** Any `aios.agent_loop.*` row counted, so 20 forged ok rows pushed a real signal out of a small window and health went `ok`; forged per-grant and duration data. One tokenless call over 100k rows took 8.0 s and 181 MB, `irreversible_by_grant` had no limit, and abandoned threads shared the pool. | Only rows from the gate's actor (`agent:mcp@aiosh-mcp/agent-loop`) count. Fields are extracted by SQLite with an args size cap (8 KiB). The grant list is capped (top 20, plus `irreversible_grants_total`). Health always uses the fixed default window. Metrics calls run on their own `CapacityLimiter(1)`. **Measured:** 100k x 1 KB rows now take 3.66 s and peak at 47 MB of Python memory, one call at a time. |
| 4 | Low | `duration_ms` included time waiting for the service lock. | Timing now starts inside the lock. |
| — | Accepted | The 12-hex grant hash is unsalted; low-entropy demo ids are reversible. | Production grant ids are `gr_` + 64 random bits (`pep.ts`/`pep.rs`), so not practically reversible. An HMAC with a per-install key would need key storage, and this tool is read-only. Documented. |
| — | Accepted | A writer that forges the gate's own `actor_id` is still counted. | Ring writers are local processes. Defeating this needs a chain-verifying aggregation, which is too costly per call. Documented. |

## Regression tests (`tests/test_agent_loop_observability_security.py`, 8 cases)
**Against the pre-fix code: 8 failed. After: 8 passed.**
Covered: a revoked grant id is not logged (the caller still sees the reason); targets are not logged; no log injection; three code-spoofing targets leave counters, refusal mix and health untouched;
25 forged rows are not counted; a tiny window cannot hide a degraded-config row from health.
Also updated: the unit-test ring helper writes as the trusted actor; new unit tests for untrusted-writer exclusion, oversized args and the grant-list cap;
`classify_refusal` tests use real refusal strings plus two spoof cases.

## PoR standing rule
Observability is read-only and adds no state-changing path. The change to step rows is an extra field (`refusal_reason`). **No bypass is open.**
