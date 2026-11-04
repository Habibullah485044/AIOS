# T-03314 Specification: Agent Loop Hardening — automated tests

- Date: 2026-11-05
- Adopts T-03313 D1..D5. Everything here is **AIOS-specific** test infrastructure: stdlib only, kept under `code/aiosh-mcp/tests/`.

## 1. Components
| Status | File | Role |
|---|---|---|
| **New** | `tests/agent_loop_model.py` | Reference model and operation generator: `LoopModel`, `Op`, `generate_ops(rng, n)`, `run_and_check(seed, n_ops, db_path) -> FuzzReport` |
| **New** | `tests/test_agent_loop_fuzz.py` | Seeded model-based fuzz against the real `AgentLoopService` + `PepCapabilityGate` + temp ring |
| **New** | `tests/test_agent_loop_stress.py` | Multi-process stress on one ring |
| **New** | `tests/test_agent_loop_cross_substrate.py` | TS `aiosh grant create` mints; Python redeems and runs a loop on the same ring |
| Changed | `tools/ci_suites.py` | Suite #34 `agent_loop_battery`: `pytest -q code/aiosh-mcp/tests -k "agent_loop or audit_chain_concurrency or grant_scope or secret_masking"` |
| Reused | `agent_loop_grants.mint_grant/revoke_grant/audit_tools/verify_chain`, `audit_client.verify`, `read_loop_history` | — |

## 2. Model-based fuzz (D1)
- **Inputs:** `seed` (int) and `n_ops` (default 200). Env knobs: `AIOSH_LOOP_FUZZ_SEEDS` (comma list, default `1,2,3,4,5`), `AIOSH_LOOP_FUZZ_OPS`.
- **Operations** (chosen by `Random(seed)`): `start` (fresh id, reused id, or malformed id; grant valid, replayed, unknown or out of scope),
  `advance` (in-scope or out-of-scope tool, `policy_allowed` true or false, oversize args, no-tool args, wrong grant), `abort`, `complete`,
  `revoke` (the grant of a live loop), `snapshot`. Each op targets a random known loop or an unknown id.
- **Reference model** predicts each op's outcome (success, or the exact `AgentLoopServiceError.code`) and its audit effect (number and `tool`
  of the rows appended). It mirrors the spec, **not** the implementation.
- **Checked after every op:**
  - **M1** the outcome or error code equals the model's prediction.
  - **M2** audit rows appended equal the prediction (tool names in order). Nothing is written on any refusal before redemption.
  - **M3** every live snapshot passes `validate_invariants()` (contiguous steps, token conservation).
  - **M4** a terminated loop stays terminated, and its step count never changes again.
  - **M5** every agent-loop row of a run carries that run's `run_id`; there is at most one start/init row per `loop_id`.
- **At the end:** `audit_client.verify(...)["ok"] is True`.
- **Failure output:** `seed`, the op index and the last 20 ops, so `run_and_check(seed, ...)` replays it exactly.

## 3. Multi-process stress (D2)
`P=4` processes x `L=5` loops x `T=6` turns on one temp ring, each with its own grants, started together.
**Assert:** every process exits 0; there are `P*L` start rows and `P*L*T` step rows; loop ids are unique; the chain verifies
(`count(distinct prev_hash) == count(*)`).

## 4. Cross-substrate (D3)
If `node` and `code/aiosh-cli/dist/cli.js` exist: the TS CLI mints a grant (`--tools aios.agent_loop.start,aios.fs.read`) under a temp
`AIOSH_HOME`; Python `AgentLoopService` redeems it, runs ok + refused steps and completes. **Assert:** the history order, and that the chain verifies
across both writers. Otherwise `pytest.skip("<reason>")`, never a silent pass.

## 5. Error cases and effects
The tests write only under `tmp_path` and never read or write the developer's `$AIOSH_HOME`. They leave no processes behind (`join` with timeout,
then kill). Runtime budget: the battery stays under 120 s on this host.

## 6. Invariants
- AUTOTEST-INV1: every generated failure is replayable from its seed.
- AUTOTEST-INV2: the model is derived from the spec docs, not from the code under test.
- AUTOTEST-INV3: no test touches state outside its temp directory.
