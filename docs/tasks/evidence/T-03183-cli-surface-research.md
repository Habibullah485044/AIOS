# Research Evidence: AI Control Plane Model Backend Adapters CLI Surface (T-03183)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / CLI surface
- **Artifact**: `docs/tasks/evidence/T-03183-cli-surface-research.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE

---

## 1. Context & Architectural Requirements

1. **Role of Model Backend Adapters CLI Surface**:
   Provides an operator-facing and scriptable terminal interface (`aiosh model ...`) for inspecting registered model endpoints, verifying endpoint health, registering dynamic inference backends, and executing test completions with fallback support.
2. **Subcommand Architecture**:
   - `list`: Enumerate configured backend adapters with optional provider filters and JSON formatting (read-only).
   - `show <backend_id>`: Display endpoint configuration, timeouts, retries, and capability flags (read-only).
   - `health [backend_id]`: Query health and operational readiness across adapters (read-only).
   - `complete <backend_id>`: Dispatch inference request with prompt payload, temperature, and fallback chains (PEP capability token gated).
   - `register <backend_id>`: Dynamically register backend endpoint with provider and credentials (PEP capability token gated).
3. **Proof-of-Restraint Invariant I-2 Compliance**:
   - Pure read commands (`list`, `show`, `health`) require zero tokens.
   - Consequential commands (`complete`, `register`) strictly require `--token <grant_token>`, returning exit code `3` (`EXIT_UNAUTHORIZED`) if missing or whitespace.
4. **Exit Code Taxonomy**:
   - `EXIT_SUCCESS = 0`: Normal completion.
   - `EXIT_FAILURE = 1`: General execution failure.
   - `EXIT_USAGE = 2`: Invalid syntax, missing flags, or NUL byte injection.
   - `EXIT_UNAUTHORIZED = 3`: Missing or invalid capability token.
   - `EXIT_TIMEOUT = 4`: Execution exceeded timeout.
5. **System Invariants**:
   - `MODCLI-INV1`: Canonical command parsing and dispatch.
   - `MODCLI-INV2`: PoR Invariant I-2 capability token gating.
   - `MODCLI-INV3`: Standardized exit codes & JSON envelope parity.
   - `MODCLI-INV4`: Secret redaction in terminal outputs.
   - `MODCLI-INV5`: Fallback chain propagation and error handling.
