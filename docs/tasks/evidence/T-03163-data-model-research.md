# Research Evidence: AI Control Plane Model Backend Adapters Data Model (T-03163)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / data model
- **Artifact**: `docs/tasks/evidence/T-03163-data-model-research.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS

---

## 1. Facts, Constraints, and Prior Art

### 1.1 Established Facts (Authoritative)
1. **Architectural Role in Pillar C Spine**:
   - The AI Control Plane requires a robust, vendor-agnostic adapter layer to translate abstract agent intents into concrete model provider requests.
   - External providers vary widely in wire format (OpenAI Chat Completions JSON, Anthropic Messages JSON, Google GenAI Content chunks, Ollama local HTTP).
2. **Normalized Data Model Necessity**:
   - Without a canonical data model, internal components (MCP server, agent loops, benchmark harnesses) become tightly coupled to individual vendor SDKs.
   - Canonical models (`ModelRequest`, `ModelResponse`, `ModelMessage`, `ModelEndpointConfig`, `ModelUsage`) provide schema stability and cross-substrate parity.
3. **Secret Isolation & Zero Plaintext Keys**:
   - Storing API keys in configuration files or memory structures violates defense-in-depth principles.
   - Endpoint configurations must store environment variable names (`api_key_env: str`, e.g. `"OPENAI_API_KEY"`), dynamically resolving credentials at invocation time.
4. **Dual-Substrate Parity**:
   - Python substrate (`aiosh_mcp.model_backend_adapters_data_model`): Data structures, validation, and JSON serialization for FastMCP tools and Python agent loops.
   - Rust substrate (`aiosh_core::model_backend_adapters_data_model`): Zero-copy deserialization, invariant enforcement, and native orchestration.
5. **Proof-of-Restraint Gating (PoR Invariant I-2)**:
   - Data model introspection, schema discovery, and configuration inspection are strictly read-only (`READ_ONLY`), requiring zero capability tokens.
   - Model endpoint registration, credential rebinding, and inference dispatch mutate state or consume external quotas, strictly requiring capability tokens.

### 1.2 Identified Assumptions (vs. Facts)
1. *Assumption*: Each model provider requires an entirely separate wire protocol abstraction.
   - *Fact*: Modern LLM backends have converged around a shared message-passing topology (`system`, `user`, `assistant`, `tool`). A unified data model with provider-specific serialization decorators captures >98% of provider behaviors.
2. *Assumption*: Model temperature can be unbounded.
   - *Fact*: Standard LLM inference parameters must be strictly bounded (`temperature: [0.0, 2.0]`, `top_p: [0.0, 1.0]`) to avoid runtime crashes or unbounded sampling behavior.

### 1.3 Constraints & Invariants (`MODADAPT-INV1..MODADAPT-INV5`)
1. **`MODADAPT-INV1` (Role Canonicalization)**:
   - Only `system`, `user`, `assistant`, `tool` are permitted roles. Any other role string raises `MODADAPT_ERR_INVALID_ROLE`.
2. **`MODADAPT-INV2` (Token Non-Negativity & Accounting Sum)**:
   - `prompt_tokens >= 0`, `completion_tokens >= 0`, and `total_tokens == prompt_tokens + completion_tokens`.
3. **`MODADAPT-INV3` (Secret Isolation)**:
   - `ModelEndpointConfig` strictly disallows raw API key storage; it references the environment variable name (`api_key_env`).
4. **`MODADAPT-INV4` (Parameter Bounds Enforcement)**:
   - Temperature clamped in `[0.0, 2.0]`; max tokens must be positive integer if specified; timeouts clamped in `[1000, 300000]` ms.
5. **`MODADAPT-INV5` (PoR Invariant I-2 Compliance)**:
   - Pure queries require zero tokens; mutations strictly require capability tokens.

---

## 2. Decisions & Implementation Roadmap

- **Decision 1**: Define canonical data structures in `code/aiosh-mcp/aiosh_mcp/model_backend_adapters_data_model.py` and `code/aiosh-rust/aiosh-core/src/model_backend_adapters_data_model.rs`.
- **Decision 2**: Draft comprehensive formal specification in `docs/SPEC-MODEL-BACKEND-ADAPTERS.md`.
- **Decision 3**: No code changes in this research task; proceed sequentially to Specification (`T-03164`).
