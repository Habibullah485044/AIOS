# T-02893 — Compliance Mapping / MCP-API Surface: Research

**Task ID**: T-02893  
**Component**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / MCP-API surface  
**Date**: 2026-10-08  
**Constraint honored**: no code changed; this document separates FACT (verifiable, cited) from ASSUMPTION (unverified inference) and lists decisions required before any implementation task.

---

## 1. Scope & Research Question

Compliance Mapping already ships as a **Rust core** (`aiosh_core::compliance_*`) with an `aiosh compliance` CLI. The MCP/API surface task series must expose it to external models / clients. Research question: *what exists today, what does the protocol allow, and what must be decided before specifying the surface?*

---

## 2. Facts — Protocol (authoritative sources)

| ID | Fact | Source |
|---|---|---|
| P1 | MCP is JSON-RPC 2.0 request/response over a transport (stdio for our server). | [JSON-RPC 2.0 spec](https://www.jsonrpc.org/specification); [MCP spec 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18) |
| P2 | MCP servers expose tools via `tools/list` (discovery, JSON Schema input per tool) and `tools/call` (invocation). | [MCP spec 2025-06-18 — Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) |
| P3 | Spec revision 2025-06-18 added tool **output schemas** (`outputSchema` / `structuredContent`) and tool **annotations** (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`). | [MCP spec 2025-06-18 — Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) |
| P4 | A newer spec revision exists: **2026-07-28**. | [MCP spec 2026-07-28 — Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) |
| P5 | Our server uses the official Python SDK class `mcp.server.fastmcp.FastMCP` (`@mcp.tool()` decorator); installed SDK version is **1.29.1**. | [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk); `pip show mcp` on this host |
| P6 | MCP tool errors are conventionally surfaced as tool-result `isError` content, while protocol-level misuse yields JSON-RPC errors; servers choose the mapping. | [MCP spec 2025-06-18 — Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) |

---

## 3. Facts — Existing AIOS MCP Surface (repo)

| ID | Fact | Source |
|---|---|---|
| A1 | ADR-0035 §D-2 binds MCP as **the only tool-call protocol** AIOS exposes to external models. | `code/aiosh-mcp/aiosh_mcp/server.py` docstring |
| A2 | Server pins MCP spec **2025-06-18** (stdio), with a stated intent to pin **2026-07-28** once the corresponding fastmcp release ships. | `server.py` docstring |
| A3 | Tool naming convention: `aios.<domain>.<verb>` (e.g. `aios.audit.rotate`, `aios.pentest.nmap`); PEP-gated tools take an optional `grant_id: str | None`. | `server.py` tool defs |
| A4 | Every tool runs behind `_recorded_call`: classifier first, then PEP via `_dispatch.dispatch(...)`; on refusal the gate writes the refusal audit row; on success `commit()` writes exactly one result audit row carrying classifier fields. Envelope: `{"ok": ..., "audit_id": ..., "classifier_policy_revision": ...}`; errors return `{"ok": False, "tool", "error", "audit_id"}` — never silent. | `server.py::_recorded_call` |
| A5 | State-changing tools use `require_grant=True` / grant redemption; read-only tools pass no grant. | `server.py` (`aios.audit.rotate` vs `aios.audit.tail`) |
| A6 | The Python MCP surface already hosts restraint tools (`aios.restraint.prove`, `aios.restraint.verify`) and a generic `aios.task` action-dispatch tool — two coexisting granularity styles. | `server.py` |
| A7 | A stale `rust_smoke` wire-contract assertion ("expected 13 tools, got 205") shows the registry grew ~15x since that smoke was written; tool-count assertions are brittle. | `ci` smoke (T-02887 findings) |

---

## 4. Facts — Existing Compliance Mapping Substrate (repo)

| ID | Fact | Source |
|---|---|---|
| C1 | Data model: `ComplianceMappingEntry { id, control_id, framework, target_type, target_ref, threat_ids[], status, mitigation_summary, tags[], created_at, updated_at }`. | `code/aiosh-rust/aiosh-core/src/compliance_data_model.rs` |
| C2 | Frameworks (closed enum, snake_case serde): `nist_sp_800_53_rev5`, `soc2_type2`, `iso_27001_2022`, `cis_controls_v8`, `hipaa_security`, `pci_dss_v4`. | `compliance_data_model.rs` |
| C3 | Status state machine: `compliant | partially_compliant | non_compliant | not_applicable`, with `can_transition_to` legality. | `compliance_data_model.rs` |
| C4 | Validation bounds live in the model: identifier rules, `MAX_COMPLIANCE_ID_LEN`, `MAX_COMPLIANCE_NOTES_LEN`, `MAX_THREAT_IDS_COUNT`; `compliant` requires non-empty mitigation summary. | `compliance_data_model.rs` |
| C5 | Service: `ComplianceService` with `load_from_path/save_to_path`, `register_mapping`, `get_mapping`, `remove_mapping`, `update_status`, `assess_framework`, `verify_pep_coverage(gate_id)`, `uncovered_pep_gates(required)`, `find_by_framework/control/status`. | `compliance_service.rs` |
| C6 | Store: `docs/compliance_map.json` (pretty serde JSON); path validation enforces `.json` extension and rejects traversal; saves write via temp file. | `compliance_service.rs` |
| C7 | CLI surface already exists: `aiosh compliance <list|show|register|status|assess|check-pep|init>`. | `code/aiosh-rust/aiosh-cli/src/main.rs` (`cmd_compliance`) |
| C8 | Existing compliance specs cover data model, core service, and CLI only — **no MCP/API surface spec exists yet**. | `docs/SPEC-COMPLIANCE-{DATA-MODEL,SERVICE,CLI}.md` |
| C9 | Standards bodies behind the frameworks (authoritative catalogs): NIST SP 800-53 Rev 5 ([NIST CSRC](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)), SOC 2 Trust Services Criteria (AICPA), ISO/IEC 27001:2022 ([ISO](https://www.iso.org/standard/27001)), CIS Controls v8 ([CIS](https://www.cisecurity.org/controls/v8)), HIPAA Security Rule (45 CFR Part 164 Subpart C), PCI DSS v4 ([PCI SSC](https://www.pcisecuritystandards.org)). | public standards catalogs |

---

## 5. Assumptions (not yet verified)

| ID | Assumption | Risk if wrong |
|---|---|---|
| AS1 | "MCP/API surface" means the MCP tool surface (ADR-0035 §D-2), possibly plus a Python-internal API; it does **not** imply an HTTP REST API. | Scope creep / a second protocol surface violating ADR-0035. |
| AS2 | The JSON store (`docs/compliance_map.json`) remains the single authoritative persistence; the MCP surface must not fork a second store format. | Cross-substrate drift (Python vs Rust serialization). |
| AS3 | Read-only compliance queries need no grant; `register` / `update_status` (state-changing) will need PEP grant gating + exactly-one audit row. | Either an ungated state-change path (policy bypass) or over-gating read paths. |
| AS4 | The Python side will implement compliance logic natively (parity with Rust) rather than shell out to `aiosh` per call. | If wrong: subprocess-per-call cost + binary availability on hosts without the Rust build. |

---

## 6. Unknowns & Decisions Required (before Specification task)

1. **Granularity**: one tool per verb (`aios.compliance.list`, `.show`, `.assess`, …) vs one action-dispatch tool (`aios.compliance(action=...)`, matching `aios.task`)? Both precedents exist (A6).
2. **Authority model**: is Rust `ComplianceService` the sole writer (Python read-only) or does Python get write parity? Determines the dual-substrate invariant (AS2/AS4).
3. **Store contract**: pin a canonical-JSON serialization for `compliance_map.json` (key order, float/int forms) so Rust and Python writes are byte-stable — needed for hashing/anchoring later.
4. **Error mapping**: map model validation errors (C4) to the `{"ok": False, "error": COMPLIANCE_ERR_*}` envelope vs MCP `isError` tool results (P6). Current server convention is envelope-style (A4).
5. **Annotations**: adopt MCP tool annotations (P3) — `readOnlyHint` for queries, `destructiveHint=false, idempotentHint` choices for `register`/`update_status` — or keep the uniform surface?
6. **Structured output**: adopt `outputSchema`/`structuredContent` (P3) for assessment reports, or keep ad-hoc dicts?
7. **Registry smoke**: replace brittle tool-count assertions (A7) with schema/annotation invariants before adding 7+ tools.
8. **Bridging fact-finding**: verify exactly which bounds/error codes the Rust model emits (C4) so Python can match them 1:1 (needs a read of the full `compliance_data_model.rs` constants before spec).

---

## 7. Constraints Carried Forward

- ADR-0035 §D-2: MCP only (A1); spec pin 2025-06-18, migration intent to 2026-07-28 (A2).
- Every state-changing call: PEP gate + exactly one honest audit row, refusals included (A4, ADR-0035 §F-2).
- No code changed in this task (acceptance honored).
