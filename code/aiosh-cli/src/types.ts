/**
 * AIOS shell — shared types.
 *
 * Every aiosh subcommand emits exactly one AuditRow to the append-only
 * SQLite WAL ring. The row is hash-chained: ring_hash = SHA-256(prev_hash
 * || canonical_json(row_without_hash)). The first row's prev_hash is the
 * genesis hash 0x000...0.
 *
 * Schema mirrors AI_CONSTITUTION article 1.4 (C-1..C-4 caution structure)
 * and ADR-0035 §D-3 (skill promotion row format) so other subsystems can
 * parse the ring uniformly.
 */

export type ActorKind = "user" | "agent" | "system";

export type OutcomeKind = "ok" | "refused" | "error";

export type ToolClass = "fs.read" | "fs.write" | "process" | "audit"
                     | "pentest" | "network" | "gui" | "system";

/** One Censorship-graded action row.
 *  - `actor`: who initiated (user/agent/system)
 *  - `constitution_rev`: sha256 prefix of active Constitution at emit time
 *  - `grant_token`: PEP grant id under which the action was authorised;
 *    undefined for user-issued commands.
 *  - `c_flags`: which C-1..C-4 cautions were checked/applied.
 */
export interface AuditRow {
  id: number;            // autoincrement primary key
  ts: string;            // ISO-8601 UTC
  actor: ActorKind;
  actor_id: string;      // user@host, agent:<name>, system:<subsystem>
  tool: ToolClass | string;       // tool class invoked
  command: string;       // canonical command string
  args: Record<string, unknown>; // structured args (NOT arbitrary blobs)
  target?: string;       // optional target path/host/identifier
  outcome: OutcomeKind;
  outcome_detail?: string;       // short error / refusal / warning
  constitution_rev?: string;      // sha256[:12] of active Constitution
  grant_token?: string;          // pep grant id
  c_flags: { c1: boolean; c2: boolean; c3: boolean; c4: boolean };
  /** Sprint 2 — Constitution rule-pack revision that decided this row. */
  policy_revision?: string;
  /** Sprint 2 — rule IDs that fired for this (tool,target,args) tuple. */
  classify_rule_ids?: string[];
  /** Sprint 2 — human-readable evidence strings per C-flag. */
  classify_evidence?: Record<"c1" | "c2" | "c3" | "c4", string[]>;
  /** Sprint 2 — top-level verdict: "ok" | "caution" | "refused". */
  classify_overall_verdict?: "ok" | "caution" | "refused";
  /** Sprint 2 — short reason string (e.g. "c1=0.95 (R-01,R-08)"). */
  classify_verdict_reason?: string;
  prev_hash: string;     // sha256 hex of preceding row (or genesis 00..0)
  hash: string;          // sha256 hex of this row (chain head)
}

/** PEP grant token issued at `aiosh grant create <scope>`. */
export interface PepGrant {
  grant_id: string;           // "gr_" + 16 hex chars
  issued_at: string;          // ISO-8601 UTC
  expires_at: string;         // ISO-8601 UTC
  scope: GrantScope;          // what tools the grant allows
  constitution_rev: string;   // active Constitution at issue time
  issued_to: string;          // agent:<name> / user@host
  /** Proof of Restraint: single-use capability (defaults to true). */
  single_use?: boolean;
  /** Proof of Restraint: ISO-8601 timestamp when the grant was redeemed. */
  redeemed_at?: string;
}

export interface RedeemResult {
  ok: boolean;
  reason?: string;
  grant?: PepGrant;
  audit_hash?: string;
}

export interface GrantScope {
  /** Allowed tool class globs, e.g. ["pentest.nmap", "fs.read"]. Empty = none. */
  tools: string[];
  /** CIDR host restrictions for pentest.* and network.*, e.g. ["10.0.0.0/8"]. */
  networks?: string[];
  /** Path prefixes restricted/unrestricted. */
  paths?: { allow?: string[]; deny?: string[] };
  /** Action irreversibility budget: max non-reversible actions under this grant. */
  max_irreversible?: number;
}

/** Result envelope returned from every subcommand execution. */
export interface SubCommandResult {
  ok: boolean;
  subcommand: string;
  outcome: OutcomeKind;
  audit_id: number;
  data: unknown;
  error?: string;
}

/** Ring meta — first-row prev_hash sentinel. */
export const GENESIS_HASH = "0".repeat(64);
