/**
 * AIOS shell — audit ring.
 *
 * Append-only SQLite WAL table. Every row carries:
 *   - a `prev_hash` field that references the previous row's `hash`
 *   - a `hash` field = SHA-256(prev_hash || canonical_json(row_without_hash))
 *
 * `tail(n)` returns the most recent n rows in order.
 * `verify()` walks the whole ring and confirms every chain link is intact.
 *
 * Why hash-chain and not just sequence numbers: because at incident
 * response time we must answer "was any row deleted or rewritten?".
 * Sequence numbers can't; a hash chain can.
 */

import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type {
  AuditRow, OutcomeKind, ActorKind
} from "./types.js";
import { GENESIS_HASH } from "./types.js";

/** Stable JSON serializer: keys sorted, no whitespace. Used for hashing.
 *  Coerces `undefined` to `null` so it produces valid JSON (Python's
 *  equivalent decoder stores SQL NULL as Python None — matching our
 *  convention). Cross-substrate invariant defined in
 *  `code/aiosh-mcp/aiosh_mcp/audit_client.py:cannonical`. */
export function canonicalJson(value: unknown): string {
  if (value === undefined) return "null";
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJson).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map(
    (k) => JSON.stringify(k) + ":" + canonicalJson(obj[k])
  ).join(",") + "}";
}

export function sha256Hex(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

export interface OpenOptions {
  /** Path to the .db file. Defaults to ~/.aios/audit.db. */
  path?: string;
  /** Override home for the default path. */
  home?: string;
}

/** Rebuild the hashed proto dict for a row (same shape as at write time).
 *  Sprint 3: shared by AuditRing.verify and retention.verifyFull. */
export function hashProtoFromRow(row: AuditRow): Record<string, unknown> {
  const proto: Record<string, unknown> = {
    ts: row.ts,
    actor: row.actor,
    actor_id: row.actor_id,
    tool: row.tool,
    command: row.command,
    args: row.args,
    target: row.target,
    outcome: row.outcome,
    outcome_detail: row.outcome_detail,
    constitution_rev: row.constitution_rev,
    grant_token: row.grant_token,
    c_flags: row.c_flags,
    prev_hash: row.prev_hash,
  };
  if (row.policy_revision !== undefined)
    proto["policy_revision"] = row.policy_revision;
  if (row.classify_rule_ids !== undefined)
    proto["classify_rule_ids"] = row.classify_rule_ids;
  if (row.classify_evidence !== undefined)
    proto["classify_evidence"] = row.classify_evidence;
  if (row.classify_overall_verdict !== undefined)
    proto["classify_overall_verdict"] = row.classify_overall_verdict;
  if (row.classify_verdict_reason !== undefined)
    proto["classify_verdict_reason"] = row.classify_verdict_reason;
  return proto;
}

/** Deserialize one raw SQL record into an AuditRow. Shared by the ring
 *  and the retention module (archive replay). */
export function auditRowFromSql(rec: Record<string, unknown>): AuditRow {
  const base: AuditRow = {
    id: Number(rec["id"]),
    ts: String(rec["ts"]),
    actor: rec["actor"] as ActorKind,
    actor_id: String(rec["actor_id"]),
    tool: String(rec["tool"]),
    command: String(rec["command"]),
    args: JSON.parse(String(rec["args_json"])) as Record<string, unknown>,
    target: rec["target"] != null ? String(rec["target"]) : undefined,
    outcome: rec["outcome"] as OutcomeKind,
    outcome_detail: rec["outcome_detail"] != null
      ? String(rec["outcome_detail"]) : undefined,
    constitution_rev: rec["constitution_rev"] != null
      ? String(rec["constitution_rev"]) : undefined,
    grant_token: rec["grant_token"] != null
      ? String(rec["grant_token"]) : undefined,
    c_flags: {
      c1: Number(rec["c1"]) === 1,
      c2: Number(rec["c2"]) === 1,
      c3: Number(rec["c3"]) === 1,
      c4: Number(rec["c4"]) === 1,
    },
    prev_hash: String(rec["prev_hash"]),
    hash: String(rec["hash"]),
  };
  // Sprint 2: classifier fields (nullable; old rows from Sprint 0/1/1.5
  // have NULL here and their hash was computed without them).
  if (rec["policy_revision"] != null)
    base.policy_revision = String(rec["policy_revision"]);
  if (rec["classify_rule_ids_json"] != null)
    base.classify_rule_ids = JSON.parse(
      String(rec["classify_rule_ids_json"])) as string[];
  if (rec["classify_evidence_json"] != null)
    base.classify_evidence = JSON.parse(
      String(rec["classify_evidence_json"])) as AuditRow["classify_evidence"];
  if (rec["classify_overall_verdict"] != null)
    base.classify_overall_verdict =
      String(rec["classify_overall_verdict"]) as AuditRow["classify_overall_verdict"];
  if (rec["classify_verdict_reason"] != null)
    base.classify_verdict_reason = String(rec["classify_verdict_reason"]);
  return base;
}

export class AuditRing {
  private db_: Database.Database;
  private insertStmt_: Database.Statement;

  constructor(db: Database.Database) {
    this.db_ = db;
    this.init_();
    this.insertStmt_ = db.prepare(`
      INSERT INTO audit_ring (
        ts, actor, actor_id, tool, command, args_json, target,
        outcome, outcome_detail, constitution_rev, grant_token,
        c1, c2, c3, c4,
        policy_revision, classify_rule_ids_json, classify_evidence_json,
        classify_overall_verdict, classify_verdict_reason,
        prev_hash, hash
      ) VALUES (
        @ts, @actor, @actor_id, @tool, @command, @args_json, @target,
        @outcome, @outcome_detail, @constitution_rev, @grant_token,
        @c1, @c2, @c3, @c4,
        @policy_revision, @classify_rule_ids_json, @classify_evidence_json,
        @classify_overall_verdict, @classify_verdict_reason,
        @prev_hash, @hash
      )
    `);
  }

  private init_(): void {
    this.db_.pragma("journal_mode = WAL");
    this.db_.pragma("synchronous = FULL");
    this.db_.exec(`
      CREATE TABLE IF NOT EXISTS audit_ring (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        ts              TEXT NOT NULL,
        actor           TEXT NOT NULL,
        actor_id        TEXT NOT NULL,
        tool            TEXT NOT NULL,
        command         TEXT NOT NULL,
        args_json       TEXT NOT NULL,
        target          TEXT,
        outcome         TEXT NOT NULL,
        outcome_detail  TEXT,
        constitution_rev TEXT,
        grant_token     TEXT,
        c1              INTEGER NOT NULL DEFAULT 0,
        c2              INTEGER NOT NULL DEFAULT 0,
        c3              INTEGER NOT NULL DEFAULT 0,
        c4              INTEGER NOT NULL DEFAULT 0,
        prev_hash       TEXT NOT NULL,
        hash            TEXT NOT NULL UNIQUE
      );
      CREATE INDEX IF NOT EXISTS idx_audit_ts   ON audit_ring(ts);
      CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_ring(actor);
      CREATE INDEX IF NOT EXISTS idx_audit_tool  ON audit_ring(tool);
      CREATE TABLE IF NOT EXISTS audit_segments (
        segment_id        INTEGER PRIMARY KEY,
        closed_at         TEXT NOT NULL,
        first_row_id      INTEGER NOT NULL,
        last_row_id       INTEGER NOT NULL,
        row_count         INTEGER NOT NULL,
        genesis_prev_hash TEXT NOT NULL,
        head_hash         TEXT NOT NULL,
        archive_path      TEXT NOT NULL,
        archive_sha256    TEXT NOT NULL,
        bloom_m_bits      INTEGER NOT NULL,
        bloom_k           INTEGER NOT NULL,
        bloom_hex         TEXT NOT NULL
      );
    `);
    // Sprint 2 schema migration: add the classifier-decision columns if
    // they don't exist yet. NULL allowed — old rows from Sprint 0/1/1.5
    // stay verifiable because their hash was computed WITHOUT these
    // fields, and the verifier omits null fields from the recomputed
    // proto. New rows write them, and the verifier includes them when
    // present. This preserves the canonical-JSON invariant end-to-end.
    this.maybeAddColumn_("audit_ring", "policy_revision", "TEXT");
    this.maybeAddColumn_("audit_ring", "classify_rule_ids_json", "TEXT");
    this.maybeAddColumn_("audit_ring", "classify_evidence_json", "TEXT");
    this.maybeAddColumn_("audit_ring", "classify_overall_verdict", "TEXT");
    this.maybeAddColumn_("audit_ring", "classify_verdict_reason", "TEXT");
  }

  private maybeAddColumn_(table: string, col: string, decl: string): void {
    const cols = this.db_.pragma(`table_info(${table})`) as Array<{
      name: string;
    }>;
    if (cols.some((c) => c.name === col)) return;
    this.db_.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${decl}`);
  }

  static open(opts: OpenOptions = {}): AuditRing {
    const home = opts.home ?? process.env["HOME"] ?? "/tmp";
    const dbPath = opts.path ?? `${home}/.aios/audit.db`;
    mkdirSync(dirname(dbPath), { recursive: true });
    const db = new Database(dbPath);
    return new AuditRing(db);
  }

  /** Sprint 3: chain head is the last live row's hash; if the live table
   *  is empty (post-rotation with keep_rows=0), fall back to the newest
   *  segment checkpoint head; if no segments exist, genesis. */
  private headHash_(): string {
    const row = this.db_.prepare(
      "SELECT hash FROM audit_ring ORDER BY id DESC LIMIT 1"
    ).get() as { hash: string } | undefined;
    if (row) return row.hash;
    return this.anchorHash_();
  }

  /** Append one row. The chain-head read and the INSERT run inside one
   *  IMMEDIATE transaction: without it, concurrent writers (other CLI
   *  processes, the Python MCP server) could read the same head and
   *  fork the chain (security audit 2026-11-05, finding #1; mirrors
   *  `audit_client.write_audit_row`). Nested calls become savepoints. */
  write(input: Omit<AuditRow, "id" | "prev_hash" | "hash">): AuditRow {
    return this.db_.transaction(() => this.writeLocked_(input)).immediate();
  }

  private writeLocked_(input: Omit<AuditRow, "id" | "prev_hash" | "hash">): AuditRow {
    const prev_hash = this.headHash_();
    const proto: Omit<AuditRow, "id" | "hash"> = { ...input, prev_hash };
    const hash = sha256Hex(prev_hash + canonicalJson(proto));
    const row: AuditRow = { ...proto, id: 0, hash };
    // Sprint-1 cross-substrate invariant fix (audit invariant):
    // `args_json` must be stored in the same canonical-JSON form that
    // was used to compute the chain hash. JSON.stringify() strips
    // undefined keys, but canonicalJson() preserves them as null. So
    // if args has any nested optional fields (e.g. grant.create's
    // GrantScope with networks=undefined), JSON.stringify drops them
    // from the column while canonicalJson keeps them in the hash proto
    // — producing a chain mismatch when Python verifies. We serialize
    // with canonicalJson to keep both views symmetric.
    // See tests/test_pentest_smoke.py (Sprint 1) for the proof.
    const info = this.insertStmt_.run({
      ts: row.ts,
      actor: row.actor,
      actor_id: row.actor_id,
      tool: row.tool,
      command: row.command,
      args_json: canonicalJson(row.args),
      target: row.target ?? null,
      outcome: row.outcome,
      outcome_detail: row.outcome_detail ?? null,
      constitution_rev: row.constitution_rev ?? null,
      grant_token: row.grant_token ?? null,
      c1: row.c_flags.c1 ? 1 : 0,
      c2: row.c_flags.c2 ? 1 : 0,
      c3: row.c_flags.c3 ? 1 : 0,
      c4: row.c_flags.c4 ? 1 : 0,
      policy_revision: row.policy_revision ?? null,
      classify_rule_ids_json: row.classify_rule_ids != null
        ? canonicalJson(row.classify_rule_ids) : null,
      classify_evidence_json: row.classify_evidence != null
        ? canonicalJson(row.classify_evidence) : null,
      classify_overall_verdict: row.classify_overall_verdict ?? null,
      classify_verdict_reason: row.classify_verdict_reason ?? null,
      prev_hash: row.prev_hash,
      hash: row.hash,
    });
    return { ...row, id: Number(info.lastInsertRowid) };
  }

  tail(n: number): AuditRow[] {
    const safe = Math.max(0, Math.min(n, 1024));
    const rows = this.db_.prepare(
      "SELECT * FROM audit_ring ORDER BY id DESC LIMIT ?"
    ).all(safe) as Array<Record<string, unknown>>;
    const minId = (this.db_.prepare(
      "SELECT MIN(id) AS m FROM audit_ring"
    ).get() as { m: number | null } | undefined)?.m;
    return rows.reverse().map(this.rowFromSql_).map((r, i) => {
      // Sprint 3: only re-anchor the FIRST live row (post-rotation its
      // prev_hash points at the latest checkpoint, not genesis). Rows
      // mid-window keep their stored prev_hash as-is.
      if (i === 0 && r.id === minId) {
        return { ...r, prev_hash: this.anchorHash_() };
      }
      return r;
    });
  }

  private rowFromSql_ = auditRowFromSql;

  /** Sprint 3: chain anchor for the live segment — newest checkpoint
   *  head hash, or genesis when no rotation has happened yet. */
  private anchorHash_(): string {
    const hasSegments = this.db_.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_segments'"
    ).get();
    if (hasSegments) {
      const seg = this.db_.prepare(
        "SELECT head_hash FROM audit_segments ORDER BY segment_id DESC LIMIT 1"
      ).get() as { head_hash: string } | undefined;
      if (seg) return seg.head_hash;
    }
    return GENESIS_HASH;
  }

  /** Walk the entire LIVE ring and confirm every chain link matches.
   *  Sprint 3: the walk anchors at the newest segment checkpoint head
   *  (or genesis when no rotation has happened yet). Archived segments
   *  are replayed by retention.verifyFull(). */
  verify(): { ok: boolean; checked: number; brokenAt?: number;
              anchor?: string; segments?: number; mode?: string } {
    const anchor = this.anchorHash_();
    const segmentCount = this.db_.prepare(
      "SELECT COUNT(*) AS n FROM audit_segments"
    ).get() as { n: number } | undefined;
    const rows = this.db_.prepare(
      "SELECT * FROM audit_ring ORDER BY id ASC"
    ).all() as Array<Record<string, unknown>>;
    let prev = anchor;
    let i = 0;
    for (const rec of rows) {
      const row = this.rowFromSql_(rec);
      // 1. prev_hash link check
      if (row.prev_hash !== prev) {
        return { ok: false, checked: i, brokenAt: row.id, anchor };
      }
      // 2. recompute hash from canonical proto (no id, no hash field).
      // Sprint 2: classifier fields are included in the proto iff they
      // are non-null on the row. Old rows have NULL there because their
      // hash was computed without them; this conditional inclusion is
      // what preserves the canonical-JSON invariant across the Sprint-2
      // schema migration. The cross-language proof lives in
      // tests/test_smoke.py and tests/test_agent_smoke.py.
      const proto = hashProtoFromRow(row);
      const expected = sha256Hex(prev + canonicalJson(proto));
      if (expected !== row.hash) {
        return { ok: false, checked: i, brokenAt: row.id, anchor };
      }
      prev = row.hash;
      i++;
    }
    return { ok: true, checked: i, anchor,
             segments: segmentCount?.n ?? 0, mode: "live" };
  }

  close(): void { this.db_.close(); }
}
