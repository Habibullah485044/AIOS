/**
 * AIOS shell — PEP (Policy Enforcement Point) grant tokens.
 *
 * A PEP grant is a scoped capability token issued by a user. The AI
 * subsystem must present a valid grant to dispatch any tool flagged as
 * `pentest.*` or `fs.write` (the non-reversible / high-blast-radius set),
 * per AI_CONSTITUTION article 1.4 cautions C-1..C-3.
 *
 * Grants live in their own table in the same audit WAL database — the
 * grant creation itself is an audit row (tool = "pep.grant.create") so
 * the chain captures who enabled the AI to do what, and when.
 *
 * Grant revocation is also recorded as an audit row (tool =
 * "pep.grant.revoke") and updates the grants table's `revoked_at` field.
 */

import Database from "better-sqlite3";
import { createHash, randomBytes } from "node:crypto";
import { canonicalJson, AuditRing } from "./audit.js";
import type { PepGrant, GrantScope, RedeemResult } from "./types.js";

export interface CreateOpts {
  scope: GrantScope;
  ttl_seconds?: number;
  issued_to: string;
  /** sha256[:12] of active Constitution at issue time. */
  constitution_rev: string;
  /** Proof of Restraint: single-use capability (defaults to true). */
  single_use?: boolean;
}

/** Match a tool name against a scope-tools glob, e.g. "pentest.nmap"
 *  against ["pentest.*"] — true. Against ["pentest.metasploit"] — false. */
export function toolGlobMatch(tool: string, globs: string[]): boolean {
  if (globs.length === 0) return false;
  for (const glob of globs) {
    if (glob === tool) return true;
    if (glob.endsWith(".*") && tool.startsWith(glob.slice(0, -2))) {
      return true;
    }
  }
  return false;
}

/** Path-based allow/deny check. Deny always wins over allow. */
export function pathAllowed(
  target: string, paths: GrantScope["paths"]
): boolean {
  if (!paths) return true;
  const deny = paths.deny ?? [];
  for (const p of deny) {
    if (target === p || target.startsWith(p + "/") || p.endsWith("/")
        && target.startsWith(p)) {
      return false;
    }
  }
  const allow = paths.allow ?? [];
  if (allow.length === 0) return true;
  for (const p of allow) {
    if (target === p || target.startsWith(p + "/") || p.endsWith("/")
        && target.startsWith(p)) {
      return true;
    }
  }
  return false;
}

export function isIrreversible(tool: string): boolean {
  return tool.startsWith("fs.write")
      || tool.startsWith("pentest.")
      || tool === "system.reboot"
      || tool === "system.shutdown";
}

export class PepStore {
  private db_: Database.Database;

  constructor(db: Database.Database) {
    this.db_ = db;
    this.init_();
  }

  static attach(db: Database.Database): PepStore {
    return new PepStore(db);
  }

  private init_(): void {
    this.db_.exec(`
      CREATE TABLE IF NOT EXISTS pep_grants (
        grant_id          TEXT PRIMARY KEY,
        issued_at         TEXT NOT NULL,
        expires_at        TEXT NOT NULL,
        issued_to         TEXT NOT NULL,
        constitution_rev  TEXT NOT NULL,
        scope_json        TEXT NOT NULL,
        scope_hash        TEXT NOT NULL,
        revoked_at        TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_grants_active
        ON pep_grants(issued_to)
        WHERE revoked_at IS NULL;
    `);
    this.maybeAddColumn_("pep_grants", "single_use", "INTEGER NOT NULL DEFAULT 1");
    this.maybeAddColumn_("pep_grants", "redeemed_at", "TEXT");
  }

  private maybeAddColumn_(table: string, col: string, decl: string): void {
    const cols = this.db_.pragma(`table_info(${table})`) as Array<{
      name: string;
    }>;
    if (cols.some((c) => c.name === col)) return;
    this.db_.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${decl}`);
  }

  create(opts: CreateOpts, ring?: AuditRing): PepGrant {
    const ttl = opts.ttl_seconds ?? 3600;
    const now = new Date();
    const expires = new Date(now.getTime() + ttl * 1000);
    const grant_id = "gr_" + randomBytes(8).toString("hex");
    const scope_json = JSON.stringify(opts.scope);
    const scope_hash = createHash("sha256")
      .update(canonicalJson(opts.scope)).digest("hex");
    const single_use = opts.single_use !== false;
    this.db_.prepare(`
      INSERT INTO pep_grants
        (grant_id, issued_at, expires_at, issued_to,
         constitution_rev, scope_json, scope_hash, single_use)
      VALUES
        (@grant_id, @issued_at, @expires_at, @issued_to,
         @constitution_rev, @scope_json, @scope_hash, @single_use)
    `).run({
      grant_id,
      issued_at: now.toISOString(),
      expires_at: expires.toISOString(),
      issued_to: opts.issued_to,
      constitution_rev: opts.constitution_rev,
      scope_json,
      scope_hash,
      single_use: single_use ? 1 : 0,
    });
    if (ring) {
      ring.write({
        actor: "user",
        actor_id: opts.issued_to,
        tool: "pep.capability.mint",
        command: "grant.mint",
        args: {
          grant_id,
          single_use,
          scope: opts.scope,
          expires_at: expires.toISOString(),
        },
        target: undefined,
        outcome: "ok",
        outcome_detail: undefined,
        constitution_rev: opts.constitution_rev,
        grant_token: grant_id,
        c_flags: { c1: false, c2: false, c3: false, c4: false },
        ts: now.toISOString(),
      });
    }
    return {
      grant_id,
      issued_at: now.toISOString(),
      expires_at: expires.toISOString(),
      issued_to: opts.issued_to,
      constitution_rev: opts.constitution_rev,
      scope: opts.scope,
      single_use,
    };
  }

  revoke(grant_id: string): boolean {
    const info = this.db_.prepare(`
      UPDATE pep_grants SET revoked_at = ?
      WHERE grant_id = ? AND revoked_at IS NULL
    `).run(new Date().toISOString(), grant_id);
    return info.changes > 0;
  }

  get(grant_id: string): PepGrant | undefined {
    const row = this.db_.prepare(
      "SELECT * FROM pep_grants WHERE grant_id = ?"
    ).get(grant_id) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    if (row["revoked_at"] != null) return undefined;
    return {
      grant_id: String(row["grant_id"]),
      issued_at: String(row["issued_at"]),
      expires_at: String(row["expires_at"]),
      issued_to: String(row["issued_to"]),
      constitution_rev: String(row["constitution_rev"]),
      scope: JSON.parse(String(row["scope_json"])) as GrantScope,
      single_use: row["single_use"] != null ? Number(row["single_use"]) === 1 : true,
      redeemed_at: row["redeemed_at"] != null ? String(row["redeemed_at"]) : undefined,
    };
  }

  list(active_only = true): PepGrant[] {
    const sql = active_only
      ? "SELECT * FROM pep_grants WHERE revoked_at IS NULL ORDER BY issued_at DESC"
      : "SELECT * FROM pep_grants ORDER BY issued_at DESC";
    const rows = this.db_.prepare(sql).all() as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      grant_id: String(r["grant_id"]),
      issued_at: String(r["issued_at"]),
      expires_at: String(r["expires_at"]),
      issued_to: String(r["issued_to"]),
      constitution_rev: String(r["constitution_rev"]),
      scope: JSON.parse(String(r["scope_json"])) as GrantScope,
      single_use: r["single_use"] != null ? Number(r["single_use"]) === 1 : true,
      redeemed_at: r["redeemed_at"] != null ? String(r["redeemed_at"]) : undefined,
    }));
  }

  /** Returns refusal reason if check fails; null if the grant authorises the call. */
  check(
    grant_id: string | undefined,
    tool: string,
    target?: string
  ): { ok: true } | { ok: false; reason: string } {
    // User-issued commands skip the grant check unless the tool is
    // irreversible (which then demands `--yes` flag at the CLI surface).
    if (grant_id === undefined) {
      if (isIrreversible(tool)) {
        return {
          ok: false,
          reason: `irreversible tool '${tool}' requires explicit PEP grant`,
        };
      }
      return { ok: true };
    }
    const g = this.get(grant_id);
    if (!g) return { ok: false, reason: `unknown or revoked grant: ${grant_id}` };
    if (Date.parse(g.expires_at) < Date.now()) {
      return { ok: false, reason: `grant ${grant_id} expired` };
    }
    if (g.single_use && g.redeemed_at) {
      return {
        ok: false,
        reason: `grant ${grant_id} already redeemed at ${g.redeemed_at}`,
      };
    }
    if (!toolGlobMatch(tool, g.scope.tools)) {
      return {
        ok: false,
        reason: `tool '${tool}' not in grant scope.tools=${JSON.stringify(g.scope.tools)}`,
      };
    }
    if (target && !pathAllowed(target, g.scope.paths)) {
      return { ok: false, reason: `target '${target}' blocked by grant scope.paths` };
    }
    return { ok: true };
  }

  /** Proof of Restraint: redeem a single-use capability token before execution. */
  redeem(
    grant_id: string,
    actor: string,
    tool: string,
    command: string,
    ring?: AuditRing
  ): RedeemResult {
    const g = this.get(grant_id);
    if (!g) {
      return { ok: false, reason: `unknown or revoked grant: ${grant_id}` };
    }
    if (Date.parse(g.expires_at) < Date.now()) {
      return { ok: false, reason: `grant ${grant_id} expired` };
    }
    if (g.single_use && g.redeemed_at) {
      return { ok: false, reason: `grant ${grant_id} already redeemed at ${g.redeemed_at}` };
    }
    const MAX_PARAM_LEN = 8192;
    if (tool.length > MAX_PARAM_LEN || command.length > MAX_PARAM_LEN) {
      return { ok: false, reason: "tool or command parameter exceeds maximum allowed length (8192)" };
    }
    const now = new Date().toISOString();
    if (g.single_use) {
      const res = this.db_.prepare(`
        UPDATE pep_grants SET redeemed_at = ?
        WHERE grant_id = ? AND redeemed_at IS NULL
      `).run(now, grant_id);
      if (res.changes === 0) {
        return { ok: false, reason: `grant ${grant_id} already redeemed concurrently` };
      }
    } else {
      this.db_.prepare(`
        UPDATE pep_grants SET redeemed_at = ?
        WHERE grant_id = ?
      `).run(now, grant_id);
    }
    let audit_hash: string | undefined;
    if (ring) {
      try {
        const row = ring.write({
          actor: "agent",
          actor_id: actor,
          tool: "pep.capability.redeem",
          command,
          args: { grant_id, tool, command },
          target: undefined,
          outcome: "ok",
          outcome_detail: undefined,
          constitution_rev: g.constitution_rev,
          grant_token: grant_id,
          c_flags: { c1: false, c2: false, c3: false, c4: false },
          ts: now,
        });
        audit_hash = row.hash;
      } catch (err) {
        // Rollback redemption state if audit log failed (fail-closed integrity)
        if (g.single_use) {
          this.db_.prepare(`
            UPDATE pep_grants SET redeemed_at = NULL
            WHERE grant_id = ? AND redeemed_at = ?
          `).run(grant_id, now);
        }
        return { ok: false, reason: `audit ring write failed: ${String(err)}` };
      }
    }
    const updated = this.get(grant_id);
    return { ok: true, grant: updated, audit_hash };
  }
}
