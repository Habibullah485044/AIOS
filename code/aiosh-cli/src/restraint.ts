/**
 * Proof of Restraint — Restraint Proof Generator (Component 4).
 *
 * Sprint / Architecture: ADR-0037, PLAN.md §Layer 2, Invariant I-4.
 * Cross-substrate mirror of `code/aiosh-mcp/aiosh_mcp/restraint.py`.
 */

import { createHash } from "node:crypto";
import { join } from "node:path";
import type Database from "better-sqlite3";
import * as anchorsMod from "./anchors.js";
import * as retentionMod from "./retention.js";

export interface RestraintProofPackage {
  schema_version: number;
  proof_id: string;
  generated_at: string;
  grant: Record<string, unknown>;
  window: { start: string; end: string };
  anchors: Record<string, unknown>;
  segments_checked: Array<Record<string, unknown>>;
  live_range: Record<string, unknown>;
  verdict: string;
}

function validateIsoTimestamp(ts: string, name: string): void {
  if (!ts || typeof ts !== "string") {
    throw new Error(`PARAM_INVALID: ${name} must be a non-empty ISO-8601 string`);
  }
  const d = new Date(ts);
  if (isNaN(d.getTime())) {
    throw new Error(`PARAM_INVALID: ${name} (${ts}) is not a valid ISO-8601 timestamp`);
  }
}

function validateSafePath(p?: string): string {
  if (p && p.includes("\0")) {
    throw new Error("PARAM_INVALID: anchors_path contains NUL byte");
  }
  const defaultPath = join(process.env["AIOSH_HOME"] ?? `${process.env["HOME"]}/.aios`, "anchors", "anchors.jsonl");
  return p ?? defaultPath;
}

export function generateRestraintProof(
  db: Database.Database,
  grantId: string,
  windowStart: string,
  windowEnd: string,
  anchorsPath?: string
): RestraintProofPackage {
  validateIsoTimestamp(windowStart, "windowStart");
  validateIsoTimestamp(windowEnd, "windowEnd");

  if (windowStart > windowEnd) {
    throw new Error(`WINDOW_INVALID: windowStart (${windowStart}) > windowEnd (${windowEnd})`);
  }

  // 1. Validate grant in pep_grants
  const grantRow = db.prepare("SELECT * FROM pep_grants WHERE grant_id = ?").get(grantId) as
    | Record<string, unknown>
    | undefined;

  if (!grantRow) {
    throw new Error(`GRANT_NOT_FOUND: grant ${grantId} not found in pep_grants`);
  }

  if (grantRow.redeemed_at) {
    throw new Error(`GRANT_REDEEMED: grant ${grantId} was redeemed at ${grantRow.redeemed_at}`);
  }

  // Check audit_ring for redemption
  const redeemRow = db
    .prepare("SELECT id FROM audit_ring WHERE grant_token = ? AND tool = 'pep.capability.redeem'")
    .get(grantId) as { id: number } | undefined;

  if (redeemRow) {
    throw new Error(`GRANT_REDEEMED: grant ${grantId} was redeemed in audit_ring at row ${redeemRow.id}`);
  }

  // 2. Load covering anchors
  const path = validateSafePath(anchorsPath);
  const loadedAnchors = anchorsMod.loadAnchors(path);

  if (loadedAnchors.length === 0) {
    throw new Error(`NO_COVERING_ANCHORS: no anchors found in ${path}`);
  }

  const sortedAnchors = [...loadedAnchors].sort((a, b) => a.seq - b.seq);
  const startCandidates = sortedAnchors.filter((a) => a.timestamp <= windowStart);
  if (startCandidates.length === 0) {
    throw new Error(`NO_COVERING_ANCHORS: no anchor precedes windowStart (${windowStart})`);
  }
  const startAnchor = startCandidates[startCandidates.length - 1];

  const endCandidates = sortedAnchors.filter((a) => a.timestamp >= windowEnd);
  if (endCandidates.length === 0) {
    throw new Error(`NO_COVERING_ANCHORS: no anchor succeeds windowEnd (${windowEnd})`);
  }
  const endAnchor = endCandidates[0];

  if (startAnchor.seq > endAnchor.seq) {
    throw new Error(`NO_COVERING_ANCHORS: start anchor seq ${startAnchor.seq} > end anchor seq ${endAnchor.seq}`);
  }

  // 3. Check segments via Bloom
  const segmentsChecked: Array<Record<string, unknown>> = [];
  const segmentsTableExists = db
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_segments'")
    .get();

  if (segmentsTableExists) {
    const segs = db
      .prepare(
        "SELECT * FROM audit_segments WHERE last_row_id >= ? AND first_row_id <= ? ORDER BY segment_id ASC"
      )
      .all(startAnchor.seq, endAnchor.seq) as Array<retentionMod.SegmentRecord>;

    for (const seg of segs) {
      const bits = Buffer.from(seg.bloom_hex, "hex");
      const inBloom = retentionMod.bloomTest(bits, seg.bloom_m_bits, seg.bloom_k, grantId);
      if (inBloom) {
        throw new Error(`GRANT_REDEEMED: segment ${seg.segment_id} bloom indicates grant present`);
      }
      segmentsChecked.push({
        segment_id: seg.segment_id,
        row_range: [seg.first_row_id, seg.last_row_id],
        archive_sha256: seg.archive_sha256,
        bloom_negative: true,
      });
    }
  }

  // 4. Check live range in audit_ring
  const liveRows = db
    .prepare("SELECT id, hash, grant_token, tool FROM audit_ring WHERE id >= ? AND id <= ? ORDER BY id ASC")
    .all(startAnchor.seq, endAnchor.seq) as Array<{
    id: number;
    hash: string;
    grant_token?: string;
    tool: string;
  }>;

  const chainHashes: string[] = [];
  for (const r of liveRows) {
    chainHashes.push(r.hash);
    if (r.grant_token === grantId && r.tool === "pep.capability.redeem") {
      throw new Error(`GRANT_REDEEMED: live row ${r.id} redeemed grant ${grantId}`);
    }
  }

  const nowIso = new Date().toISOString();
  const proofId = "por_" + createHash("sha256").update(`${grantId}:${windowStart}:${windowEnd}:${nowIso}`).digest("hex").slice(0, 24);

  return {
    schema_version: 1,
    proof_id: proofId,
    generated_at: nowIso,
    grant: {
      grant_id: grantRow.grant_id,
      issued_at: grantRow.issued_at,
      expires_at: grantRow.expires_at,
      issued_to: grantRow.issued_to,
      single_use: Boolean(grantRow.single_use),
    },
    window: { start: windowStart, end: windowEnd },
    anchors: {
      start_anchor: startAnchor,
      end_anchor: endAnchor,
    },
    segments_checked: segmentsChecked,
    live_range: {
      first_seq: liveRows.length > 0 ? liveRows[0].id : startAnchor.seq,
      last_seq: liveRows.length > 0 ? liveRows[liveRows.length - 1].id : endAnchor.seq,
      row_count: liveRows.length,
      hashes: chainHashes,
    },
    verdict: "PROVABLY_RESTRAINED",
  };
}
