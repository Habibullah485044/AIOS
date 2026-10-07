/**
 * Proof of Restraint — Restraint Proof Generator (Component 4).
 *
 * Sprint / Architecture: ADR-0037, PLAN.md §Layer 2, Invariant I-4.
 * Cross-substrate mirror of `code/aiosh-mcp/aiosh_mcp/restraint.py`.
 */

import type Database from "better-sqlite3";

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

export function generateRestraintProof(
  _db: Database.Database,
  _grantId: string,
  _windowStart: string,
  _windowEnd: string,
  _anchorsPath?: string
): RestraintProofPackage {
  throw new Error("T-02864 scaffold: generateRestraintProof not implemented yet");
}
