/**
 * Proof of Restraint — Standalone Proof Verifier (Component 5).
 *
 * Sprint / Architecture: ADR-0037, PLAN.md §Layer 2, Invariant I-4.
 * Zero-trust mathematical and cryptographic verifier for RestraintProofPackage.
 * Requires ZERO access to audit.db, agent host, or network services.
 */

import { readFileSync, statSync } from "node:fs";
import type { RestraintProofPackage } from "./restraint.js";
import { type AnchorRecord, verifyCheckpoint } from "./anchors.js";
import { bloomTest } from "./retention.js";

const MAX_PROOF_PAYLOAD_BYTES = 20 * 1024 * 1024; // 20 MB cap
const MAX_SEGMENTS_COUNT = 10_000;
const MAX_LIVE_HASHES_COUNT = 100_000;
const MAX_BLOOM_BITS = 16_000_000; // ~2 MB bitset
const MAX_BLOOM_K = 64;
const MAX_FIELD_STR_LEN = 4_096;

function parseIso8601Utc(ts: unknown, field: string): Date {
  if (typeof ts !== "string" || !ts.trim()) {
    throw new Error(
      `TIMESTAMP_INVALID: ${field} (${JSON.stringify(ts)}) is not a valid ISO-8601 UTC timestamp`
    );
  }
  const d = new Date(ts);
  if (isNaN(d.getTime())) {
    throw new Error(
      `TIMESTAMP_INVALID: ${field} (${ts}) is not a valid ISO-8601 UTC timestamp`
    );
  }
  return d;
}

export interface VerificationResult {
  valid: boolean;
  proof_id: string;
  reason?: string;
  checks: Record<string, boolean>;
}

function loadProof(proof: RestraintProofPackage | string): RestraintProofPackage {
  if (typeof proof === "object" && proof !== null) {
    return proof;
  }
  if (typeof proof === "string") {
    const trimmed = proof.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      const encoded = Buffer.byteLength(proof, "utf-8");
      if (encoded > MAX_PROOF_PAYLOAD_BYTES) {
        throw new Error(
          `PAYLOAD_TOO_LARGE: proof string exceeds limit (${MAX_PROOF_PAYLOAD_BYTES} bytes)`
        );
      }
      return JSON.parse(trimmed) as RestraintProofPackage;
    }
    const stat = statSync(proof);
    if (stat.size > MAX_PROOF_PAYLOAD_BYTES) {
      throw new Error(
        `PAYLOAD_TOO_LARGE: proof file size (${stat.size} bytes) exceeds limit (${MAX_PROOF_PAYLOAD_BYTES} bytes)`
      );
    }
    const content = readFileSync(proof, "utf-8");
    return JSON.parse(content) as RestraintProofPackage;
  }
  throw new Error(`PARAM_INVALID: cannot parse proof of type ${typeof proof}`);
}

export function verifyRestraintProof(
  proof: RestraintProofPackage | string,
  trustedPubkeys: string[] | string
): VerificationResult {
  const trustedSet = new Set<string>(
    typeof trustedPubkeys === "string"
      ? [trustedPubkeys.trim()]
      : trustedPubkeys.map((k) => k.trim()).filter((k) => k.length > 0)
  );

  const checks: Record<string, boolean> = {
    schema: false,
    grant: false,
    anchor_keys: false,
    anchor_sigs: false,
    anchor_bounds: false,
    bloom_exclusion: false,
    live_chain: false,
  };

  let pkg: RestraintProofPackage;
  try {
    pkg = loadProof(proof);
  } catch (err: any) {
    return {
      valid: false,
      proof_id: "unknown",
      reason: `VERIFY_FAILED: INVALID_SCHEMA: ${err?.message ?? String(err)}`,
      checks,
    };
  }

  const proofId = pkg.proof_id ?? "unknown";

  // 1. CHECK_SCHEMA
  if (pkg.schema_version !== 1) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: UNSUPPORTED_SCHEMA_VERSION (${pkg.schema_version})`,
      checks,
    };
  }
  if (!pkg.grant || !pkg.window || !pkg.anchors || !pkg.live_range) {
    return {
      valid: false,
      proof_id: proofId,
      reason: "VERIFY_FAILED: MISSING_FIELD: required top-level fields missing",
      checks,
    };
  }

  // Structural type guards (hardening T-02879)
  if (
    typeof pkg.grant !== "object" || Array.isArray(pkg.grant) ||
    typeof pkg.window !== "object" || Array.isArray(pkg.window) ||
    typeof pkg.anchors !== "object" || Array.isArray(pkg.anchors) ||
    typeof pkg.live_range !== "object" || Array.isArray(pkg.live_range)
  ) {
    return {
      valid: false,
      proof_id: proofId,
      reason: "VERIFY_FAILED: INVALID_SCHEMA: grant/window/anchors/live_range must be JSON objects",
      checks,
    };
  }
  const segmentsRaw = (pkg.segments_checked ?? []) as unknown;
  if (!Array.isArray(segmentsRaw)) {
    return {
      valid: false,
      proof_id: proofId,
      reason: "VERIFY_FAILED: INVALID_SCHEMA: segments_checked must be a list",
      checks,
    };
  }
  if (segmentsRaw.length > MAX_SEGMENTS_COUNT) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: PROOF_TOO_COMPLEX: segments_checked (${segmentsRaw.length}) exceeds limit (${MAX_SEGMENTS_COUNT})`,
      checks,
    };
  }
  const hashesRaw = ((pkg.live_range as { hashes?: unknown }).hashes ?? []) as unknown;
  if (!Array.isArray(hashesRaw)) {
    return {
      valid: false,
      proof_id: proofId,
      reason: "VERIFY_FAILED: INVALID_SCHEMA: live_range.hashes must be a list",
      checks,
    };
  }
  if (hashesRaw.length > MAX_LIVE_HASHES_COUNT) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: PROOF_TOO_COMPLEX: live_range.hashes (${hashesRaw.length}) exceeds limit (${MAX_LIVE_HASHES_COUNT})`,
      checks,
    };
  }
  checks.schema = true;

  // 2. CHECK_GRANT
  const grant = pkg.grant;
  const window = pkg.window;
  const grantId = grant["grant_id"] as unknown;
  if (typeof grantId !== "string" || !grantId || grantId.length > MAX_FIELD_STR_LEN) {
    return {
      valid: false,
      proof_id: proofId,
      reason: "VERIFY_FAILED: GRANT_INVALID: missing or invalid grant_id",
      checks,
    };
  }
  if (grant["redeemed_at"]) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: GRANT_REDEEMED: grant redeemed at ${grant["redeemed_at"]}`,
      checks,
    };
  }
  if (!grant["single_use"]) {
    return {
      valid: false,
      proof_id: proofId,
      reason: "VERIFY_FAILED: GRANT_INVALID: proof requires single_use=true",
      checks,
    };
  }
  const wStart = window.start;
  const wEnd = window.end;
  let wStartDt: Date;
  let wEndDt: Date;
  try {
    wStartDt = parseIso8601Utc(wStart, "window.start");
    wEndDt = parseIso8601Utc(wEnd, "window.end");
  } catch (err: any) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: ${err?.message ?? String(err)}`,
      checks,
    };
  }
  if (wStartDt.getTime() > wEndDt.getTime()) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: WINDOW_INVALID: [${wStart}, ${wEnd}]`,
      checks,
    };
  }
  const gIssued = grant["issued_at"] as string | undefined;
  const gExpires = grant["expires_at"] as string | undefined;
  let gIssuedDt: Date | undefined;
  let gExpiresDt: Date | undefined;
  try {
    if (gIssued !== undefined && gIssued !== null) {
      gIssuedDt = parseIso8601Utc(gIssued, "grant.issued_at");
    }
    if (gExpires !== undefined && gExpires !== null) {
      gExpiresDt = parseIso8601Utc(gExpires, "grant.expires_at");
    }
  } catch (err: any) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: ${err?.message ?? String(err)}`,
      checks,
    };
  }
  if (gIssuedDt && gIssuedDt.getTime() > wStartDt.getTime()) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: GRANT_INVALID: grant issued (${gIssued}) after window start (${wStart})`,
      checks,
    };
  }
  if (gExpiresDt && gExpiresDt.getTime() < wEndDt.getTime()) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: GRANT_INVALID: grant expired (${gExpires}) before window end (${wEnd})`,
      checks,
    };
  }
  checks.grant = true;

  // 3. CHECK_ANCHOR_KEYS
  const anchors = pkg.anchors as {
    start_anchor?: AnchorRecord;
    end_anchor?: AnchorRecord;
  };
  const startAnchor = anchors.start_anchor;
  const endAnchor = anchors.end_anchor;
  if (!startAnchor || !endAnchor) {
    return {
      valid: false,
      proof_id: proofId,
      reason: "VERIFY_FAILED: MISSING_ANCHORS",
      checks,
    };
  }
  if (!trustedSet.has(startAnchor.pubkey)) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: UNTRUSTED_KEY: start_anchor pubkey ${startAnchor.pubkey} not trusted`,
      checks,
    };
  }
  if (!trustedSet.has(endAnchor.pubkey)) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: UNTRUSTED_KEY: end_anchor pubkey ${endAnchor.pubkey} not trusted`,
      checks,
    };
  }
  checks.anchor_keys = true;

  // 4. CHECK_ANCHOR_SIGS
  if (!verifyCheckpoint(startAnchor)) {
    return {
      valid: false,
      proof_id: proofId,
      reason: "VERIFY_FAILED: INVALID_ANCHOR_SIGNATURE: start_anchor signature invalid",
      checks,
    };
  }
  if (!verifyCheckpoint(endAnchor)) {
    return {
      valid: false,
      proof_id: proofId,
      reason: "VERIFY_FAILED: INVALID_ANCHOR_SIGNATURE: end_anchor signature invalid",
      checks,
    };
  }
  checks.anchor_sigs = true;

  // 5. CHECK_ANCHOR_BOUNDS (strict UTC instants)
  let saDt: Date;
  let eaDt: Date;
  try {
    saDt = parseIso8601Utc(startAnchor.timestamp, "start_anchor.timestamp");
    eaDt = parseIso8601Utc(endAnchor.timestamp, "end_anchor.timestamp");
  } catch (err: any) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: ${err?.message ?? String(err)}`,
      checks,
    };
  }
  if (saDt.getTime() > wStartDt.getTime()) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: UNBOUNDED_WINDOW: start anchor ts (${startAnchor.timestamp}) > window start (${wStart})`,
      checks,
    };
  }
  if (eaDt.getTime() < wEndDt.getTime()) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: UNBOUNDED_WINDOW: end anchor ts (${endAnchor.timestamp}) < window end (${wEnd})`,
      checks,
    };
  }
  if (startAnchor.seq > endAnchor.seq) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: UNBOUNDED_WINDOW: start anchor seq ${startAnchor.seq} > end anchor seq ${endAnchor.seq}`,
      checks,
    };
  }
  checks.anchor_bounds = true;

  // 6. CHECK_BLOOM_EXCLUSION (hardened decode: caps + strict hex + param bounds)
  const segments = segmentsRaw as Array<Record<string, unknown>>;
  for (const seg of segments) {
    if (typeof seg !== "object" || seg === null || Array.isArray(seg)) {
      return {
        valid: false,
        proof_id: proofId,
        reason: "VERIFY_FAILED: INVALID_SCHEMA: segment entries must be JSON objects",
        checks,
      };
    }
    const m = seg["bloom_m_bits"] as number | undefined;
    const k = seg["bloom_k"] as number | undefined;
    const bhex = seg["bloom_hex"] as string | undefined;
    if (m && k && bhex) {
      if (!Number.isInteger(m) || m <= 0 || m % 8 !== 0 || m > MAX_BLOOM_BITS) {
        return {
          valid: false,
          proof_id: proofId,
          reason: `VERIFY_FAILED: BLOOM_INVALID: segment ${seg["segment_id"]} bloom_m_bits (${String(m)}) outside bounds`,
          checks,
        };
      }
      if (!Number.isInteger(k) || k <= 0 || k > MAX_BLOOM_K) {
        return {
          valid: false,
          proof_id: proofId,
          reason: `VERIFY_FAILED: BLOOM_INVALID: segment ${seg["segment_id"]} bloom_k (${String(k)}) outside bounds`,
          checks,
        };
      }
      if (typeof bhex !== "string" || bhex.length !== m / 4 || !/^[0-9a-fA-F]+$/.test(bhex)) {
        return {
          valid: false,
          proof_id: proofId,
          reason: `VERIFY_FAILED: BLOOM_INVALID: segment ${seg["segment_id"]} bloom_hex malformed or length mismatch`,
          checks,
        };
      }
      const bits = Buffer.from(bhex, "hex");
      if (bloomTest(bits, m, k, grantId)) {
        return {
          valid: false,
          proof_id: proofId,
          reason: `VERIFY_FAILED: BLOOM_INDICATES_PRESENCE: segment ${seg["segment_id"]} matches grant ${grantId}`,
          checks,
        };
      }
    } else {
      if (!seg["bloom_negative"]) {
        return {
          valid: false,
          proof_id: proofId,
          reason: `VERIFY_FAILED: BLOOM_POSITIVE: segment ${seg["segment_id"]} not certified negative`,
          checks,
        };
      }
    }
  }
  checks.bloom_exclusion = true;

  // 7. CHECK_LIVE_CHAIN
  const liveRange = pkg.live_range as { hashes?: string[] };
  const hashes = liveRange.hashes ?? [];
  if (hashes.length > 0) {
    if (hashes.some((h) => typeof h !== "string")) {
      return {
        valid: false,
        proof_id: proofId,
        reason: "VERIFY_FAILED: INVALID_SCHEMA: live_range.hashes entries must be strings",
        checks,
      };
    }
    const lastHash = hashes[hashes.length - 1];
    if (lastHash !== endAnchor.head_hash) {
      return {
        valid: false,
        proof_id: proofId,
        reason: `VERIFY_FAILED: HEAD_HASH_MISMATCH: chain tail ${lastHash} != anchor head_hash ${endAnchor.head_hash}`,
        checks,
      };
    }
  }
  checks.live_chain = true;

  return {
    valid: true,
    proof_id: proofId,
    reason: undefined,
    checks,
  };
}
