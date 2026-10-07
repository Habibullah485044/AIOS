/**
 * Proof of Restraint — Standalone Proof Verifier (Component 5).
 *
 * Sprint / Architecture: ADR-0037, PLAN.md §Layer 2, Invariant I-4.
 * Zero-trust mathematical and cryptographic verifier for RestraintProofPackage.
 * Requires ZERO access to audit.db, agent host, or network services.
 */

import { readFileSync } from "node:fs";
import type { RestraintProofPackage } from "./restraint.js";
import { type AnchorRecord, verifyCheckpoint } from "./anchors.js";
import { bloomTest } from "./retention.js";

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
    if (trimmed.startsWith("{")) {
      return JSON.parse(trimmed) as RestraintProofPackage;
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
  checks.schema = true;

  // 2. CHECK_GRANT
  const grant = pkg.grant;
  const window = pkg.window;
  const grantId = grant["grant_id"] as string | undefined;
  if (!grantId) {
    return {
      valid: false,
      proof_id: proofId,
      reason: "VERIFY_FAILED: GRANT_INVALID: missing grant_id",
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
  if (!wStart || !wEnd || wStart > wEnd) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: WINDOW_INVALID: [${wStart}, ${wEnd}]`,
      checks,
    };
  }
  const gIssued = grant["issued_at"] as string | undefined;
  const gExpires = grant["expires_at"] as string | undefined;
  if (gIssued && gIssued > wStart) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: GRANT_INVALID: grant issued (${gIssued}) after window start (${wStart})`,
      checks,
    };
  }
  if (gExpires && gExpires < wEnd) {
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

  // 5. CHECK_ANCHOR_BOUNDS
  if (startAnchor.timestamp > wStart) {
    return {
      valid: false,
      proof_id: proofId,
      reason: `VERIFY_FAILED: UNBOUNDED_WINDOW: start anchor ts (${startAnchor.timestamp}) > window start (${wStart})`,
      checks,
    };
  }
  if (endAnchor.timestamp < wEnd) {
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

  // 6. CHECK_BLOOM_EXCLUSION
  const segments = (pkg.segments_checked ?? []) as Array<Record<string, unknown>>;
  for (const seg of segments) {
    const m = seg["bloom_m_bits"] as number | undefined;
    const k = seg["bloom_k"] as number | undefined;
    const bhex = seg["bloom_hex"] as string | undefined;
    if (m && k && bhex) {
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
