/**
 * Proof of Restraint — Chain Anchoring & Completeness Checkpoints (Component 3).
 *
 * Sprint / Architecture: ADR-0037, PLAN.md §Layer 2, Invariant I-3.
 * Cross-substrate mirror of `code/aiosh-mcp/aiosh_mcp/anchors.py`.
 * Hardened against input tampering, key confusion, and corrupted records (T-02859).
 */

import { generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, appendFileSync, statSync, chmodSync } from "node:fs";
import { dirname } from "node:path";

export interface AnchorRecord {
  schema_version: number;
  seq: number;
  head_hash: string;
  timestamp: string;
  pubkey: string;
  signature: string;
}

const MAX_ANCHORS_FILE_SIZE = 10 * 1024 * 1024; // 10MB cap
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const HEX_64_REGEX = /^[0-9a-fA-F]{64}$/;

function validateHexKey(keyHex: string, name = "key"): Buffer {
  if (!keyHex || !HEX_64_REGEX.test(keyHex.trim())) {
    throw new Error(`Invalid ${name}: must be a 64-character hex string (32 bytes)`);
  }
  return Buffer.from(keyHex.trim(), "hex");
}

export function canonicalAnchorPayload(seq: number, headHash: string, timestamp: string): Buffer {
  const payload = {
    head_hash: headHash,
    seq,
    timestamp,
  };
  return Buffer.from(JSON.stringify(payload), "utf-8");
}

export function generateKeypair(): { privateKeyHex: string; publicKeyHex: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privDer = privateKey.export({ type: "pkcs8", format: "der" });
  const pubDer = publicKey.export({ type: "spki", format: "der" });

  const rawPriv = privDer.subarray(16);
  const rawPub = pubDer.subarray(12);

  return {
    privateKeyHex: rawPriv.toString("hex"),
    publicKeyHex: rawPub.toString("hex"),
  };
}

export function signCheckpoint(
  seq: number,
  headHash: string,
  timestamp: string,
  privateKeyHex: string
): AnchorRecord {
  const rawPriv = validateHexKey(privateKeyHex, "privateKey");
  const privKey = createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, rawPriv]),
    format: "der",
    type: "pkcs8",
  });

  const rawPub = createPublicKey(privKey)
    .export({ type: "spki", format: "der" })
    .subarray(12);

  const payload = canonicalAnchorPayload(seq, headHash, timestamp);
  const signature = sign(null, payload, privKey);

  return {
    schema_version: 1,
    seq,
    head_hash: headHash,
    timestamp,
    pubkey: rawPub.toString("hex"),
    signature: signature.toString("hex"),
  };
}

export function verifyCheckpoint(anchor: AnchorRecord): boolean {
  try {
    const rawPub = validateHexKey(anchor.pubkey, "pubkey");
    if (!anchor.signature || anchor.signature.length !== 128) {
      return false;
    }
    const pubKey = createPublicKey({
      key: Buffer.concat([SPKI_PREFIX, rawPub]),
      format: "der",
      type: "spki",
    });

    const payload = canonicalAnchorPayload(anchor.seq, anchor.head_hash, anchor.timestamp);
    const signature = Buffer.from(anchor.signature, "hex");

    return verify(null, payload, pubKey, signature);
  } catch {
    return false;
  }
}

export function appendAnchor(anchor: AnchorRecord, anchorsPath: string): void {
  const dir = dirname(anchorsPath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
    try {
      chmodSync(dir, 0o700);
    } catch {
      // Windows non-fatal
    }
  }
  const line = JSON.stringify(anchor) + "\n";
  appendFileSync(anchorsPath, line, "utf-8");
  try {
    chmodSync(anchorsPath, 0o600);
  } catch {
    // Windows non-fatal
  }
}

export function loadAnchors(anchorsPath: string): AnchorRecord[] {
  if (!existsSync(anchorsPath)) {
    return [];
  }
  const stat = statSync(anchorsPath);
  if (stat.size > MAX_ANCHORS_FILE_SIZE) {
    throw new Error(`Anchors file exceeds size limit of ${MAX_ANCHORS_FILE_SIZE} bytes`);
  }

  const content = readFileSync(anchorsPath, "utf-8");
  const records: AnchorRecord[] = [];
  let lineNum = 0;
  for (const line of content.split("\n")) {
    lineNum++;
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed) as AnchorRecord;
      if (!parsed.pubkey || !parsed.signature || parsed.seq === undefined) {
        throw new Error("Missing required anchor fields");
      }
      records.push(parsed);
    } catch (e) {
      throw new Error(`Corrupted anchor record at line ${lineNum}: ${(e as Error).message}`);
    }
  }
  return records;
}

export function verifyChainAgainstAnchors(
  chainRows: Array<{ id: number; hash: string }>,
  anchors: AnchorRecord[],
  trustedPubkey?: string
): { valid: boolean; reason?: string } {
  if (anchors.length === 0) {
    return { valid: true };
  }

  if (trustedPubkey) {
    try {
      validateHexKey(trustedPubkey, "trustedPubkey");
    } catch (e) {
      return { valid: false, reason: `INVALID_TRUSTED_PUBKEY: ${(e as Error).message}` };
    }
  }

  const rowMap = new Map<number, string>();
  let maxChainId = 0;
  for (const r of chainRows) {
    rowMap.set(r.id, r.hash);
    if (r.id > maxChainId) {
      maxChainId = r.id;
    }
  }

  for (const anchor of anchors) {
    if (trustedPubkey && anchor.pubkey.toLowerCase() !== trustedPubkey.toLowerCase()) {
      return {
        valid: false,
        reason: `UNTRUSTED_KEY: anchor pubkey ${anchor.pubkey} != trusted ${trustedPubkey}`,
      };
    }

    if (!verifyCheckpoint(anchor)) {
      return {
        valid: false,
        reason: `SIGNATURE_INVALID: anchor at seq ${anchor.seq} failed signature verification`,
      };
    }

    if (anchor.seq > maxChainId) {
      return {
        valid: false,
        reason: `TRUNCATION_DETECTED: anchor requires seq ${anchor.seq} but chain ends at ${maxChainId}`,
      };
    }

    const chainHash = rowMap.get(anchor.seq);
    if (!chainHash || chainHash !== anchor.head_hash) {
      return {
        valid: false,
        reason: `FORK_DETECTED: chain row at seq ${anchor.seq} has hash ${chainHash} != anchor head_hash ${anchor.head_hash}`,
      };
    }
  }

  return { valid: true };
}
