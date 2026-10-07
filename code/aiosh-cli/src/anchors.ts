/**
 * Proof of Restraint — Chain Anchoring & Completeness Checkpoints (Component 3).
 *
 * Sprint / Architecture: ADR-0037, PLAN.md §Layer 2, Invariant I-3.
 * Cross-substrate mirror of `code/aiosh-mcp/aiosh_mcp/anchors.py`.
 */

export interface AnchorRecord {
  schema_version: number;
  seq: number;
  head_hash: string;
  timestamp: string;
  pubkey: string;
  signature: string;
}

export function generateKeypair(): { privateKeyHex: string; publicKeyHex: string } {
  throw new Error("T-02854 scaffold: generateKeypair not implemented yet");
}

export function signCheckpoint(
  _seq: number,
  _headHash: string,
  _timestamp: string,
  _privateKeyHex: string
): AnchorRecord {
  throw new Error("T-02854 scaffold: signCheckpoint not implemented yet");
}

export function verifyCheckpoint(_anchor: AnchorRecord): boolean {
  throw new Error("T-02854 scaffold: verifyCheckpoint not implemented yet");
}

export function appendAnchor(_anchor: AnchorRecord, _anchorsPath: string): void {
  throw new Error("T-02854 scaffold: appendAnchor not implemented yet");
}

export function loadAnchors(_anchorsPath: string): AnchorRecord[] {
  throw new Error("T-02854 scaffold: loadAnchors not implemented yet");
}

export function verifyChainAgainstAnchors(
  _chainRows: Array<{ id: number; hash: string }>,
  _anchors: AnchorRecord[],
  _trustedPubkey?: string
): { valid: boolean; reason?: string } {
  throw new Error("T-02854 scaffold: verifyChainAgainstAnchors not implemented yet");
}
