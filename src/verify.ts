// Section 7 verification RPCs: verifyReceipt, verifyPack, replay.
// Verification checks schema, body hash, signature, then chain link in that
// order. Pure functions — no key fetch, no network, no live policy service.

import { ClosedError } from './errors.ts';
import { b64uDecode, sha256Hex } from './crypto.ts';
import { jcs, type JsonValue } from './jcs.ts';
import { verifyReceiptWithKey } from './receipts.ts';
import { verifyPack as verifyPackCore } from './packs.ts';
import { dedupSortFindings } from './rules.ts';
import { applyReplacements, type Ctx, type Engine } from './engine.ts';
import {
  validateDecision,
  validateEnvelope,
  validateScreenRequest,
  validateSignedPack,
  validateSignedReceipt,
  validateTrustConfig,
  type DataEnvelope,
  type Decision,
  type ScreenRequest,
  type ScreenResponse,
  type SignedPack,
  type SignedReceipt,
  type TextBlock,
  type TrustConfig,
} from './schema.ts';

export type VerifyReason = 'VALID' | 'HASH' | 'SIGNATURE' | 'LINK' | 'SCHEMA';
export interface VerifyResponse {
  v: 1;
  valid: boolean;
  reason: VerifyReason;
}

export function verifyReceipt(req: {
  v: 1;
  receipt: SignedReceipt;
  public_key: string;
  expected_prev_hash: string;
  expected_seq: number;
}): VerifyResponse {
  let receipt: SignedReceipt;
  let pub: Uint8Array;
  try {
    receipt = validateSignedReceipt(req.receipt);
    pub = b64uDecode(req.public_key);
    if (pub.length !== 32) return { v: 1, valid: false, reason: 'SCHEMA' };
  } catch {
    return { v: 1, valid: false, reason: 'SCHEMA' };
  }
  const r = verifyReceiptWithKey(receipt, pub, req.expected_prev_hash, req.expected_seq);
  return { v: 1, valid: r.valid, reason: r.reason };
}

// Receipt verification under a trust file: the key must exist with purpose
// "receipt" and be unrevoked (current trust). Historical verification passes
// an explicitly supplied historical trust config.
export function verifyReceiptTrust(
  receipt: SignedReceipt,
  trust: TrustConfig,
  expectedPrevHash: string,
  expectedSeq: number,
): VerifyResponse {
  let r: SignedReceipt;
  try {
    r = validateSignedReceipt(receipt);
  } catch {
    return { v: 1, valid: false, reason: 'SCHEMA' };
  }
  const key = trust.keys.find((k) => k.key_id === r.key_id);
  if (!key || key.purpose !== 'receipt') return { v: 1, valid: false, reason: 'SCHEMA' };
  if (key.revoked) return { v: 1, valid: false, reason: 'SIGNATURE' };
  const res = verifyReceiptWithKey(r, b64uDecode(key.public_key), expectedPrevHash, expectedSeq);
  return { v: 1, valid: res.valid, reason: res.reason };
}

export function verifyPack(req: { pack: SignedPack; trust: TrustConfig; now_ms: number }): VerifyResponse {
  let pack: SignedPack;
  try {
    pack = validateSignedPack(req.pack);
    validateTrustConfig(req.trust);
  } catch {
    return { v: 1, valid: false, reason: 'SCHEMA' };
  }
  const r = verifyPackCore(pack, req.trust, req.now_ms);
  return { v: 1, valid: r.valid, reason: r.reason };
}

export type ReplayDifference = 'input' | 'policy' | 'findings' | 'transform' | 'output';
export interface ReplayResponse {
  v: 1;
  equal: boolean;
  differences: ReplayDifference[];
}

// replay(ReplayRequest) -> ReplayResponse. Requires the recorded artifacts
// locally (pack by hash; model inside that pack); uses the recorded
// policy_result — never invokes a live policy service, allocates no IDs,
// appends no receipt, delivers nothing.
export function replay(
  engine: Engine,
  req: { v: 1; request: ScreenRequest; recorded: ScreenResponse },
): ReplayResponse {
  const request = validateScreenRequest(req.request);
  const recordedDecision = validateDecision(req.recorded.decision);
  const recordedEnvelope = validateEnvelope(req.recorded.envelope);
  const recordedReceipt = validateSignedReceipt(req.recorded.receipt);

  const differences = new Set<ReplayDifference>();

  const inputHash = sha256Hex(jcs(request.candidate as unknown as JsonValue));
  if (inputHash !== recordedDecision.input_hash) differences.add('input');

  const snap = recordedDecision.snapshot;
  const storedPack = engine.deps.sink.getPackByHash(engine.config.tenant_id, snap.pack_hash);
  if (!storedPack) {
    throw new ClosedError('NOT_FOUND', 'recorded pack artifact not archived locally');
  }
  if (snap.model_hash !== null) {
    const m = storedPack.pack.body.model;
    if (!m || sha256Hex(jcs(m as unknown as JsonValue)) !== snap.model_hash) {
      throw new ClosedError('NOT_FOUND', 'recorded model artifact not archived locally');
    }
  }

  // Recompute the deterministic pipeline under the recorded snapshot; the
  // recorded policy_result is used verbatim (never a live callback).
  const ctx = engine.bareCtx(request, recordedDecision.snapshot);
  const prevArtifact = engine.artifact;
  const prevHash = engine.artifactHash;
  const prevMode = engine.modeOverride;
  try {
    engine.artifact = snap.model_hash === null ? null : storedPack.pack.body.model;
    engine.artifactHash = snap.model_hash;
    engine.modeOverride = snap.model_hash === null ? 'rules_only' : 'required';
    engine.runLocal(ctx);
    ctx.policyResult = recordedDecision.policy_result;
  } finally {
    engine.artifact = prevArtifact;
    engine.artifactHash = prevHash;
    engine.modeOverride = prevMode;
  }

  const findingsJcs = jcs(dedupSortFindings(ctx.findings).slice(0, 64) as unknown as JsonValue);
  if (findingsJcs !== jcs(recordedDecision.findings as unknown as JsonValue)) {
    differences.add('findings');
  }
  const replacementsSorted = [...ctx.replacements].sort(
    (a, b) => a.block - b.block || a.start - b.start || a.end - b.end,
  );
  if (jcs(replacementsSorted as unknown as JsonValue) !== jcs(recordedDecision.replacements as unknown as JsonValue)) {
    differences.add('transform');
  }
  if (jcs(recordedDecision.policy_result as unknown as JsonValue) !== jcs(ctx.policyResult as unknown as JsonValue)) {
    differences.add('policy');
  }
  // For infrastructure holds, replay treats the signed failure reason as an
  // observation and validates a closed output: verdict must be hold and the
  // envelope must be empty.
  const env = rebuildEnvelope(recordedDecision, request, recordedReceipt, recordedEnvelope.notice);
  if (sha256Hex(jcs(env as unknown as JsonValue)) !== recordedDecision.output_hash) {
    differences.add('output');
  }
  const order: ReplayDifference[] = ['input', 'policy', 'findings', 'transform', 'output'];
  return { v: 1, equal: differences.size === 0, differences: order.filter((d) => differences.has(d)) };
}

function rebuildEnvelope(
  decision: Decision,
  request: ScreenRequest,
  receipt: SignedReceipt,
  notice: DataEnvelope['notice'],
): DataEnvelope {
  let data: TextBlock[] = [];
  if (decision.verdict === 'pass') data = request.candidate.blocks;
  else if (decision.verdict === 'strip') {
    data = applyReplacements(request.candidate.blocks, decision.replacements).blocks;
  }
  return {
    type: 'lexsieve.tool-data.v1',
    result_id: request.candidate.result_id,
    decision_id: decision.decision_id,
    receipt_id: receipt.body.receipt_id,
    trust: 'untrusted',
    disposition: decision.verdict,
    provenance: {
      tool: request.candidate.binding.tool,
      adapter: request.candidate.binding.adapter,
      content_sha256: sha256Hex(jcs(request.candidate.blocks as unknown as JsonValue)),
    },
    notice,
    data,
  };
}
