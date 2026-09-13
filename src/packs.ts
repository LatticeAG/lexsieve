// Pack verification and activation (spec 8, 9.2). Pack verification does not
// mean policy activation; activation is a separate local atomic operation
// enforcing persisted monotonic serials.

import { ClosedError } from './errors.ts';
import { b64uDecode, sha256Hex } from './crypto.ts';
import { jcs, jcsBytes, type JsonValue } from './jcs.ts';
import { compilePackRules } from './rules.ts';
import { packHash, verifyPackSignature } from './receipts.ts';
import {
  validatePackBody,
  validateSignedPack,
  type Config,
  type PackBody,
  type SignedPack,
  type TrustConfig,
} from './schema.ts';
import type { Sink } from './sink.ts';
import { modelHash } from './model.ts';

export type PackVerifyReason = 'VALID' | 'HASH' | 'SIGNATURE' | 'LINK' | 'SCHEMA';
export const CORE_VERSION = '1.0.0';

export function compareSemver(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if (pa[i]! !== pb[i]!) return pa[i]! < pb[i]! ? -1 : 1;
  }
  return 0;
}

// verifyPack: validates schema, hash, signature/trust, core compatibility,
// and validity window (created_at_ms <= now_ms < expires_at_ms). Failure
// returns {valid:false, reason}; never throws for well-formed JSON input.
export function verifyPack(
  pack: SignedPack,
  trust: TrustConfig,
  nowMs: number,
): { valid: boolean; reason: PackVerifyReason } {
  // schema
  let body: PackBody;
  try {
    body = validatePackBody(pack.body);
    compilePackRules(pack.body.rules as unknown as JsonValue);
    if (Buffer.byteLength(jcs(pack.body as unknown as JsonValue), 'utf8') > 262144) {
      return { valid: false, reason: 'SCHEMA' };
    }
    if (compareSemver(body.core_min, CORE_VERSION) > 0) return { valid: false, reason: 'SCHEMA' };
  } catch {
    return { valid: false, reason: 'SCHEMA' };
  }
  // hash
  if (packHash(pack.body) !== pack.hash) return { valid: false, reason: 'HASH' };
  // signature under trust (pack-purpose, unrevoked)
  const key = trust.keys.find((k) => k.key_id === pack.key_id);
  if (!key || key.purpose !== 'pack') return { valid: false, reason: 'SCHEMA' };
  if (key.revoked) return { valid: false, reason: 'SIGNATURE' };
  if (!verifyPackSignature(pack, b64uDecode(key.public_key))) {
    return { valid: false, reason: 'SIGNATURE' };
  }
  // validity window
  if (!(body.created_at_ms <= nowMs && nowMs < body.expires_at_ms)) {
    return { valid: false, reason: 'SCHEMA' };
  }
  return { valid: true, reason: 'VALID' };
}

// Structural pack verification without the time window — used by reload and
// check-config where the caller reports expiry separately.
export function verifyPackUntimed(
  pack: SignedPack,
  trust: TrustConfig,
): { valid: boolean; reason: PackVerifyReason } {
  try {
    validatePackBody(pack.body);
    compilePackRules(pack.body.rules as unknown as JsonValue);
    if (Buffer.byteLength(jcs(pack.body as unknown as JsonValue), 'utf8') > 262144) {
      return { valid: false, reason: 'SCHEMA' };
    }
    if (compareSemver(pack.body.core_min, CORE_VERSION) > 0) return { valid: false, reason: 'SCHEMA' };
  } catch {
    return { valid: false, reason: 'SCHEMA' };
  }
  if (packHash(pack.body) !== pack.hash) return { valid: false, reason: 'HASH' };
  const key = trust.keys.find((k) => k.key_id === pack.key_id);
  if (!key || key.purpose !== 'pack') return { valid: false, reason: 'SCHEMA' };
  if (key.revoked) return { valid: false, reason: 'SIGNATURE' };
  if (!verifyPackSignature(pack, b64uDecode(key.public_key))) return { valid: false, reason: 'SIGNATURE' };
  return { valid: true, reason: 'VALID' };
}

// Atomic activation under the monotonic-serial rule (spec 8, 9.2). Throws
// ClosedError CONFLICT on downgrade/equivocation; NOT_READY on expiry or
// untrusted artifact. Returns the new epoch.
export function activatePack(
  sink: Sink,
  config: Config,
  trust: TrustConfig,
  pack: SignedPack,
  nowMs: number,
  configHash: string,
  lexshieldPolicyHash: string,
): number {
  const v = verifyPack(pack, trust, nowMs);
  if (!v.valid) {
    throw new ClosedError('NOT_READY', `pack activation: ${v.reason}`);
  }
  const tenant = config.tenant_id;
  const maxSerial = sink.getMaxPackSerial(tenant, pack.body.pack_id);
  const stored = sink.getPack(tenant, pack.body.pack_id, pack.body.serial);
  if (stored && stored.hash !== pack.hash) {
    throw new ClosedError('CONFLICT', 'pack equivocation');
  }
  if (maxSerial !== null && pack.body.serial < maxSerial) {
    throw new ClosedError('CONFLICT', 'pack downgrade');
  }
  const active = sink.getActiveSnapshot(tenant, config.gateway_id);
  if (active && active.pack_id === pack.body.pack_id && active.pack_hash === pack.hash) {
    return active.epoch; // idempotent re-activation
  }
  sink.putPack(tenant, pack);
  const epoch = (active?.epoch ?? 0) + 1;
  const snapshot = {
    epoch,
    config_hash: configHash,
    pack_hash: pack.hash,
    model_hash: config.mode === 'required' ? modelHash(validateModelForActivation(pack)) : null,
    lexshield_policy_hash: lexshieldPolicyHash,
  };
  sink.setActiveSnapshot(tenant, config.gateway_id, {
    epoch,
    snapshot,
    pack_id: pack.body.pack_id,
    pack_serial: pack.body.serial,
    pack_expires_at_ms: pack.body.expires_at_ms,
    pack_hash: pack.hash,
  });
  return epoch;
}

function validateModelForActivation(pack: SignedPack) {
  if (!pack.body.model) throw new ClosedError('NOT_READY', 'required mode needs a model');
  return pack.body.model;
}

export function configHashOf(config: Config): string {
  return sha256Hex(jcsBytes(config as unknown as JsonValue));
}
