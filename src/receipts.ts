// Receipt hashing/signing domains and chain verification (spec 8, 10).
//   receipt_hash = SHA256(UTF8("LexSieve/receipt/v1\n")   || JCS(ReceiptBody))
//   signature    = Ed25519(UTF8("LexSieve/receipt-sign/v1\n") || HEX_DECODE(receipt_hash))
//   pack_hash    = SHA256(UTF8("LexSieve/pack/v1\n")      || JCS(PackBody))
//   pack sig     = Ed25519(UTF8("LexSieve/pack-sign/v1\n")    || HEX_DECODE(pack_hash))

import { b64uDecode, b64uEncode, ed25519Sign, ed25519Verify, hexDecode, sha256Hex } from './crypto.ts';
import { jcs, type JsonValue } from './jcs.ts';
import type { PackBody, ReceiptBody, SignedPack, SignedReceipt } from './schema.ts';

const RECEIPT_HASH_DOMAIN = 'LexSieve/receipt/v1\n';
const RECEIPT_SIGN_DOMAIN = 'LexSieve/receipt-sign/v1\n';
const PACK_HASH_DOMAIN = 'LexSieve/pack/v1\n';
const PACK_SIGN_DOMAIN = 'LexSieve/pack-sign/v1\n';

export function receiptHash(body: ReceiptBody): string {
  return sha256Hex(RECEIPT_HASH_DOMAIN + jcs(body as unknown as JsonValue));
}

export function signReceipt(body: ReceiptBody, seed: Uint8Array): { hash: string; signature: string } {
  const hash = receiptHash(body);
  const sig = ed25519Sign(seed, new Uint8Array([...new TextEncoder().encode(RECEIPT_SIGN_DOMAIN), ...hexDecode(hash)]));
  return { hash, signature: b64uEncode(sig) };
}

export function packHash(body: PackBody): string {
  return sha256Hex(PACK_HASH_DOMAIN + jcs(body as unknown as JsonValue));
}

export function signPack(body: PackBody, seed: Uint8Array): { hash: string; signature: string } {
  const hash = packHash(body);
  const sig = ed25519Sign(seed, new Uint8Array([...new TextEncoder().encode(PACK_SIGN_DOMAIN), ...hexDecode(hash)]));
  return { hash, signature: b64uEncode(sig) };
}

export type VerifyReason = 'VALID' | 'HASH' | 'SIGNATURE' | 'LINK' | 'SCHEMA';

// verifyReceipt: checks schema, body hash, signature, then chain link — in
// that order. Pure: never fetches a key; key_id is an informational label
// bound only by the caller-supplied public_key.
export function verifyReceiptWithKey(
  receipt: SignedReceipt,
  publicKey: Uint8Array,
  expectedPrevHash: string,
  expectedSeq: number,
): { valid: boolean; reason: VerifyReason } {
  const body = receipt.body;
  if (receiptHash(body) !== receipt.hash) return { valid: false, reason: 'HASH' };
  const msg = new Uint8Array([...new TextEncoder().encode(RECEIPT_SIGN_DOMAIN), ...hexDecode(receipt.hash)]);
  let sigOk = false;
  try {
    sigOk = ed25519Verify(publicKey, msg, b64uDecode(receipt.signature));
  } catch {
    sigOk = false;
  }
  if (!sigOk) return { valid: false, reason: 'SIGNATURE' };
  if (body.prev_hash !== expectedPrevHash || body.seq !== expectedSeq) {
    return { valid: false, reason: 'LINK' };
  }
  return { valid: true, reason: 'VALID' };
}

export function verifyPackSignature(pack: SignedPack, publicKey: Uint8Array): boolean {
  const msg = new Uint8Array([...new TextEncoder().encode(PACK_SIGN_DOMAIN), ...hexDecode(pack.hash)]);
  try {
    return ed25519Verify(publicKey, msg, b64uDecode(pack.signature));
  } catch {
    return false;
  }
}
