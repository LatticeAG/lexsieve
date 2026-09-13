// Cryptographic primitives: SHA-256, Ed25519 (RFC 8032), base64url, CSPRNG.
// Node implementation uses node:crypto Ed25519 with raw PKCS8/SPKI framing.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as nodeSign,
  verify as nodeVerify,
  type KeyObject,
} from 'node:crypto';
import { ClosedError } from './errors.ts';

const B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export function sha256(data: Uint8Array | string): Uint8Array {
  const h = createHash('sha256');
  h.update(typeof data === 'string' ? Buffer.from(data, 'utf8') : data);
  return new Uint8Array(h.digest());
}

export function sha256Hex(data: Uint8Array | string): string {
  return Buffer.from(sha256(data)).toString('hex');
}

export function b64uEncode(b: Uint8Array): string {
  return Buffer.from(b).toString('base64url');
}

export function b64uDecode(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) throw new ClosedError('INVALID_REQUEST', 'bad base64url');
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

export function hexDecode(s: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(s) && !/^[0-9a-fA-F]*$/.test(s)) {
    throw new ClosedError('INVALID_REQUEST', 'bad hex');
  }
  return new Uint8Array(Buffer.from(s, 'hex'));
}

const PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

export function ed25519PrivateFromSeed(seed: Uint8Array): KeyObject {
  if (seed.length !== 32) throw new ClosedError('INVALID_REQUEST', 'seed must be 32 bytes');
  const der = Buffer.concat([Buffer.from(PKCS8_PREFIX), Buffer.from(seed)]);
  return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}

export function ed25519PublicFromSeed(seed: Uint8Array): Uint8Array {
  const priv = ed25519PrivateFromSeed(seed);
  const pub = createPublicKey(priv);
  const der = pub.export({ format: 'der', type: 'spki' });
  return new Uint8Array(der.slice(-32));
}

export function ed25519PublicFromBytes(publicKey: Uint8Array): KeyObject {
  if (publicKey.length !== 32) throw new ClosedError('INVALID_REQUEST', 'public key must be 32 bytes');
  const der = Buffer.concat([Buffer.from(SPKI_PREFIX), Buffer.from(publicKey)]);
  return createPublicKey({ key: der, format: 'der', type: 'spki' });
}

export function ed25519Sign(seed: Uint8Array, message: Uint8Array): Uint8Array {
  const priv = ed25519PrivateFromSeed(seed);
  return new Uint8Array(nodeSign(null, Buffer.from(message), priv));
}

export function ed25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    const pub = ed25519PublicFromBytes(publicKey);
    return nodeVerify(null, Buffer.from(message), pub, Buffer.from(signature));
  } catch {
    return false;
  }
}

// RFC 8032 test key material — production startup MUST reject it (spec 8.1).
export const RFC8032_TEST_SEED_HEX = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
export const RFC8032_TEST_PUB_HEX = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';

const NANOID_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// 21-char nanoid from the spec's locked alphabet, CSPRNG bytes only.
export function nanoid21(): string {
  const bytes = randomBytes(32);
  let out = '';
  for (const b of bytes) {
    const idx = b & 0x3f;
    // rejection: 256 % 64 == 0, so no modulo bias; just consume until 21 chars
    out += NANOID_ALPHABET[idx];
    if (out.length === 21) return out;
  }
  // 32 bytes is always enough (32 >= 21); unreachable
  return out;
}

export { B64U };
