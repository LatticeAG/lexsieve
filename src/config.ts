// Configuration loading (spec 8.1). Paths resolve relative to the config
// file's directory, never process cwd. The signer seed is read from the named
// environment variable at startup and each reload, never serialized.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { ClosedError } from './errors.ts';
import { b64uDecode, ed25519PublicFromSeed, RFC8032_TEST_PUB_HEX, RFC8032_TEST_SEED_HEX } from './crypto.ts';
import { parseJson } from './jcs.ts';
import {
  validateConfig,
  validateSignedPack,
  validateTrustConfig,
  type Config,
  type SignedPack,
  type TrustConfig,
} from './schema.ts';
import { verifyPackUntimed } from './packs.ts';
import { Buffer } from 'node:buffer';

export interface LoadedFiles {
  config: Config;
  configPath: string;
  trust: TrustConfig;
  pack: SignedPack;
  signerSeed: Uint8Array;
  signerKeyId: string;
}

function readJsonFile(path: string, what: string): unknown {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (e) {
    throw new ClosedError('NOT_READY', `cannot read ${what}: ${(e as Error).message}`);
  }
  return parseJson(raw);
}

export function resolvePath(configPath: string, p: string): string {
  return join(dirname(configPath), p);
}

export function loadConfig(configPath: string): Config {
  const v = readJsonFile(configPath, 'config');
  return validateConfig(v);
}

// Loads and cross-checks config + trust + pack + signer seed. When
// `allowFixtureKey` is false (always, outside the test runner), the RFC8032
// fixture key material is rejected.
export function loadDeployment(configPath: string, allowFixtureKey = false): LoadedFiles {
  const config = loadConfig(configPath);
  const trust = validateTrustConfig(readJsonFile(resolvePath(configPath, config.trust_file), 'trust'));
  const pack = validateSignedPack(readJsonFile(resolvePath(configPath, config.pack_file), 'pack'));

  const envName = config.signer_seed_env;
  const seedB64 = process.env[envName];
  if (seedB64 === undefined) {
    throw new ClosedError('NOT_READY', `env ${envName} not set`);
  }
  let seed: Uint8Array;
  try {
    seed = b64uDecode(seedB64);
  } catch {
    throw new ClosedError('NOT_READY', `env ${envName} not base64url`);
  }
  if (seed.length !== 32) throw new ClosedError('NOT_READY', 'signer seed must be 32 bytes');
  const derivedPub = ed25519PublicFromSeed(seed);
  if (!allowFixtureKey) {
    if (Buffer.from(seed).toString('hex') === RFC8032_TEST_SEED_HEX) {
      throw new ClosedError('NOT_READY', 'fixture seed prohibited in production');
    }
    if (Buffer.from(derivedPub).toString('hex') === RFC8032_TEST_PUB_HEX) {
      throw new ClosedError('NOT_READY', 'fixture public key prohibited in production');
    }
  }
  const trustEntry = trust.keys.find((k) => k.key_id === config.signer_key_id);
  if (!trustEntry || trustEntry.purpose !== 'receipt') {
    throw new ClosedError('NOT_READY', 'signer_key_id not a receipt key in trust');
  }
  if (trustEntry.revoked) throw new ClosedError('NOT_READY', 'signer key revoked');
  if (Buffer.from(b64uDecode(trustEntry.public_key)).equals(Buffer.from(derivedPub)) === false) {
    throw new ClosedError('NOT_READY', 'signer seed does not match signer_key_id trust entry');
  }
  return {
    config,
    configPath,
    trust,
    pack,
    signerSeed: seed,
    signerKeyId: config.signer_key_id,
  };
}

// Full check-config: schema + files + pack structural/signature verification
// + signer consistency. Does not check the pack validity window.
export function checkConfig(configPath: string, allowFixtureKey = false): { valid: boolean; error?: string } {
  try {
    const dep = loadDeployment(configPath, allowFixtureKey);
    const v = verifyPackUntimed(dep.pack, dep.trust);
    if (!v.valid) return { valid: false, error: v.reason === 'SIGNATURE' ? 'BAD_SIGNATURE' : 'INVALID_REQUEST' };
    return { valid: true };
  } catch (e) {
    if (e instanceof ClosedError) return { valid: false, error: e.code };
    return { valid: false, error: 'INTERNAL' };
  }
}
