// Section 14.1/14.2 fixture builder. Deterministic keys (the RFC 8032
// seed for receipts), packs, models, trust file, and engine construction
// shared by the conformance harness and the CLI smoke path.

import { b64uEncode, ed25519PublicFromSeed, sha256Hex } from '../src/crypto.ts';
import { jcs, type JsonValue } from '../src/jcs.ts';
import type { IdAllocator, IdPrefix } from '../src/ids.ts';
import { signPack } from '../src/receipts.ts';
import { activatePack, configHashOf } from '../src/packs.ts';
import { STATIC_POLICY_HASH, StaticLexShield } from '../src/lexshield.ts';
import type { Config, PackBody, SignedPack, TrustConfig } from '../src/schema.ts';
import { MemorySink } from '../src/sink.ts';
import { Engine, type EngineDeps } from '../src/engine.ts';
import { fakeClock, scriptedClock, type FakeClock } from '../src/eval/clocks.ts';
export { fakeClock, scriptedClock, type FakeClock };
import type { ModelArtifact } from '../src/model.ts';

export const SEED_HEX = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
export const SEED = new Uint8Array(Buffer.from(SEED_HEX, 'hex'));
export const PACK_SEED = new Uint8Array(Buffer.from('7f'.concat('11'.repeat(31)), 'hex'));
export const PACK_SEED_B = new Uint8Array(Buffer.from('aa'.concat('22'.repeat(31)), 'hex'));

// 21-char ID suffix helper: pads with '0' and truncates.
export function sfx(name: string): string {
  return (name + '0'.repeat(21)).slice(0, 21);
}

export const TENANT = `lsten_${sfx('fixturetenant')}`;
export const GATEWAY = `lsgw_${sfx('fixturegateway')}`;
export const RUN = `lsrun_${sfx('fixturerun')}`;
export const PACK_ID = `lspack_${sfx('baselinepack')}`;
export const RECEIPT_KEY_ID = `lskey_${sfx('receiptkey')}`;
export const PACK_KEY_ID = `lskey_${sfx('packkey')}`;
export const PACK_KEY_ID_B = `lskey_${sfx('packkeyb')}`;

export interface FixtureKeys {
  receiptSeed: Uint8Array;
  packSeed: Uint8Array;
  packSeedB: Uint8Array;
}

export function fixtureKeys(): FixtureKeys {
  return { receiptSeed: SEED, packSeed: PACK_SEED, packSeedB: PACK_SEED_B };
}

// Deterministic sequential allocator: prefix_ + zero-padded counter.
export function fixtureAllocator(start = 0): IdAllocator {
  let n = start;
  return {
    next(prefix: IdPrefix): string {
      n++;
      return `${prefix}_${String(n).padStart(21, '0')}`;
    },
  };
}

// Minimal valid lexsieve.linear.v1 artifact (empty weights — scores all 0,
// below threshold 1).
export function modelArtifact(): ModelArtifact {
  return {
    format: 'lexsieve.linear.v1',
    unicode: '15.1.0',
    tokenizer: 'word-ngram-1-3-v1',
    classes: ['override', 'exfiltration', 'tool_directive'],
    bias: [0, 0, 0],
    threshold: 1,
    weights: [],
  };
}

// Artifact that flags the word "ignore" as class override (score 5).
export function modelArtifactPositive(): ModelArtifact {
  return {
    format: 'lexsieve.linear.v1',
    unicode: '15.1.0',
    tokenizer: 'word-ngram-1-3-v1',
    classes: ['override', 'exfiltration', 'tool_directive'],
    bias: [0, 0, 0],
    threshold: 4,
    weights: [{ feature: 'xyzzy', values: [5, 0, 0] }],
  };
}

export interface PackOpts {
  serial?: number;
  model?: ModelArtifact | null;
  rules?: JsonValue[];
  packId?: string;
  packSeed?: Uint8Array;
  keyId?: string;
  created?: number;
  expires?: number;
  coreMin?: string;
}

export function makePack(opts: PackOpts = {}): SignedPack {
  const body: PackBody = {
    v: 1,
    pack_id: opts.packId ?? PACK_ID,
    serial: opts.serial ?? 1,
    core_min: opts.coreMin ?? '1.0.0',
    builtin_revision: 'builtin-1',
    created_at_ms: opts.created ?? 1700000000000,
    expires_at_ms: opts.expires ?? 1700000000000 + 30 * 86400000,
    rules: (opts.rules ?? []) as unknown as PackBody['rules'],
    model: opts.model === undefined ? null : opts.model,
  };
  const { hash, signature } = signPack(body, opts.packSeed ?? PACK_SEED);
  return { body, hash, key_id: opts.keyId ?? PACK_KEY_ID, signature };
}

export function makeTrust(opts: {
  revokePack?: boolean;
  extraKeys?: { key_id: string; seed: Uint8Array; purpose: 'pack' | 'receipt'; revoked?: boolean }[];
  packKeyId?: string;
  packSeed?: Uint8Array;
} = {}): TrustConfig {
  const keys: TrustConfig['keys'] = [
    {
      key_id: RECEIPT_KEY_ID,
      public_key: b64uEncode(ed25519PublicFromSeed(SEED)),
      purpose: 'receipt',
      revoked: false,
    },
    {
      key_id: opts.packKeyId ?? PACK_KEY_ID,
      public_key: b64uEncode(ed25519PublicFromSeed(opts.packSeed ?? PACK_SEED)),
      purpose: 'pack',
      revoked: opts.revokePack ?? false,
    },
  ];
  for (const e of opts.extraKeys ?? []) {
    keys.push({
      key_id: e.key_id,
      public_key: b64uEncode(ed25519PublicFromSeed(e.seed)),
      purpose: e.purpose,
      revoked: e.revoked ?? false,
    });
  }
  return { v: 1, keys };
}

export function makeConfig(overrides: Partial<Config> = {}): Config {
  return {
    v: 1,
    tenant_id: TENANT,
    gateway_id: GATEWAY,
    mode: 'rules_only',
    pack_file: 'pack.json',
    trust_file: 'trust.json',
    signer_key_id: RECEIPT_KEY_ID,
    signer_seed_env: 'LEXSIEVE_TEST_SEED',
    receipt_sink: { kind: 'sqlite', path: ':memory:' },
    lexshield: { kind: 'static' },
    telemetry: { enabled: false, origin: null, token_env: null },
    max_inflight: 16,
    retention_days: 30,
    ...overrides,
  };
}

export interface EngineFixture {
  engine: Engine;
  sink: MemorySink;
  clock: ReturnType<typeof fakeClock>;
  config: Config;
  pack: SignedPack;
  trust: TrustConfig;
  epoch: number;
}

// Builds a MemorySink with the pack activated, then the engine on top.
export function makeEngine(opts: {
  config?: Partial<Config>;
  pack?: SignedPack;
  trust?: TrustConfig;
  clockStart?: number;
  idsStart?: number;
} = {}): EngineFixture {
  const config = makeConfig(opts.config);
  const trust = opts.trust ?? makeTrust();
  const pack = opts.pack ?? makePack({ model: config.mode === 'required' ? modelArtifact() : null });
  const clock = fakeClock(opts.clockStart);
  const sink = new MemorySink();
  const epoch = activatePack(
    sink,
    config,
    trust,
    pack,
    clock.now(),
    configHashOf(config),
    STATIC_POLICY_HASH,
  );
  const deps: EngineDeps = {
    sink,
    clock,
    ids: fixtureAllocator(opts.idsStart),
    lexshield: new StaticLexShield(),
    signer: { keyId: RECEIPT_KEY_ID, seed: SEED },
  };
  const engine = new Engine(config, deps);
  return { engine, sink, clock, config, pack, trust, epoch };
}

// Canonical minimal screen request for fixture tenants.
export function makeRequest(text: string, opts: { resultId?: string; callId?: string; adapter?: 'native' | 'mcp' | 'openai'; toolError?: boolean; requestId?: string; ordinal?: number } = {}): JsonValue {
  let n = 0;
  void n;
  return {
    v: 1,
    request_id: opts.requestId ?? `lsreq_${sfx('req' + Math.abs(hashCode(text)))}`,
    candidate: {
      result_id: opts.resultId ?? `lsres_${sfx('res' + Math.abs(hashCode(text)))}`,
      binding: {
        tenant_id: TENANT,
        gateway_id: GATEWAY,
        run_id: RUN,
        call_id: opts.callId ?? `lscall_${sfx('call' + Math.abs(hashCode(text)))}`,
        tool: 'search',
        adapter: opts.adapter ?? 'native',
        result_ordinal: opts.ordinal ?? 0,
      },
      tool_error: opts.toolError ?? false,
      blocks: [{ index: 0, text }],
    },
  };
}

function hashCode(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}

export { sha256Hex, jcs };
