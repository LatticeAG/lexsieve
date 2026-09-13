// Section 19 exact fixture objects: I, J, H, U, B, B64, S functions and the
// named constants seed, pub, Z, H0, M0, PB0, PH0, P0, T0, C0, Q0, E0, D0,
// RB0, RH0, R0, S0. All values are computed by the real implementation; the
// printed golden anchors in the spec (input_hash, pack_hash, receipt hash,
// signature) are asserted by the conformance suite.

import { b64uEncode, ed25519PublicFromSeed, ed25519Sign, sha256Hex, hexDecode } from '../crypto.ts';
import { jcs, type JsonValue } from '../jcs.ts';
import { signPack, signReceipt, packHash, receiptHash } from '../receipts.ts';
import type { IdAllocator, IdPrefix } from '../ids.ts';
import { STATIC_POLICY_HASH } from '../lexshield.ts';
import type { ModelArtifact } from '../model.ts';
import type { Config, Decision, PackBody, ReceiptBody, SignedPack, SignedReceipt, TrustConfig } from '../schema.ts';
import { modelHash } from '../model.ts';

export const SEED_HEX = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
export const PUB_HEX = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
export const seed = hexDecode(SEED_HEX);
export const pub = ed25519PublicFromSeed(seed);
export const Z = '0'.repeat(64);
export const H0 = STATIC_POLICY_HASH;

// I(prefix,c): prefix + "_" + 21 repetitions of c.
export function I(prefix: string, c: string): string {
  return `${prefix}_${c.repeat(21)}`;
}
export const J = (v: JsonValue) => jcs(v);
export const H = (s: string | Uint8Array) => sha256Hex(s);
export const U = (s: string) => new TextEncoder().encode(s);
export const B = hexDecode;
export const B64 = b64uEncode;
export const S = (sd: Uint8Array, msg: Uint8Array) => ed25519Sign(sd, msg);

// Per-prefix letter allocator: first ID of each prefix gets 'A' x21, then B...
export function letterAllocator(): IdAllocator {
  const counts = new Map<string, number>();
  return {
    next(prefix: IdPrefix): string {
      const n = counts.get(prefix) ?? 0;
      counts.set(prefix, n + 1);
      return I(prefix, String.fromCharCode(0x41 + n));
    },
  };
}

export const M0: ModelArtifact = {
  format: 'lexsieve.linear.v1',
  unicode: '15.1.0',
  tokenizer: 'word-ngram-1-3-v1',
  classes: ['override', 'exfiltration', 'tool_directive'],
  bias: [-500, -500, -500],
  threshold: 0,
  weights: [
    { feature: 'credential', values: [0, 1000, 0] },
    { feature: 'forget', values: [1000, 0, 0] },
    { feature: 'terminal', values: [0, 0, 1000] },
  ],
};

export const PB0: PackBody = {
  v: 1,
  pack_id: I('lspack', 'A'),
  serial: 1,
  core_min: '1.0.0',
  builtin_revision: 'builtin-1',
  created_at_ms: 0,
  expires_at_ms: 86400000,
  rules: [],
  model: M0,
};
export const PH0 = packHash(PB0);
export const P0: SignedPack = (() => {
  const { hash, signature } = signPack(PB0, seed);
  return { body: PB0, hash, key_id: I('lskey', 'A'), signature };
})();

export const T0: TrustConfig = {
  v: 1,
  keys: [
    { key_id: I('lskey', 'A'), public_key: B64(pub), purpose: 'pack', revoked: false },
    { key_id: I('lskey', 'B'), public_key: B64(pub), purpose: 'receipt', revoked: false },
  ],
};

export const C0: Config = {
  v: 1,
  tenant_id: I('lsten', 'A'),
  gateway_id: I('lsgw', 'A'),
  mode: 'rules_only',
  pack_file: './packs/active.json',
  trust_file: './trust.json',
  signer_key_id: I('lskey', 'B'),
  signer_seed_env: 'LEXSIEVE_RECEIPT_SEED',
  receipt_sink: { kind: 'sqlite', path: './state/lexsieve.sqlite' },
  lexshield: { kind: 'static' },
  telemetry: { enabled: false, origin: null, token_env: null },
  max_inflight: 16,
  retention_days: 30,
};

export const CM0: Config = { ...C0, mode: 'required' };

export const Q0: JsonValue = {
  v: 1,
  request_id: I('lsreq', 'A'),
  candidate: {
    result_id: I('lsres', 'A'),
    binding: {
      tenant_id: I('lsten', 'A'),
      gateway_id: I('lsgw', 'A'),
      run_id: I('lsrun', 'A'),
      call_id: I('lscall', 'A'),
      tool: 'search',
      adapter: 'native',
      result_ordinal: 0,
    },
    tool_error: false,
    blocks: [{ index: 0, text: 'Hello' }],
  },
};

// Receipt generation (spec 19): receipt n uses the nth allocator suffix for
// request/result/call/decision/receipt, text "Hello", time 999+n, prev =
// preceding generated receipt hash; seq 1 is exactly R0.
export function genReceipt(n: number, mode: 'rules_only' | 'required' = 'rules_only'): SignedReceipt {
  const c = String.fromCharCode(0x41 + n - 1);
  const config = mode === 'required' ? CM0 : C0;
  const candidate = {
    result_id: I('lsres', c),
    binding: {
      tenant_id: I('lsten', 'A'),
      gateway_id: I('lsgw', 'A'),
      run_id: I('lsrun', 'A'),
      call_id: I('lscall', c),
      tool: 'search',
      adapter: 'native',
      result_ordinal: 0,
    },
    tool_error: false,
    blocks: [{ index: 0, text: 'Hello' }],
  };
  const envelope = {
    type: 'lexsieve.tool-data.v1',
    result_id: I('lsres', c),
    decision_id: I('lsdec', c),
    receipt_id: I('lsrcp', c),
    trust: 'untrusted',
    disposition: 'pass',
    provenance: {
      tool: 'search',
      adapter: 'native',
      content_sha256: H(J(candidate.blocks as JsonValue)),
    },
    notice: null,
    data: candidate.blocks,
  };
  const decision: Decision = {
    decision_id: I('lsdec', c),
    result_id: I('lsres', c),
    input_hash: H(J(candidate as JsonValue)),
    snapshot: {
      epoch: 1,
      config_hash: H(J(config as unknown as JsonValue)),
      pack_hash: PH0,
      model_hash: mode === 'required' ? modelHash(M0) : null,
      lexshield_policy_hash: H0,
    },
    policy_result: { v: 1, policy_hash: H0, disposition: 'allow', reason: 'POLICY_ALLOW' },
    verdict: 'pass',
    reason: 'CLEAN',
    findings: [],
    replacements: [],
    output_hash: H(J(envelope as unknown as JsonValue)),
    quarantine_id: null,
  };
  const body: ReceiptBody = {
    v: 1,
    receipt_id: I('lsrcp', c),
    tenant_id: I('lsten', 'A'),
    gateway_id: I('lsgw', 'A'),
    seq: n,
    recorded_at_ms: 999 + n,
    prev_hash: n === 1 ? Z : genReceipt(n - 1, mode).hash,
    decision,
  };
  const { hash, signature } = signReceipt(body, seed);
  return { body, hash, key_id: I('lskey', 'B'), signature };
}

export const R0 = genReceipt(1);
export const S0: JsonValue = {
  v: 1,
  decision: R0.body.decision as unknown as JsonValue,
  envelope: {
    type: 'lexsieve.tool-data.v1',
    result_id: I('lsres', 'A'),
    decision_id: I('lsdec', 'A'),
    receipt_id: I('lsrcp', 'A'),
    trust: 'untrusted',
    disposition: 'pass',
    provenance: {
      tool: 'search',
      adapter: 'native',
      content_sha256: H(J((((Q0 as Record<string, JsonValue>)['candidate']) as Record<string, JsonValue>)['blocks'] as JsonValue)),
    },
    notice: null,
    data: (((Q0 as Record<string, JsonValue>)['candidate']) as Record<string, JsonValue>)['blocks'] as JsonValue,
  },
  receipt: R0 as unknown as JsonValue,
  cached: false,
};
export const E0 = (S0 as Record<string, JsonValue>)['envelope'] as JsonValue;
export const D0 = R0.body.decision;
