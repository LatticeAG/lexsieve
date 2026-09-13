// Golden anchors from section 19/4.4: the printed S0 values must match the
// implementation byte-for-byte — these pin JCS, hashing domains, Ed25519,
// the ID allocator, and the full screen path.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { jcs, type JsonValue } from '../src/jcs.ts';
import { sha256Hex, ed25519PublicFromSeed } from '../src/crypto.ts';
import { STATIC_POLICY_HASH } from '../src/lexshield.ts';
import { replay } from '../src/verify.ts';
import { ClosedError } from '../src/errors.ts';
import { MemorySink } from '../src/sink.ts';
import { SqliteSink } from '../src/sqlite.ts';
import { buildRuntimeForTest, runScreen } from './testkit.ts';
import {
  P0, PH0, Q0, R0, S0, T0, C0, CM0, M0, H0, I, J, H, seed, pub, genReceipt,
} from '../src/eval/fixture19.ts';
import { modelHash } from '../src/model.ts';

test('RFC8032 key derivation matches the fixture public key', () => {
  assert.equal(Buffer.from(pub).toString('hex'), 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
});

test('static policy hash matches H0', () => {
  assert.equal(STATIC_POLICY_HASH, '16a9ed3d0a547b3103e7d01ea797797422f0b396790ab7ea6a93ad8e1895e801');
});

test('P0 pack hash matches PH0 printed value', () => {
  assert.equal(P0.hash, '1adeb52efeda50e1586f25e1adf064430ca5c748440fb3ecd7e5adad0b4e76fb');
});

test('C0 config hash matches printed value', () => {
  assert.equal(H(J(C0 as unknown as JsonValue)), 'a1e7eb529ce214bb40165df566124e7c373b16c6995ea384a668a94d5504df2f');
});

test('R0 receipt hash and signature match the printed fixture', () => {
  assert.equal(R0.hash, 'e1ff9ff88352f3a6d74d406f2cd1172349224c7e51b50a1cddccc5ee2c014bb2');
  assert.equal(
    R0.signature,
    '8ldHhAWXawJLPwpoMZDEDO_znflMlx6Sk--1GA0MTr8Qa9Xj68QF8UFGvP45TMUjQwMNm0uuY3jauDQgUlpbBw',
  );
});

test('screen(Q0) under fixture runtime produces S0 exactly', () => {
  const rt = buildRuntimeForTest('R');
  const resp = rt.engine.screen(structuredClone(Q0));
  assert.equal(jcs(resp as never), jcs(S0 as never));
  assert.equal(resp.decision.input_hash, '58eafc3a1193bc0e7a2258644a862514d9cc2af5a1028507f2a987c6263307bb');
  assert.equal(resp.decision.output_hash, '1fef99be7abd8612d8cf4b2b66d7859fff029167850484206bb3b243f3d5d38f');
});

test('replay of recorded S0 is equal', () => {
  const rt = buildRuntimeForTest('R');
  const resp = rt.engine.screen(structuredClone(Q0));
  const r = replay(rt.engine, { v: 1, request: Q0 as never, recorded: resp });
  assert.deepEqual(r, { v: 1, equal: true, differences: [] });
});

test('sqlite sink round-trips commits and chain verification', () => {
  const sink = new SqliteSink(':memory:');
  const rt = buildRuntimeForTest('R', sink);
  const resp = rt.engine.screen(structuredClone(Q0));
  assert.equal(resp.decision.verdict, 'pass');
  assert.equal(sink.receiptCount(), 1);
  assert.equal(sink.verifyTail(C0.tenant_id, C0.gateway_id, 10), true);
  const stored = sink.getReceiptBySeq(C0.tenant_id, C0.gateway_id, 1);
  assert.equal(stored?.hash, R0.hash);
  sink.close();
});

test('memory and sqlite sinks produce identical committed objects', () => {
  const a = buildRuntimeForTest('R', new MemorySink());
  const b = buildRuntimeForTest('R', new SqliteSink(':memory:'));
  const ra = a.engine.screen(structuredClone(Q0));
  const rb = b.engine.screen(structuredClone(Q0));
  assert.equal(jcs(ra as never), jcs(rb as never));
});

test('replay reports a tampered input', () => {
  const rt = buildRuntimeForTest('R');
  const resp = rt.engine.screen(structuredClone(Q0));
  const tampered = structuredClone(Q0) as Record<string, unknown>;
  (tampered['candidate'] as Record<string, unknown>)['tool_error'] = true;
  const r = replay(rt.engine, { v: 1, request: tampered as never, recorded: resp });
  assert.equal(r.equal, false);
  assert.ok(r.differences.includes('input'));
});
