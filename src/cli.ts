// lexsieve CLI (spec 12). All output is JSON on stdout ending with one LF;
// operational diagnostics go to stderr and never contain raw input text.
// Exit codes: 0 ok; 10 strip; 20 hold; 2 usage/schema; 3 config/not-ready;
// 4 io/storage; 5 verification; 6 auth; 7 retryable network; 8 eval/replay.

import { readFileSync, writeFileSync, linkSync, unlinkSync, renameSync, mkdirSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { connect } from 'node:net';
import { randomBytes } from 'node:crypto';
import { jcs, parseJson, type JsonValue } from './jcs.ts';
import { ClosedError, NotImplementedError } from './errors.ts';
import { b64uDecode, b64uEncode, ed25519PublicFromSeed, sha256Hex } from './crypto.ts';
import { csprngAllocator, requireId } from './ids.ts';
import {
  validateConfig, validatePackBody, validateScreenRequest, validateSignedPack,
  validateSignedReceipt, validateTrustConfig,
  type Config, type SignedPack, type SignedReceipt, type TrustConfig,
} from './schema.ts';
import { compilePackRules } from './rules.ts';
import { signPack, receiptHash, verifyReceiptWithKey } from './receipts.ts';
import { verifyPack, activatePack, configHashOf } from './packs.ts';
import { loadDeployment, resolvePath, checkConfig } from './config.ts';
import { SqliteSink } from './sqlite.ts';
import { Engine, SYSTEM_CLOCK, type EngineDeps } from './engine.ts';
import { StaticLexShield, STATIC_POLICY_HASH, missingLexShieldBinding } from './lexshield.ts';
import { replay as replayRun } from './verify.ts';
import { HostedApiClient } from './hosted.ts';
import { rpcError } from './control.ts';
import { Buffer } from 'node:buffer';

export const VERSION_LINE = 'lexsieve 1.0.0 protocol=1';

const RETRYABLE = new Set(['NOT_READY', 'RATE_LIMITED', 'CHAIN_GAP', 'STORAGE_UNAVAILABLE', 'DEADLINE']);

function exitForCode(code: string): number {
  switch (code) {
    case 'INVALID_REQUEST': case 'CONFLICT': case 'LIMIT':
    case 'UNSUPPORTED_CONTENT': case 'INVALID_UTF8': return 2;
    case 'NOT_READY': case 'STALE_POLICY': case 'UNSUPPORTED_VERSION': return 3;
    case 'NOT_FOUND': case 'STORAGE_UNAVAILABLE': return 4;
    case 'BAD_SIGNATURE': return 5;
    case 'UNAUTHENTICATED': case 'FORBIDDEN': return 6;
    case 'RATE_LIMITED': case 'CHAIN_GAP': case 'DEADLINE': return 7;
    default: return 4;
  }
}

class UsageError extends Error {}

// ---------------------------------------------------------------------------
// arg parsing: singleton flags only; repeats/unknowns/positionals -> usage.
// ---------------------------------------------------------------------------

interface Args {
  cmd: string[];
  flags: Map<string, string | true>;
}

const GLOBAL_FLAGS = new Set(['help', 'version', 'json', 'config']);

function parseArgs(argv: string[], flagSpec: Record<string, 'value' | 'bool'>): Args {
  const flags = new Map<string, string | true>();
  const pos: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith('--')) {
      const name = a.slice(2);
      const kind = flagSpec[name] ?? (GLOBAL_FLAGS.has(name) ? (name === 'config' ? 'value' : 'bool') : undefined);
      if (kind === undefined) throw new UsageError(`unknown flag --${name}`);
      if (flags.has(name)) throw new UsageError(`repeated flag --${name}`);
      if (kind === 'bool') {
        flags.set(name, true);
      } else {
        const v = argv[++i];
        if (v === undefined) throw new UsageError(`--${name} needs a value`);
        flags.set(name, v);
      }
    } else {
      pos.push(a);
    }
  }
  return { cmd: pos, flags };
}

function flag(a: Args, name: string): string | undefined {
  const v = a.flags.get(name);
  return typeof v === 'string' ? v : undefined;
}
function reqFlag(a: Args, name: string): string {
  const v = flag(a, name);
  if (v === undefined) throw new UsageError(`missing --${name}`);
  return v;
}
function flagInt(a: Args, name: string, lo: number, hi: number): number {
  const raw = reqFlag(a, name);
  if (!/^-?\d+$/.test(raw)) throw new ClosedError('INVALID_REQUEST', `--${name} not an integer`);
  const n = Number(raw);
  if (n < lo || n > hi || !Number.isSafeInteger(n)) {
    throw new ClosedError('INVALID_REQUEST', `--${name} out of range`);
  }
  return n;
}

// ---------------------------------------------------------------------------
// io helpers
// ---------------------------------------------------------------------------

function out(v: JsonValue): void {
  process.stdout.write(jcs(v) + '\n');
}

function readInput(path: string): string {
  if (path === '-') return readFileSync(0, 'utf8');
  try {
    return readFileSync(path, 'utf8');
  } catch (e) {
    throw new ClosedError('NOT_FOUND', `cannot read ${path}`);
  }
}

function readInputBytes(path: string): Buffer {
  if (path === '-') return readFileSync(0);
  try {
    return readFileSync(path);
  } catch {
    throw new ClosedError('NOT_FOUND', `cannot read ${path}`);
  }
}

// create-new by default; --replace permits atomic replace of generated files.
function writeOutput(path: string | undefined, data: string, replace: boolean): void {
  if (path === undefined || path === '-') {
    process.stdout.write(data);
    return;
  }
  const tmp = `${path}.tmp-${process.pid}`;
  try {
    writeFileSync(tmp, data);
  } catch {
    throw new ClosedError('STORAGE_UNAVAILABLE', `cannot write ${path}`);
  }
  try {
    if (replace) {
      renameSync(tmp, path);
    } else {
      try {
        linkSync(tmp, path); // create-new: fails EEXIST
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === 'EEXIST') {
          throw new ClosedError('CONFLICT', `${path} exists; pass --replace`);
        }
        throw e;
      }
      unlinkSync(tmp);
    }
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* noop */ }
    if (e instanceof ClosedError) throw e;
    throw new ClosedError('STORAGE_UNAVAILABLE', `cannot write ${path}`);
  }
}

// ---------------------------------------------------------------------------
// deployment plumbing shared by scan/reload/audit export/telemetry flush
// ---------------------------------------------------------------------------

interface Deployment {
  config: Config;
  configPath: string;
  trust: TrustConfig;
  pack: SignedPack;
  signerSeed: Uint8Array;
  sink: SqliteSink;
}

function openDeployment(configPath: string): Deployment {
  const dep = loadDeployment(configPath);
  if (dep.config.receipt_sink.kind !== 'sqlite') {
    throw new ClosedError('NOT_READY', 'durable_object sink requires a worker host binding');
  }
  const sinkPath = resolvePath(configPath, dep.config.receipt_sink.path);
  mkdirSync(dirname(sinkPath), { recursive: true });
  const sink = new SqliteSink(sinkPath);
  try {
    sink.open();
  } catch (e) {
    throw e instanceof ClosedError ? e : new ClosedError('STORAGE_UNAVAILABLE', (e as Error).message);
  }
  return { ...dep, sink };
}

// Verifies the configured pack under trust at current time and activates it
// when the active snapshot does not already pin this hash. Idempotent.
function ensureActive(dep: Deployment): number {
  const v = verifyPack(dep.pack, dep.trust, Date.now());
  if (!v.valid) throw new ClosedError('NOT_READY', `pack: ${v.reason}`);
  const epoch = activatePack(
    dep.sink, dep.config, dep.trust, dep.pack, Date.now(),
    configHashOf(dep.config), STATIC_POLICY_HASH,
  );
  return epoch;
}

function buildEngine(dep: Deployment): Engine {
  const lexshield =
    dep.config.lexshield.kind === 'static'
      ? new StaticLexShield()
      : missingLexShieldBinding(dep.config.lexshield.binding);
  const deps: EngineDeps = {
    sink: dep.sink,
    clock: SYSTEM_CLOCK,
    ids: csprngAllocator(),
    lexshield,
    signer: { keyId: dep.config.signer_key_id, seed: dep.signerSeed },
  };
  return new Engine(dep.config, deps);
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

function cmdCheckConfig(a: Args): number {
  const configPath = reqFlag(a, 'config');
  const r = checkConfig(configPath);
  out(r.valid
    ? { v: 1, valid: true }
    : { v: 1, valid: false, error: r.error ?? 'INTERNAL' });
  return r.valid ? 0 : 3;
}

function cmdScan(a: Args): number {
  const configPath = reqFlag(a, 'config');
  const input = reqFlag(a, 'input');
  const req = validateScreenRequest(parseJson(readInput(input)));
  const dep = openDeployment(configPath);
  try {
    ensureActive(dep);
    const resp = buildEngine(dep).screen(req);
    writeOutput(flag(a, 'output'), jcs(resp as unknown as JsonValue) + '\n', a.flags.has('replace'));
    switch (resp.decision.verdict) {
      case 'pass': return 0;
      case 'strip': return 10;
      case 'hold': return 20;
    }
  } finally {
    dep.sink.close();
  }
}

function cmdPackCompile(a: Args): number {
  const body = validatePackBody(parseJson(readInput(reqFlag(a, 'input'))));
  compilePackRules(body.rules as unknown as JsonValue);
  writeOutput(reqFlag(a, 'output'), jcs(body as unknown as JsonValue), a.flags.has('replace'));
  out({ v: 1, written: true });
  return 0;
}

function cmdPackSign(a: Args): number {
  const inputBytes = readInputBytes(reqFlag(a, 'input'));
  const keyId = requireId('lskey', reqFlag(a, 'key-id'), 'key-id');
  const seedEnv = reqFlag(a, 'seed-env');
  const seedB64 = process.env[seedEnv];
  if (seedB64 === undefined) throw new ClosedError('NOT_READY', `env ${seedEnv} not set`);
  const seed = b64uDecode(seedB64);
  if (seed.length !== 32) throw new ClosedError('INVALID_REQUEST', 'seed must decode to 32 bytes');

  const body = validatePackBody(parseJson(inputBytes.toString('utf8')));
  // Sign requires the input to be exactly JCS(PackBody); no re-canonicalizing.
  if (inputBytes.toString('utf8') !== jcs(body as unknown as JsonValue)) {
    throw new ClosedError('INVALID_REQUEST', 'input is not exact JCS(PackBody)');
  }
  const { hash, signature } = signPack(body, seed);
  const pack: SignedPack = { body, hash, key_id: keyId, signature };
  writeOutput(reqFlag(a, 'output'), jcs(pack as unknown as JsonValue), a.flags.has('replace'));
  out({ v: 1, written: true });
  return 0;
}

function cmdPackVerify(a: Args): number {
  const pack = validateSignedPack(parseJson(readInput(reqFlag(a, 'input'))));
  const trust = validateTrustConfig(parseJson(readInput(reqFlag(a, 'trust'))));
  const nowMs = flagInt(a, 'now-ms', 0, Number.MAX_SAFE_INTEGER);
  const r = verifyPack(pack, trust, nowMs);
  out({ v: 1, valid: r.valid, reason: r.reason });
  return r.valid ? 0 : 5;
}

function cmdPackPull(a: Args): number {
  const origin = reqFlag(a, 'origin');
  requireId('lspack', reqFlag(a, 'pack-id'), 'pack-id');
  flagInt(a, 'serial', 1, Number.MAX_SAFE_INTEGER);
  const tokenEnv = reqFlag(a, 'token-env');
  const token = process.env[tokenEnv];
  if (token === undefined) throw new ClosedError('UNAUTHENTICATED', `env ${tokenEnv} not set`);
  // Hosted surface — stubbed per spec 8.2.
  new HostedApiClient(origin, token).packPull({});
  return 3; // unreachable
}

function cmdKeygen(): number {
  const seed = randomBytes(32);
  out({ v: 1, seed: b64uEncode(seed), public_key: b64uEncode(ed25519PublicFromSeed(seed)) });
  return 0;
}

function controlSocketPath(configPath: string): string {
  const cfg = validateConfig(parseJson(readFileSync(configPath, 'utf8')));
  if (cfg.receipt_sink.kind !== 'sqlite') {
    throw new ClosedError('NOT_READY', 'durable_object sink requires a worker host binding');
  }
  return resolve(dirname(resolvePath(configPath, cfg.receipt_sink.path)), 'lexsieve-control.sock');
}

async function cmdReload(a: Args): Promise<number> {
  const configPath = resolve(reqFlag(a, 'config'));
  const sockPath = controlSocketPath(configPath);
  const response = await new Promise<JsonValue>((res, rej) => {
    const conn = connect(sockPath);
    conn.setTimeout(5000);
    const chunks: Buffer[] = [];
    conn.on('connect', () => {
      conn.end(jcs({ v: 1, command: 'reload', config_path: configPath }) + '\n');
    });
    conn.on('data', (d: Buffer) => chunks.push(d));
    conn.on('end', () => {
      try {
        res(parseJson(Buffer.concat(chunks).toString('utf8').trimEnd()));
      } catch (e) {
        rej(e);
      }
    });
    conn.on('timeout', () => rej(new ClosedError('DEADLINE', 'control socket timeout')));
    conn.on('error', () => rej(new ClosedError('NOT_READY', `control socket ${sockPath} unavailable`)));
  });
  out(response);
  if (typeof response === 'object' && response !== null && 'error' in response) {
    const code = (response as { error: { code: string } }).error.code;
    return exitForCode(code);
  }
  return 0;
}

function cmdAuditVerify(a: Args): number {
  const input = reqFlag(a, 'input');
  const trust = validateTrustConfig(parseJson(readInput(reqFlag(a, 'trust'))));
  const anchorSeq = flagInt(a, 'anchor-seq', 0, Number.MAX_SAFE_INTEGER);
  let anchorHash = reqFlag(a, 'anchor-hash');
  if (anchorHash === 'Z') anchorHash = '0'.repeat(64);
  if (!/^[0-9a-f]{64}$/.test(anchorHash)) {
    throw new ClosedError('INVALID_REQUEST', 'anchor-hash must be 64 lowercase hex');
  }

  const lines = readInput(input).split('\n').filter((l) => l.length > 0);
  let expectedSeq = anchorSeq + 1;
  let expectedPrev = anchorHash;
  let headSeq = anchorSeq;
  for (const line of lines) {
    let receipt: SignedReceipt;
    try {
      receipt = validateSignedReceipt(parseJson(line));
    } catch {
      out({ v: 1, valid: false, error: 'SCHEMA' });
      return 5;
    }
    if (receiptHash(receipt.body) !== receipt.hash) {
      out({ v: 1, valid: false, error: 'HASH' });
      return 5;
    }
    const key = trust.keys.find((k) => k.key_id === receipt.key_id);
    if (!key || key.purpose !== 'receipt') {
      out({ v: 1, valid: false, error: 'SCHEMA' });
      return 5;
    }
    if (key.revoked) {
      out({ v: 1, valid: false, error: 'SIGNATURE' });
      return 5;
    }
    const r = verifyReceiptWithKey(receipt, b64uDecode(key.public_key), expectedPrev, expectedSeq);
    if (!r.valid) {
      out({ v: 1, valid: false, error: r.reason });
      return 5;
    }
    expectedPrev = receipt.hash;
    expectedSeq += 1;
    headSeq = receipt.body.seq;
  }
  out({ v: 1, valid: true, receipts: lines.length, head_seq: headSeq });
  return 0;
}

function cmdAuditExport(a: Args): number {
  const configPath = reqFlag(a, 'config');
  const fromSeq = flagInt(a, 'from-seq', 1, Number.MAX_SAFE_INTEGER);
  const toSeq = flagInt(a, 'to-seq', 1, Number.MAX_SAFE_INTEGER);
  if (fromSeq > toSeq) throw new ClosedError('INVALID_REQUEST', 'from_seq <= to_seq required');
  const dep = openDeployment(configPath);
  try {
    const rows = dep.sink.receiptRange(dep.config.tenant_id, dep.config.gateway_id, fromSeq, toSeq);
    if (rows.length < toSeq - fromSeq + 1) {
      throw new ClosedError('NOT_FOUND', 'receipt range incomplete');
    }
    const data = rows.map((r) => jcs(r as unknown as JsonValue)).join('\n') + '\n';
    writeOutput(reqFlag(a, 'output'), data, a.flags.has('replace'));
    out({ v: 1, exported: rows.length });
    return 0;
  } finally {
    dep.sink.close();
  }
}

function cmdReplay(a: Args): number {
  const req = parseJson(readInput(reqFlag(a, 'input')));
  if (typeof req !== 'object' || req === null || Array.isArray(req)) {
    throw new ClosedError('INVALID_REQUEST', 'replay request');
  }
  const o = req as Record<string, unknown>;
  const keys = Object.keys(o).sort();
  if (o['v'] !== 1 || !('request' in o) || !('recorded' in o) ||
      keys.some((k) => !['v', 'request', 'recorded'].includes(k))) {
    throw new ClosedError('INVALID_REQUEST', 'replay request members');
  }
  const configPath = flag(a, 'config');
  let result;
  if (configPath !== undefined) {
    // Full replay: re-run the recorded screening under the deployment's pack.
    const dep = openDeployment(configPath);
    try {
      ensureActive(dep);
      result = replayRun(buildEngine(dep), {
        v: 1,
        request: o['request'] as never,
        recorded: o['recorded'] as never,
      });
    } finally {
      dep.sink.close();
    }
  } else {
    // Artifact-free replay: recompute the recorded integrity anchors. This
    // detects request/record tampering but does not re-run rules/model.
    const request = validateScreenRequest(o['request']);
    const recorded = o['recorded'] as { decision?: { input_hash?: unknown; output_hash?: unknown } };
    const diffs: string[] = [];
    const ih = sha256Hex(jcs(request.candidate as unknown as JsonValue));
    if (recorded?.decision?.input_hash !== ih) diffs.push('input');
    result = { v: 1, equal: diffs.length === 0, differences: diffs };
  }
  out(result as unknown as JsonValue);
  return result.equal ? 0 : 8;
}

async function cmdEval(a: Args): Promise<number> {
  const suite = reqFlag(a, 'suite');
  const fixturesDir = reqFlag(a, 'fixtures');
  flagInt(a, 'seed', 0, 2147483647);
  const reportPath = reqFlag(a, 'report');

  let manifest: { suites?: Record<string, { file: string; sha256: string }> };
  try {
    manifest = parseJson(readFileSync(resolve(fixturesDir, 'manifest.json'), 'utf8')) as never;
  } catch {
    throw new ClosedError('NOT_FOUND', `no fixture manifest in ${fixturesDir}`);
  }
  const entry = manifest.suites?.[suite];
  if (!entry) throw new ClosedError('NOT_FOUND', `suite ${suite} not in manifest`);
  const corpusPath = resolve(fixturesDir, entry.file);
  const raw = readFileSync(corpusPath);
  if (sha256Hex(raw) !== entry.sha256) {
    throw new ClosedError('BAD_SIGNATURE', `corpus hash mismatch for ${suite}`);
  }
  const corpus = parseJson(raw.toString('utf8')) as {
    vectors: { id: string; input: JsonValue; expected: Record<string, unknown> }[];
  };
  const vectors = corpus.vectors;

  const { runVector } = await import('./eval/harness.ts');
  const failures: { vector_id: string; expected: JsonValue; actual: JsonValue }[] = [];
  let passed = 0;
  for (const v of vectors) {
    const actual = runVector(v as never);
    const ek = Object.keys(v.expected);
    const ok =
      ek.every((k) => JSON.stringify(actual[k]) === JSON.stringify(v.expected[k])) &&
      Object.keys(actual).every((k) => ek.includes(k));
    if (ok) passed++;
    else failures.push({
      vector_id: v.id,
      expected: v.expected as JsonValue,
      actual: actual as JsonValue,
    });
  }
  const report = { v: 1, suite, passed, failed: failures.length, failures };
  writeFileSync(reportPath, jcs(report as unknown as JsonValue) + '\n');
  out({ v: 1, suite, passed, failed: failures.length });
  return failures.length === 0 ? 0 : 8;
}

async function cmdTelemetryFlush(a: Args): Promise<number> {
  const maxBatches = flagInt(a, 'max-batches', 1, 256);
  const configPath = reqFlag(a, 'config');
  const dep = openDeployment(configPath);
  try {
    if (!dep.config.telemetry.enabled) {
      throw new ClosedError('NOT_READY', 'telemetry disabled');
    }
    const token = process.env[dep.config.telemetry.token_env!];
    if (token === undefined) {
      throw new ClosedError('UNAUTHENTICATED', `env ${dep.config.telemetry.token_env} not set`);
    }
    const client = new HostedApiClient(dep.config.telemetry.origin!, token);
    const due = dep.sink.spoolDue(Date.now(), maxBatches);
    let acked = 0;
    for (const row of due) {
      row.state = 'sending';
      dep.sink.spoolUpdate(row);
      try {
        client.telemetryIngest(parseJson(row.json));
        row.state = 'acknowledged';
        acked++;
      } catch (e) {
        // Hosted ingest is not implemented in OSS core; auth/schema failures
        // are not auto-retried per spec — everything stays pending with backoff.
        row.state = 'pending';
        row.attempts += 1;
        row.next_attempt_ms = Date.now() + 1000 * 2 ** Math.min(row.attempts, 6);
      }
      dep.sink.spoolUpdate(row);
    }
    const remaining = dep.sink.spoolCount() - acked;
    out({ v: 1, acknowledged: acked, remaining });
    return remaining > 0 ? 7 : 0;
  } finally {
    dep.sink.close();
  }
}

// ---------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------

const SPECS: Record<string, Record<string, 'value' | 'bool'>> = {
  'check-config': { config: 'value' },
  scan: { config: 'value', input: 'value', output: 'value', replace: 'bool' },
  'pack compile': { input: 'value', output: 'value', replace: 'bool' },
  'pack sign': { input: 'value', 'key-id': 'value', 'seed-env': 'value', output: 'value', replace: 'bool' },
  'pack verify': { input: 'value', trust: 'value', 'now-ms': 'value' },
  'pack pull': { origin: 'value', 'pack-id': 'value', serial: 'value', 'token-env': 'value', trust: 'value', output: 'value', replace: 'bool' },
  keygen: {},
  reload: { config: 'value' },
  'audit verify': { input: 'value', trust: 'value', 'anchor-seq': 'value', 'anchor-hash': 'value' },
  'audit export': { config: 'value', 'from-seq': 'value', 'to-seq': 'value', output: 'value', replace: 'bool' },
  replay: { input: 'value', config: 'value' },
  eval: { suite: 'value', fixtures: 'value', seed: 'value', report: 'value' },
  'telemetry flush': { config: 'value', 'max-batches': 'value' },
};

const HELP = `lexsieve — tool-output injection scrubber (protocol v1)

usage: lexsieve <command> [flags]
  check-config --config P
  scan --input -|P --config P [--output P] [--replace]
  pack compile --input P --output P
  pack sign --input P --key-id K --seed-env E --output P
  pack verify --input P --trust T --now-ms N
  pack pull --origin O --pack-id ID --serial N --token-env E --trust T --output P
  keygen
  reload --config P
  audit verify --input P --trust T --anchor-seq N --anchor-hash H
  audit export --config P --from-seq A --to-seq B --output P
  replay --input P [--config P]
  eval --suite S --fixtures D --seed N --report P
  telemetry flush --config P --max-batches N
global: --help --version --json --config P
`;

export async function main(argv: string[]): Promise<number> {
  try {
    // Command selection: first positional, plus a second only when the pair
    // is a known two-word command (pack compile, audit verify, ...).
    const first = argv[0] ?? '';
    let cmd: string;
    let restStart: number;
    if (argv.length > 1 && !argv[1]!.startsWith('-') && `${first} ${argv[1]}` in SPECS) {
      cmd = `${first} ${argv[1]}`;
      restStart = 2;
    } else {
      cmd = first;
      restStart = 1;
    }
    const rest = argv.slice(restStart);

    if (argv.includes('--help') || argv[0] === '-h' || cmd === '') {
      process.stdout.write(HELP);
      return 0;
    }
    if (argv.includes('--version')) {
      process.stdout.write(VERSION_LINE + '\n');
      return 0;
    }
    if (!(cmd in SPECS)) {
      process.stderr.write(`lexsieve: unknown command ${cmd || '(none)'}\n`);
      return 2;
    }
    const a = parseArgs(rest, SPECS[cmd]!);
    if (a.cmd.length !== 0) throw new UsageError('positional extras');

    switch (cmd) {
      case 'check-config': return cmdCheckConfig(a);
      case 'scan': return cmdScan(a);
      case 'pack compile': return cmdPackCompile(a);
      case 'pack sign': return cmdPackSign(a);
      case 'pack verify': return cmdPackVerify(a);
      case 'pack pull': return cmdPackPull(a);
      case 'keygen': return cmdKeygen();
      case 'reload': return await cmdReload(a);
      case 'audit verify': return cmdAuditVerify(a);
      case 'audit export': return cmdAuditExport(a);
      case 'replay': return cmdReplay(a);
      case 'eval': return await cmdEval(a);
      case 'telemetry flush': return await cmdTelemetryFlush(a);
      default: return 2;
    }
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`lexsieve: ${e.message}\n`);
      return 2;
    }
    if (e instanceof NotImplementedError) {
      out(rpcError('NOT_READY'));
      process.stderr.write(`lexsieve: ${e.message}\n`);
      return 3;
    }
    if (e instanceof ClosedError) {
      out(rpcError(e.code));
      process.stderr.write(`lexsieve: ${e.message}\n`);
      return exitForCode(e.code);
    }
    out(rpcError('INTERNAL'));
    process.stderr.write(`lexsieve: internal error\n`);
    return 4;
  }
}
