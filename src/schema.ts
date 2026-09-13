// Section 4.1 + 7 + 8 + 11 wire schemas. Closed unions, exact members,
// unknown members rejected at every level.

import { ClosedError } from './errors.ts';
import { checkExactKeys, isObj, type JsonValue } from './jcs.ts';
import { isValidId, requireId, type IdPrefix } from './ids.ts';
import { validateModelArtifact, type ModelArtifact } from './model.ts';
import type { Class } from './rules.ts';

export type Verdict = 'pass' | 'strip' | 'hold';
export type Reason =
  | 'CLEAN' | 'STRIPPED' | 'RULE_BLOCK' | 'MODEL_BLOCK' | 'MODEL_REQUIRED'
  | 'MODEL_TIMEOUT' | 'MODEL_INVALID' | 'LEXSHIELD_BLOCK' | 'LEXSHIELD_TIMEOUT'
  | 'LIMIT' | 'UNSUPPORTED_CONTENT' | 'INVALID_UTF8' | 'POLICY_CHANGED'
  | 'PACK_EXPIRED' | 'FINDING_LIMIT' | 'AUDIT_UNAVAILABLE' | 'DEADLINE';

export type AdapterKind = 'native' | 'mcp' | 'openai';

export interface Binding {
  tenant_id: string;
  gateway_id: string;
  run_id: string;
  call_id: string;
  tool: string;
  adapter: AdapterKind;
  result_ordinal: number;
}

export interface TextBlock {
  index: number;
  text: string;
}

export interface Candidate {
  result_id: string;
  binding: Binding;
  tool_error: boolean;
  blocks: TextBlock[];
}

export interface ScreenRequest {
  v: 1;
  request_id: string;
  candidate: Candidate;
}

export interface Snapshot {
  epoch: number;
  config_hash: string;
  pack_hash: string;
  model_hash: string | null;
  lexshield_policy_hash: string;
}

export interface Span {
  block: number;
  start: number;
  end: number;
}

export interface FindingWire {
  rule_id: string;
  class: Class;
  span: Span | null;
}

export interface Provenance {
  tool: string;
  adapter: AdapterKind;
  content_sha256: string;
}

export interface PolicyResponse {
  v: 1;
  policy_hash: string;
  disposition: 'allow' | 'block';
  reason: 'POLICY_ALLOW' | 'BLOCK_CLASS' | 'HARD_DENY';
}

export interface PolicyRequest {
  v: 1;
  request_id: string;
  binding: Binding;
  input_hash: string;
  snapshot: Snapshot;
  candidate_verdict: Verdict;
  classes: Class[];
}

export interface Decision {
  decision_id: string;
  result_id: string;
  input_hash: string;
  snapshot: Snapshot;
  policy_result: PolicyResponse | null;
  verdict: Verdict;
  reason: Reason;
  findings: FindingWire[];
  replacements: Span[];
  output_hash: string;
  quarantine_id: string | null;
}

export interface DataEnvelope {
  type: 'lexsieve.tool-data.v1';
  result_id: string;
  decision_id: string;
  receipt_id: string;
  trust: 'untrusted';
  disposition: Verdict;
  provenance: Provenance;
  notice: null | 'Suspect spans removed.' | 'Tool result withheld by LexSieve.';
  data: TextBlock[];
}

export interface QuarantineMetadata {
  v: 1;
  type: 'lexsieve.quarantine.v1';
  content_kind: 'suspected_instruction' | 'unclassified';
  quarantine_id: string;
  result_id: string;
  receipt_id: string;
  expires_at_ms: number;
}

export interface ReceiptBody {
  v: 1;
  receipt_id: string;
  tenant_id: string;
  gateway_id: string;
  seq: number;
  recorded_at_ms: number;
  prev_hash: string;
  decision: Decision;
}

export interface SignedReceipt {
  body: ReceiptBody;
  hash: string;
  key_id: string;
  signature: string;
}

export interface ScreenResponse {
  v: 1;
  decision: Decision;
  envelope: DataEnvelope;
  receipt: SignedReceipt;
  cached: boolean;
}

export interface ExtraRule {
  id: string;
  class: Class;
  action: 'strip' | 'hold';
  literals: string[];
}

export interface PackBody {
  v: 1;
  pack_id: string;
  serial: number;
  core_min: string;
  builtin_revision: 'builtin-1';
  created_at_ms: number;
  expires_at_ms: number;
  rules: ExtraRule[];
  model: ModelArtifact | null;
}

export interface SignedPack {
  body: PackBody;
  hash: string;
  key_id: string;
  signature: string;
}

export interface TrustKey {
  key_id: string;
  public_key: string;
  purpose: 'pack' | 'receipt';
  revoked: boolean;
}

export interface TrustConfig {
  v: 1;
  keys: TrustKey[];
}

export interface Config {
  v: 1;
  tenant_id: string;
  gateway_id: string;
  mode: 'required' | 'rules_only';
  pack_file: string;
  trust_file: string;
  signer_key_id: string;
  signer_seed_env: string;
  receipt_sink: { kind: 'sqlite'; path: string } | { kind: 'durable_object'; binding: string };
  lexshield: { kind: 'static' } | { kind: 'axion'; binding: string; policy_hash: string };
  telemetry: { enabled: boolean; origin: string | null; token_env: string | null };
  max_inflight: number;
  retention_days: number;
}

const HASH_RE = /^[0-9a-f]{64}$/;
const B64U_RE = /^[A-Za-z0-9_-]+$/;
const TAG_RE = /^[a-z][a-z0-9_.-]{0,63}$/;
const TOOL_RE = /^[A-Za-z0-9_.:/-]{1,128}$/;
const ENV_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
const SEMVER_RE = /^\d+\.\d+\.\d+$/;

export function isHash(v: unknown): v is string {
  return typeof v === 'string' && HASH_RE.test(v);
}
export function isB64u(v: unknown, bytes: number): v is string {
  if (typeof v !== 'string' || !B64U_RE.test(v)) return false;
  const dec = Buffer.from(v, 'base64url');
  return dec.length === bytes;
}
function isPosInt(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 1;
}
function isNonNegInt(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
}

export function validateBinding(v: unknown): Binding {
  if (!isObj(v as JsonValue)) throw new ClosedError('INVALID_REQUEST', 'binding');
  const o = v as Record<string, JsonValue>;
  checkExactKeys(o, ['tenant_id', 'gateway_id', 'run_id', 'call_id', 'tool', 'adapter', 'result_ordinal'], 'binding');
  requireId('lsten', o['tenant_id'], 'tenant_id');
  requireId('lsgw', o['gateway_id'], 'gateway_id');
  requireId('lsrun', o['run_id'], 'run_id');
  requireId('lscall', o['call_id'], 'call_id');
  if (typeof o['tool'] !== 'string' || !TOOL_RE.test(o['tool'])) {
    throw new ClosedError('INVALID_REQUEST', 'tool');
  }
  if (o['adapter'] !== 'native' && o['adapter'] !== 'mcp' && o['adapter'] !== 'openai') {
    throw new ClosedError('INVALID_REQUEST', 'adapter');
  }
  if (!isNonNegInt(o['result_ordinal']) || o['result_ordinal'] > 255) {
    throw new ClosedError('INVALID_REQUEST', 'result_ordinal');
  }
  return o as unknown as Binding;
}

export function validateTextBlocks(v: unknown): TextBlock[] {
  if (!Array.isArray(v)) throw new ClosedError('INVALID_REQUEST', 'blocks not array');
  if (v.length < 1 || v.length > 8) throw new ClosedError('INVALID_REQUEST', 'block count');
  let total = 0;
  const out: TextBlock[] = [];
  v.forEach((b, i) => {
    if (!isObj(b)) throw new ClosedError('INVALID_REQUEST', 'block not object');
    checkExactKeys(b, ['index', 'text'], 'block');
    if (b['index'] !== i) throw new ClosedError('INVALID_REQUEST', 'block index not contiguous');
    if (typeof b['text'] !== 'string') throw new ClosedError('INVALID_REQUEST', 'block text');
    const nb = Buffer.byteLength(b['text'], 'utf8');
    if (nb > 32768) throw new ClosedError('INVALID_REQUEST', 'block size');
    total += nb;
    out.push({ index: i, text: b['text'] });
  });
  if (total > 32768) throw new ClosedError('INVALID_REQUEST', 'total size');
  return out;
}

export function validateCandidate(v: unknown): Candidate {
  if (!isObj(v as JsonValue)) throw new ClosedError('INVALID_REQUEST', 'candidate');
  const o = v as Record<string, JsonValue>;
  checkExactKeys(o, ['result_id', 'binding', 'tool_error', 'blocks'], 'candidate');
  requireId('lsres', o['result_id'], 'result_id');
  const binding = validateBinding(o['binding']);
  if (typeof o['tool_error'] !== 'boolean') throw new ClosedError('INVALID_REQUEST', 'tool_error');
  const blocks = validateTextBlocks(o['blocks']);
  return { result_id: o['result_id'] as string, binding, tool_error: o['tool_error'], blocks };
}

export function validateScreenRequest(v: unknown): ScreenRequest {
  if (!isObj(v as JsonValue)) throw new ClosedError('INVALID_REQUEST', 'screen request');
  const o = v as Record<string, JsonValue>;
  checkExactKeys(o, ['v', 'request_id', 'candidate'], 'screen request');
  if (o['v'] !== 1) throw new ClosedError('UNSUPPORTED_VERSION', 'v');
  requireId('lsreq', o['request_id'], 'request_id');
  const candidate = validateCandidate(o['candidate']);
  return { v: 1, request_id: o['request_id'] as string, candidate };
}

export function validateSnapshot(v: unknown): Snapshot {
  if (!isObj(v as JsonValue)) throw new ClosedError('INVALID_REQUEST', 'snapshot');
  const o = v as Record<string, JsonValue>;
  checkExactKeys(o, ['epoch', 'config_hash', 'pack_hash', 'model_hash', 'lexshield_policy_hash'], 'snapshot');
  if (!isPosInt(o['epoch'])) throw new ClosedError('INVALID_REQUEST', 'epoch');
  if (!isHash(o['config_hash']) || !isHash(o['pack_hash']) || !isHash(o['lexshield_policy_hash'])) {
    throw new ClosedError('INVALID_REQUEST', 'snapshot hash');
  }
  if (o['model_hash'] !== null && !isHash(o['model_hash'])) {
    throw new ClosedError('INVALID_REQUEST', 'model_hash');
  }
  return o as unknown as Snapshot;
}

export function validateSpan(v: unknown): Span {
  if (!isObj(v as JsonValue)) throw new ClosedError('INVALID_REQUEST', 'span');
  const o = v as Record<string, JsonValue>;
  checkExactKeys(o, ['block', 'start', 'end'], 'span');
  if (!isNonNegInt(o['block'])) throw new ClosedError('INVALID_REQUEST', 'span.block');
  if (!isNonNegInt(o['start']) || !isNonNegInt(o['end'])) {
    throw new ClosedError('INVALID_REQUEST', 'span offset');
  }
  if ((o['end'] as number) <= (o['start'] as number) || (o['end'] as number) > 32768) {
    throw new ClosedError('INVALID_REQUEST', 'span range');
  }
  return o as unknown as Span;
}

const CLASSES: Class[] = ['override', 'exfiltration', 'tool_directive', 'role_spoof', 'encoding', 'credential'];
const VERDICTS: Verdict[] = ['pass', 'strip', 'hold'];
const REASONS: Reason[] = [
  'CLEAN', 'STRIPPED', 'RULE_BLOCK', 'MODEL_BLOCK', 'MODEL_REQUIRED', 'MODEL_TIMEOUT',
  'MODEL_INVALID', 'LEXSHIELD_BLOCK', 'LEXSHIELD_TIMEOUT', 'LIMIT', 'UNSUPPORTED_CONTENT',
  'INVALID_UTF8', 'POLICY_CHANGED', 'PACK_EXPIRED', 'FINDING_LIMIT', 'AUDIT_UNAVAILABLE', 'DEADLINE',
];

export function validateFindings(v: unknown): FindingWire[] {
  if (!Array.isArray(v) || v.length > 64) throw new ClosedError('INVALID_REQUEST', 'findings');
  const out: FindingWire[] = [];
  for (const f of v) {
    if (!isObj(f)) throw new ClosedError('INVALID_REQUEST', 'finding');
    checkExactKeys(f, ['rule_id', 'class', 'span'], 'finding');
    if (typeof f['rule_id'] !== 'string' || !TAG_RE.test(f['rule_id'])) {
      throw new ClosedError('INVALID_REQUEST', 'rule_id');
    }
    if (!CLASSES.includes(f['class'] as Class)) throw new ClosedError('INVALID_REQUEST', 'class');
    const span = f['span'] === null ? null : validateSpan(f['span']);
    out.push({ rule_id: f['rule_id'], class: f['class'] as Class, span });
  }
  return out;
}

export function validatePolicyResponse(v: unknown): PolicyResponse {
  if (!isObj(v as JsonValue)) throw new ClosedError('INVALID_REQUEST', 'policy response');
  const o = v as Record<string, JsonValue>;
  checkExactKeys(o, ['v', 'policy_hash', 'disposition', 'reason'], 'policy response');
  if (o['v'] !== 1) throw new ClosedError('INVALID_REQUEST', 'v');
  if (!isHash(o['policy_hash'])) throw new ClosedError('INVALID_REQUEST', 'policy_hash');
  if (o['disposition'] !== 'allow' && o['disposition'] !== 'block') {
    throw new ClosedError('INVALID_REQUEST', 'disposition');
  }
  if (!['POLICY_ALLOW', 'BLOCK_CLASS', 'HARD_DENY'].includes(o['reason'] as string)) {
    throw new ClosedError('INVALID_REQUEST', 'policy reason');
  }
  return o as unknown as PolicyResponse;
}

export function validateDecision(v: unknown): Decision {
  if (!isObj(v as JsonValue)) throw new ClosedError('INVALID_REQUEST', 'decision');
  const o = v as Record<string, JsonValue>;
  checkExactKeys(o, [
    'decision_id', 'result_id', 'input_hash', 'snapshot', 'policy_result', 'verdict',
    'reason', 'findings', 'replacements', 'output_hash', 'quarantine_id',
  ], 'decision');
  requireId('lsdec', o['decision_id'], 'decision_id');
  requireId('lsres', o['result_id'], 'result_id');
  if (!isHash(o['input_hash']) || !isHash(o['output_hash'])) {
    throw new ClosedError('INVALID_REQUEST', 'decision hash');
  }
  const snapshot = validateSnapshot(o['snapshot']);
  const policy_result = o['policy_result'] === null ? null : validatePolicyResponse(o['policy_result']);
  if (!VERDICTS.includes(o['verdict'] as Verdict)) throw new ClosedError('INVALID_REQUEST', 'verdict');
  if (!REASONS.includes(o['reason'] as Reason)) throw new ClosedError('INVALID_REQUEST', 'reason');
  const findings = validateFindings(o['findings']);
  if (!Array.isArray(o['replacements']) || (o['replacements'] as JsonValue[]).length > 64) {
    throw new ClosedError('INVALID_REQUEST', 'replacements');
  }
  const replacements = (o['replacements'] as JsonValue[]).map(validateSpan);
  if (o['quarantine_id'] !== null && !isValidId('lsq', o['quarantine_id'])) {
    throw new ClosedError('INVALID_REQUEST', 'quarantine_id');
  }
  return {
    decision_id: o['decision_id'] as string,
    result_id: o['result_id'] as string,
    input_hash: o['input_hash'] as string,
    snapshot,
    policy_result,
    verdict: o['verdict'] as Verdict,
    reason: o['reason'] as Reason,
    findings,
    replacements,
    output_hash: o['output_hash'] as string,
    quarantine_id: o['quarantine_id'] as string | null,
  };
}

export function validateReceiptBody(v: unknown): ReceiptBody {
  if (!isObj(v as JsonValue)) throw new ClosedError('INVALID_REQUEST', 'receipt body');
  const o = v as Record<string, JsonValue>;
  checkExactKeys(o, ['v', 'receipt_id', 'tenant_id', 'gateway_id', 'seq', 'recorded_at_ms', 'prev_hash', 'decision'], 'receipt body');
  if (o['v'] !== 1) throw new ClosedError('INVALID_REQUEST', 'v');
  requireId('lsrcp', o['receipt_id'], 'receipt_id');
  requireId('lsten', o['tenant_id'], 'tenant_id');
  requireId('lsgw', o['gateway_id'], 'gateway_id');
  if (!isPosInt(o['seq'])) throw new ClosedError('INVALID_REQUEST', 'seq');
  if (!isNonNegInt(o['recorded_at_ms'])) throw new ClosedError('INVALID_REQUEST', 'recorded_at_ms');
  if (!isHash(o['prev_hash'])) throw new ClosedError('INVALID_REQUEST', 'prev_hash');
  const decision = validateDecision(o['decision']);
  return { ...(o as unknown as Omit<ReceiptBody, 'decision'>), decision };
}

export function validateSignedReceipt(v: unknown): SignedReceipt {
  if (!isObj(v as JsonValue)) throw new ClosedError('INVALID_REQUEST', 'receipt');
  const o = v as Record<string, JsonValue>;
  checkExactKeys(o, ['body', 'hash', 'key_id', 'signature'], 'receipt');
  const body = validateReceiptBody(o['body']);
  if (!isHash(o['hash'])) throw new ClosedError('INVALID_REQUEST', 'hash');
  requireId('lskey', o['key_id'], 'key_id');
  if (!isB64u(o['signature'], 64)) throw new ClosedError('INVALID_REQUEST', 'signature');
  return { body, hash: o['hash'] as string, key_id: o['key_id'] as string, signature: o['signature'] as string };
}

export function validateEnvelope(v: unknown): DataEnvelope {
  if (!isObj(v as JsonValue)) throw new ClosedError('INVALID_REQUEST', 'envelope');
  const o = v as Record<string, JsonValue>;
  checkExactKeys(o, ['type', 'result_id', 'decision_id', 'receipt_id', 'trust', 'disposition', 'provenance', 'notice', 'data'], 'envelope');
  if (o['type'] !== 'lexsieve.tool-data.v1') throw new ClosedError('INVALID_REQUEST', 'type');
  requireId('lsres', o['result_id'], 'result_id');
  requireId('lsdec', o['decision_id'], 'decision_id');
  requireId('lsrcp', o['receipt_id'], 'receipt_id');
  if (o['trust'] !== 'untrusted') throw new ClosedError('INVALID_REQUEST', 'trust');
  if (!VERDICTS.includes(o['disposition'] as Verdict)) throw new ClosedError('INVALID_REQUEST', 'disposition');
  const pv = o['provenance'];
  if (!isObj(pv)) throw new ClosedError('INVALID_REQUEST', 'provenance');
  checkExactKeys(pv, ['tool', 'adapter', 'content_sha256'], 'provenance');
  if (typeof pv['tool'] !== 'string' || !TOOL_RE.test(pv['tool'])) {
    throw new ClosedError('INVALID_REQUEST', 'provenance.tool');
  }
  if (pv['adapter'] !== 'native' && pv['adapter'] !== 'mcp' && pv['adapter'] !== 'openai') {
    throw new ClosedError('INVALID_REQUEST', 'provenance.adapter');
  }
  if (!isHash(pv['content_sha256'])) throw new ClosedError('INVALID_REQUEST', 'content_sha256');
  const notice = o['notice'];
  if (notice !== null && notice !== 'Suspect spans removed.' && notice !== 'Tool result withheld by LexSieve.') {
    throw new ClosedError('INVALID_REQUEST', 'notice');
  }
  const dv = o['data'];
  if (!Array.isArray(dv) || dv.length > 8) throw new ClosedError('INVALID_REQUEST', 'data');
  dv.forEach((b, i) => {
    if (!isObj(b)) throw new ClosedError('INVALID_REQUEST', 'data block');
    checkExactKeys(b, ['index', 'text'], 'data block');
    if (b['index'] !== i) throw new ClosedError('INVALID_REQUEST', 'data index');
    if (typeof b['text'] !== 'string' || Buffer.byteLength(b['text'], 'utf8') > 32768) {
      throw new ClosedError('INVALID_REQUEST', 'data text');
    }
  });
  return o as unknown as DataEnvelope;
}

export function validatePackBody(v: unknown): PackBody {
  if (!isObj(v as JsonValue)) throw new ClosedError('INVALID_REQUEST', 'pack body');
  const o = v as Record<string, JsonValue>;
  checkExactKeys(o, ['v', 'pack_id', 'serial', 'core_min', 'builtin_revision', 'created_at_ms', 'expires_at_ms', 'rules', 'model'], 'pack body');
  if (o['v'] !== 1) throw new ClosedError('INVALID_REQUEST', 'v');
  requireId('lspack', o['pack_id'], 'pack_id');
  if (!isPosInt(o['serial'])) throw new ClosedError('INVALID_REQUEST', 'serial');
  if (typeof o['core_min'] !== 'string' || !SEMVER_RE.test(o['core_min'])) {
    throw new ClosedError('INVALID_REQUEST', 'core_min');
  }
  if (o['builtin_revision'] !== 'builtin-1') throw new ClosedError('INVALID_REQUEST', 'builtin_revision');
  if (!isNonNegInt(o['created_at_ms']) || !isNonNegInt(o['expires_at_ms'])) {
    throw new ClosedError('INVALID_REQUEST', 'times');
  }
  if ((o['expires_at_ms'] as number) <= (o['created_at_ms'] as number)) {
    throw new ClosedError('INVALID_REQUEST', 'expiry before creation');
  }
  if ((o['expires_at_ms'] as number) - (o['created_at_ms'] as number) > 90 * 86400000) {
    throw new ClosedError('INVALID_REQUEST', 'expiry window');
  }
  const model = o['model'] === null ? null : validateModelArtifact(o['model']);
  const rules = o['rules'] as unknown as ExtraRule[];
  return {
    v: 1,
    pack_id: o['pack_id'] as string,
    serial: o['serial'] as number,
    core_min: o['core_min'] as string,
    builtin_revision: 'builtin-1',
    created_at_ms: o['created_at_ms'] as number,
    expires_at_ms: o['expires_at_ms'] as number,
    rules,
    model,
  };
}

export function validateSignedPack(v: unknown): SignedPack {
  if (!isObj(v as JsonValue)) throw new ClosedError('INVALID_REQUEST', 'pack');
  const o = v as Record<string, JsonValue>;
  checkExactKeys(o, ['body', 'hash', 'key_id', 'signature'], 'pack');
  const body = validatePackBody(o['body']);
  if (!isHash(o['hash'])) throw new ClosedError('INVALID_REQUEST', 'pack hash');
  requireId('lskey', o['key_id'], 'key_id');
  if (!isB64u(o['signature'], 64)) throw new ClosedError('INVALID_REQUEST', 'signature');
  return { body, hash: o['hash'] as string, key_id: o['key_id'] as string, signature: o['signature'] as string };
}

export function validateTrustConfig(v: unknown): TrustConfig {
  if (!isObj(v as JsonValue)) throw new ClosedError('INVALID_REQUEST', 'trust');
  const o = v as Record<string, JsonValue>;
  checkExactKeys(o, ['v', 'keys'], 'trust');
  if (o['v'] !== 1) throw new ClosedError('INVALID_REQUEST', 'v');
  if (!Array.isArray(o['keys']) || o['keys'].length < 1 || o['keys'].length > 64) {
    throw new ClosedError('INVALID_REQUEST', 'trust keys');
  }
  const seen = new Set<string>();
  const keys: TrustKey[] = [];
  for (const k of o['keys']) {
    if (!isObj(k)) throw new ClosedError('INVALID_REQUEST', 'trust key');
    checkExactKeys(k, ['key_id', 'public_key', 'purpose', 'revoked'], 'trust key');
    requireId('lskey', k['key_id'], 'key_id');
    if (!isB64u(k['public_key'], 32)) throw new ClosedError('INVALID_REQUEST', 'public_key');
    if (k['purpose'] !== 'pack' && k['purpose'] !== 'receipt') {
      throw new ClosedError('INVALID_REQUEST', 'purpose');
    }
    if (typeof k['revoked'] !== 'boolean') throw new ClosedError('INVALID_REQUEST', 'revoked');
    if (seen.has(k['key_id'] as string)) throw new ClosedError('INVALID_REQUEST', 'duplicate key_id');
    seen.add(k['key_id'] as string);
    keys.push(k as unknown as TrustKey);
  }
  return { v: 1, keys };
}

export function validateConfig(v: unknown): Config {
  if (!isObj(v as JsonValue)) throw new ClosedError('INVALID_REQUEST', 'config');
  const o = v as Record<string, JsonValue>;
  checkExactKeys(o, [
    'v', 'tenant_id', 'gateway_id', 'mode', 'pack_file', 'trust_file', 'signer_key_id',
    'signer_seed_env', 'receipt_sink', 'lexshield', 'telemetry', 'max_inflight', 'retention_days',
  ], 'config');
  if (o['v'] !== 1) throw new ClosedError('INVALID_REQUEST', 'v');
  requireId('lsten', o['tenant_id'], 'tenant_id');
  requireId('lsgw', o['gateway_id'], 'gateway_id');
  if (o['mode'] !== 'required' && o['mode'] !== 'rules_only') {
    throw new ClosedError('INVALID_REQUEST', 'mode');
  }
  if (typeof o['pack_file'] !== 'string' || typeof o['trust_file'] !== 'string' || !o['pack_file'] || !o['trust_file']) {
    throw new ClosedError('INVALID_REQUEST', 'file path');
  }
  requireId('lskey', o['signer_key_id'], 'signer_key_id');
  if (typeof o['signer_seed_env'] !== 'string' || !ENV_RE.test(o['signer_seed_env'])) {
    throw new ClosedError('INVALID_REQUEST', 'signer_seed_env');
  }
  const rs = o['receipt_sink'];
  if (!isObj(rs)) throw new ClosedError('INVALID_REQUEST', 'receipt_sink');
  let receipt_sink: Config['receipt_sink'];
  if (rs['kind'] === 'sqlite') {
    checkExactKeys(rs, ['kind', 'path'], 'receipt_sink');
    if (typeof rs['path'] !== 'string' || !rs['path']) throw new ClosedError('INVALID_REQUEST', 'sink path');
    receipt_sink = { kind: 'sqlite', path: rs['path'] };
  } else if (rs['kind'] === 'durable_object') {
    checkExactKeys(rs, ['kind', 'binding'], 'receipt_sink');
    if (typeof rs['binding'] !== 'string' || !rs['binding']) throw new ClosedError('INVALID_REQUEST', 'sink binding');
    receipt_sink = { kind: 'durable_object', binding: rs['binding'] };
  } else {
    throw new ClosedError('INVALID_REQUEST', 'sink kind');
  }
  const ls = o['lexshield'];
  if (!isObj(ls)) throw new ClosedError('INVALID_REQUEST', 'lexshield');
  let lexshield: Config['lexshield'];
  if (ls['kind'] === 'static') {
    checkExactKeys(ls, ['kind'], 'lexshield');
    lexshield = { kind: 'static' };
  } else if (ls['kind'] === 'axion') {
    checkExactKeys(ls, ['kind', 'binding', 'policy_hash'], 'lexshield');
    if (typeof ls['binding'] !== 'string' || !ls['binding']) throw new ClosedError('INVALID_REQUEST', 'binding');
    if (!isHash(ls['policy_hash'])) throw new ClosedError('INVALID_REQUEST', 'policy_hash');
    lexshield = { kind: 'axion', binding: ls['binding'], policy_hash: ls['policy_hash'] };
  } else {
    throw new ClosedError('INVALID_REQUEST', 'lexshield kind');
  }
  const tel = o['telemetry'];
  if (!isObj(tel)) throw new ClosedError('INVALID_REQUEST', 'telemetry');
  checkExactKeys(tel, ['enabled', 'origin', 'token_env'], 'telemetry');
  if (typeof tel['enabled'] !== 'boolean') throw new ClosedError('INVALID_REQUEST', 'telemetry.enabled');
  let telemetry: Config['telemetry'];
  if (tel['enabled']) {
    if (typeof tel['origin'] !== 'string' || !/^https:\/\/[^/?#]+$/.test(tel['origin'])) {
      throw new ClosedError('INVALID_REQUEST', 'telemetry.origin');
    }
    if (typeof tel['token_env'] !== 'string' || !ENV_RE.test(tel['token_env'])) {
      throw new ClosedError('INVALID_REQUEST', 'telemetry.token_env');
    }
    telemetry = { enabled: true, origin: tel['origin'], token_env: tel['token_env'] };
  } else {
    if (tel['origin'] !== null || tel['token_env'] !== null) {
      throw new ClosedError('INVALID_REQUEST', 'telemetry disabled requires nulls');
    }
    telemetry = { enabled: false, origin: null, token_env: null };
  }
  if (!isPosInt(o['max_inflight']) || o['max_inflight'] > 64) {
    throw new ClosedError('INVALID_REQUEST', 'max_inflight');
  }
  if (!isPosInt(o['retention_days']) || o['retention_days'] > 365) {
    throw new ClosedError('INVALID_REQUEST', 'retention_days');
  }
  return {
    v: 1,
    tenant_id: o['tenant_id'] as string,
    gateway_id: o['gateway_id'] as string,
    mode: o['mode'],
    pack_file: o['pack_file'],
    trust_file: o['trust_file'],
    signer_key_id: o['signer_key_id'] as string,
    signer_seed_env: o['signer_seed_env'],
    receipt_sink,
    lexshield,
    telemetry,
    max_inflight: o['max_inflight'],
    retention_days: o['retention_days'],
  };
}
