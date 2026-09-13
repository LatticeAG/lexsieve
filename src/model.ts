// Section 6.3: lexsieve.linear.v1 — local, signed, sparse integer linear
// classifier over word 1-, 2-, and 3-grams. Deterministic integer arithmetic;
// no tools, no network, no floating point.

import { ClosedError } from './errors.ts';
import { isObj, type JsonValue, jcs, jcsBytes } from './jcs.ts';
import { sha256Hex } from './crypto.ts';
import { isTokenChar } from './unicode.ts';
import type { AChar } from './normalize.ts';

export const MODEL_CLASSES = ['override', 'exfiltration', 'tool_directive'] as const;
export type ModelClass = (typeof MODEL_CLASSES)[number];

export interface ModelArtifact {
  format: 'lexsieve.linear.v1';
  unicode: '15.1.0';
  tokenizer: 'word-ngram-1-3-v1';
  classes: ['override', 'exfiltration', 'tool_directive'];
  bias: [number, number, number];
  threshold: number;
  weights: { feature: string; values: [number, number, number] }[];
}

const INT16_MIN = -32768;
const INT16_MAX = 32767;

function isInt16(n: unknown): n is number {
  return typeof n === 'number' && Number.isInteger(n) && n >= INT16_MIN && n <= INT16_MAX;
}

function utf8SortedUnique(arr: string[]): boolean {
  let prev: Buffer | null = null;
  for (const s of arr) {
    const b = Buffer.from(s, 'utf8');
    if (prev !== null && Buffer.compare(prev, b) >= 0) return false;
    prev = b;
  }
  return true;
}

// Validates a decoded JSON value as a ModelArtifact. The weights array must
// already be in ascending UTF-8 byte order with no duplicates; violations
// fail schema validation.
export function validateModelArtifact(v: unknown): ModelArtifact {
  if (!isObj(v as JsonValue)) throw new ClosedError('INVALID_REQUEST', 'model not object');
  const o = v as Record<string, JsonValue>;
  const keys = Object.keys(o).sort();
  if (keys.join(',') !== 'bias,classes,format,threshold,tokenizer,unicode,weights') {
    throw new ClosedError('INVALID_REQUEST', 'model members');
  }
  if (o['format'] !== 'lexsieve.linear.v1') throw new ClosedError('INVALID_REQUEST', 'model format');
  if (o['unicode'] !== '15.1.0') throw new ClosedError('INVALID_REQUEST', 'model unicode');
  if (o['tokenizer'] !== 'word-ngram-1-3-v1') {
    throw new ClosedError('INVALID_REQUEST', 'model tokenizer');
  }
  if (!Array.isArray(o['classes']) || o['classes'].join(',') !== MODEL_CLASSES.join(',')) {
    throw new ClosedError('INVALID_REQUEST', 'model classes');
  }
  if (!Array.isArray(o['bias']) || o['bias'].length !== 3 || !o['bias'].every(isInt16)) {
    throw new ClosedError('INVALID_REQUEST', 'model bias');
  }
  if (!isInt16(o['threshold'])) throw new ClosedError('INVALID_REQUEST', 'model threshold');
  if (!Array.isArray(o['weights']) || o['weights'].length > 4096) {
    throw new ClosedError('INVALID_REQUEST', 'model weights bound');
  }
  const features: string[] = [];
  const weights: ModelArtifact['weights'] = [];
  for (const w of o['weights']) {
    if (!isObj(w)) throw new ClosedError('INVALID_REQUEST', 'weight not object');
    const wk = Object.keys(w).sort();
    if (wk.join(',') !== 'feature,values') throw new ClosedError('INVALID_REQUEST', 'weight members');
    if (typeof w['feature'] !== 'string' || Buffer.byteLength(w['feature'], 'utf8') > 192) {
      throw new ClosedError('INVALID_REQUEST', 'feature size');
    }
    if (!Array.isArray(w['values']) || w['values'].length !== 3 || !w['values'].every(isInt16)) {
      throw new ClosedError('INVALID_REQUEST', 'weight values');
    }
    features.push(w['feature']);
    weights.push({ feature: w['feature'], values: w['values'] as [number, number, number] });
  }
  if (!utf8SortedUnique(features)) {
    throw new ClosedError('INVALID_REQUEST', 'weights not sorted/unique');
  }
  return {
    format: 'lexsieve.linear.v1',
    unicode: '15.1.0',
    tokenizer: 'word-ngram-1-3-v1',
    classes: ['override', 'exfiltration', 'tool_directive'],
    bias: o['bias'] as [number, number, number],
    threshold: o['threshold'],
    weights,
  };
}

export function modelHash(m: ModelArtifact): string {
  return sha256Hex(jcs(m as unknown as JsonValue));
}

// Tokenize one normalized view into maximal Letter/Number/Connector_Punctuation
// sequences, then emit the set union of 1/2/3-grams (tokens joined by one
// ASCII space). Features over 192 UTF-8 bytes are omitted.
export function featurize(views: AChar[][]): Set<string> {
  const features = new Set<string>();
  for (const view of views) {
    const tokens: string[] = [];
    let cur: number[] = [];
    for (const c of view) {
      if (isTokenChar(c.cp)) cur.push(c.cp);
      else if (cur.length) {
        tokens.push(String.fromCodePoint(...cur));
        cur = [];
      }
    }
    if (cur.length) tokens.push(String.fromCodePoint(...cur));
    for (let i = 0; i < tokens.length; i++) {
      let gram = tokens[i]!;
      if (Buffer.byteLength(gram, 'utf8') <= 192) features.add(gram);
      for (let w = 2; w <= 3 && i + w <= tokens.length; w++) {
        gram += ' ' + tokens[i + w - 1]!;
        if (Buffer.byteLength(gram, 'utf8') <= 192) features.add(gram);
      }
    }
  }
  return features;
}

export interface ModelResponse {
  v: 1;
  model_hash: string;
  scores: [number, number, number];
  positive: ModelClass[];
}

// score(ModelRequest) -> ModelResponse: pure function over a validated
// artifact. `features` must be unique and ascending UTF-8 sorted, capped at
// 32768.
export function score(artifact: ModelArtifact, features: string[]): ModelResponse {
  if (features.length > 32768) throw new ClosedError('INVALID_REQUEST', 'feature cap');
  if (!utf8SortedUnique(features)) throw new ClosedError('INVALID_REQUEST', 'features not sorted');
  const present = new Set(features);
  const scores: [number, number, number] = [artifact.bias[0], artifact.bias[1], artifact.bias[2]];
  for (const w of artifact.weights) {
    if (!present.has(w.feature)) continue;
    for (let c = 0; c < 3; c++) {
      const s = scores[c]! + w.values[c]!;
      if (s > 2147483647 || s < -2147483648) {
        throw new ClosedError('INTERNAL', 'score overflow');
      }
      scores[c] = s;
    }
  }
  const positive: ModelClass[] = [];
  for (let c = 0; c < 3; c++) {
    if (scores[c]! >= artifact.threshold) positive.push(MODEL_CLASSES[c]!);
  }
  return { v: 1, model_hash: modelHash(artifact), scores, positive };
}
