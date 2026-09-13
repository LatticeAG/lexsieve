// RFC 8785 JCS canonicalization and the strict JSON parser used at every
// LexSieve boundary. Wire profile (spec section 4): UTF-8 without BOM, no
// duplicate object keys, no lone surrogates, no NaN/Infinity/-0, no
// fractional numbers; numbers are safe integers.

import { ClosedError } from './errors.ts';

export type JsonValue = string | number | boolean | null | JsonValue[] | { [k: string]: JsonValue };

const HEX = '0123456789abcdef';

function escapeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += '\\\\';
    else if (c === 0x08) out += '\\b';
    else if (c === 0x09) out += '\\t';
    else if (c === 0x0a) out += '\\n';
    else if (c === 0x0c) out += '\\f';
    else if (c === 0x0d) out += '\\r';
    else if (c < 0x20) out += '\\u00' + HEX[(c >> 4) & 0xf] + HEX[c & 0xf];
    else out += s[i];
  }
  return out + '"';
}

// Canonical JCS serialization. All numbers in the LexSieve wire profile are
// safe integers, so Number::toString is exact.
export function jcs(v: JsonValue): string {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new ClosedError('INVALID_REQUEST', 'non-integer in JCS');
    if (Object.is(v, -0)) throw new ClosedError('INVALID_REQUEST', 'negative zero in JCS');
    return String(v);
  }
  if (typeof v === 'string') return escapeString(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  const keys = Object.keys(v).sort();
  return '{' + keys.map((k) => escapeString(k) + ':' + jcs(v[k]!)).join(',') + '}';
}

export function jcsBytes(v: JsonValue): Uint8Array {
  return new TextEncoder().encode(jcs(v));
}

export interface ParseLimits {
  maxDepth: number;
  maxNodes: number;
}

export const DEFAULT_PARSE_LIMITS: ParseLimits = { maxDepth: 512, maxNodes: 65536 };
export const AUX_JSON_LIMITS: ParseLimits = { maxDepth: 16, maxNodes: 2048 };

// Thrown when a bounded auxiliary parse crosses a declared limit. Callers
// that need LIMIT semantics (hold, not parse failure) catch this type.
export class JsonLimitError extends Error {
  constructor(what: string) {
    super(what);
    this.name = 'JsonLimitError';
  }
}

export class JsonSyntaxError extends Error {
  constructor(what: string) {
    super(what);
    this.name = 'JsonSyntaxError';
  }
}

class Parser {
  private readonly text: string;
  private readonly limits: ParseLimits;
  private readonly stringSpans: [number, number][] | undefined;
  private pos = 0;
  private nodes = 0;
  constructor(text: string, limits: ParseLimits, stringSpans?: [number, number][]) {
    this.text = text;
    this.limits = limits;
    this.stringSpans = stringSpans;
  }

  parse(): JsonValue {
    this.ws();
    const v = this.value(0);
    this.ws();
    if (this.pos !== this.text.length) this.fail('trailing data');
    return v;
  }

  private fail(why: string): never {
    throw new JsonSyntaxError(`${why} at ${this.pos}`);
  }

  private failLimit(what: string): never {
    throw new JsonLimitError(what);
  }

  private ws(): void {
    while (this.pos < this.text.length) {
      const c = this.text.charCodeAt(this.pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.pos++;
      else break;
    }
  }

  private value(depth: number): JsonValue {
    if (depth > this.limits.maxDepth) this.failLimit('depth');
    if (++this.nodes > this.limits.maxNodes) this.failLimit('nodes');
    const c = this.text.charCodeAt(this.pos);
    if (c === 0x7b) return this.object(depth);
    if (c === 0x5b) return this.array(depth);
    if (c === 0x22) return this.string();
    if (c === 0x74) return this.lit('true', true);
    if (c === 0x66) return this.lit('false', false);
    if (c === 0x6e) return this.lit('null', null);
    if (c === 0x2d || (c >= 0x30 && c <= 0x39)) return this.number();
    this.fail('unexpected character');
  }

  private lit(word: string, val: JsonValue): JsonValue {
    if (this.text.startsWith(word, this.pos)) {
      this.pos += word.length;
      return val;
    }
    this.fail('bad literal');
  }

  private object(depth: number): JsonValue {
    this.pos++; // {
    const obj: Record<string, JsonValue> = {};
    this.ws();
    if (this.text.charCodeAt(this.pos) === 0x7d) {
      this.pos++;
      return obj;
    }
    for (;;) {
      this.ws();
      if (this.text.charCodeAt(this.pos) !== 0x22) this.fail('object key must be string');
      const key = this.string();
      if (Object.prototype.hasOwnProperty.call(obj, key)) this.fail('duplicate key');
      this.ws();
      if (this.text.charCodeAt(this.pos) !== 0x3a) this.fail('expected :');
      this.pos++;
      this.ws();
      obj[key] = this.value(depth + 1);
      this.ws();
      const c = this.text.charCodeAt(this.pos);
      if (c === 0x2c) {
        this.pos++;
        continue;
      }
      if (c === 0x7d) {
        this.pos++;
        return obj;
      }
      this.fail('expected , or }');
    }
  }

  private array(depth: number): JsonValue {
    this.pos++; // [
    const arr: JsonValue[] = [];
    this.ws();
    if (this.text.charCodeAt(this.pos) === 0x5d) {
      this.pos++;
      return arr;
    }
    for (;;) {
      this.ws();
      arr.push(this.value(depth + 1));
      this.ws();
      const c = this.text.charCodeAt(this.pos);
      if (c === 0x2c) {
        this.pos++;
        continue;
      }
      if (c === 0x5d) {
        this.pos++;
        return arr;
      }
      this.fail('expected , or ]');
    }
  }

  private string(): string {
    this.pos++; // "
    const contentStart = this.pos;
    let out = '';
    for (;;) {
      if (this.pos >= this.text.length) this.fail('unterminated string');
      const c = this.text.charCodeAt(this.pos);
      if (c === 0x22) {
        if (this.stringSpans) this.stringSpans.push([contentStart, this.pos]);
        this.pos++;
        return out;
      }
      if (c < 0x20) this.fail('unescaped control in string');
      if (c === 0x5c) {
        this.pos++;
        if (this.pos >= this.text.length) this.fail('unterminated escape');
        const e = this.text.charCodeAt(this.pos);
        this.pos++;
        switch (e) {
          case 0x22: out += '"'; break;
          case 0x5c: out += '\\'; break;
          case 0x2f: out += '/'; break;
          case 0x62: out += '\b'; break;
          case 0x66: out += '\f'; break;
          case 0x6e: out += '\n'; break;
          case 0x72: out += '\r'; break;
          case 0x74: out += '\t'; break;
          case 0x75: {
            const cp = this.hex4();
            if (cp >= 0xd800 && cp <= 0xdbff) {
              // must be followed by a low-surrogate escape
              if (this.text.charCodeAt(this.pos) === 0x5c && this.text.charCodeAt(this.pos + 1) === 0x75) {
                this.pos += 2;
                const lo = this.hex4();
                if (lo >= 0xdc00 && lo <= 0xdfff) {
                  out += String.fromCodePoint(0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00));
                } else this.fail('lone high surrogate');
              } else this.fail('lone high surrogate');
            } else if (cp >= 0xdc00 && cp <= 0xdfff) {
              this.fail('lone low surrogate');
            } else {
              out += String.fromCharCode(cp);
            }
            break;
          }
          default:
            this.fail('bad escape');
        }
      } else {
        out += this.text[this.pos];
        this.pos++;
      }
    }
  }

  private hex4(): number {
    if (this.pos + 4 > this.text.length) this.fail('bad \\u escape');
    const s = this.text.slice(this.pos, this.pos + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(s)) this.fail('bad \\u escape');
    this.pos += 4;
    return parseInt(s, 16);
  }

  private number(): number {
    const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(this.text.slice(this.pos));
    if (!m) this.fail('bad number');
    this.pos += m[0].length;
    const n = Number(m[0]);
    if (!Number.isSafeInteger(n)) this.fail('number not a safe integer');
    if (Object.is(n, -0)) this.fail('negative zero');
    return n;
  }
}

// Strict wire-profile JSON parse. `source` must already be validated UTF-8
// text without BOM. All failures surface as ClosedError INVALID_REQUEST.
export function parseJson(source: string, limits: ParseLimits = DEFAULT_PARSE_LIMITS): JsonValue {
  if (source.charCodeAt(0) === 0xfeff) throw new ClosedError('INVALID_REQUEST', 'BOM');
  try {
    return new Parser(source, limits).parse();
  } catch (e) {
    if (e instanceof JsonSyntaxError || e instanceof JsonLimitError) {
      throw new ClosedError('INVALID_REQUEST', `json: ${e.message}`);
    }
    throw e;
  }
}

export interface AuxJsonResult {
  value: JsonValue;
  // Code-unit spans [start,end) of every string token's content, in order.
  stringSpans: [number, number][];
}

// Auxiliary complete-JSON parse used by the decoding view (spec 6.1).
// Returns null when the text is not a complete strict JSON value; throws
// JsonLimitError when the bounded-parse limits (16 levels, 2048 nodes)
// are crossed — the caller maps that to hold LIMIT.
export function parseJsonAux(source: string): AuxJsonResult | null {
  if (source.length > 32768) return null;
  const stringSpans: [number, number][] = [];
  try {
    const value = new Parser(source, AUX_JSON_LIMITS, stringSpans).parse();
    return { value, stringSpans };
  } catch (e) {
    if (e instanceof JsonSyntaxError) return null;
    throw e;
  }
}

// Structural helpers shared by every schema validator.
export function isObj(v: JsonValue | undefined): v is Record<string, JsonValue> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function checkExactKeys(v: Record<string, JsonValue>, keys: string[], what: string): void {
  for (const k of Object.keys(v)) {
    if (!keys.includes(k)) throw new ClosedError('INVALID_REQUEST', `unknown member ${k} in ${what}`);
  }
  for (const k of keys) {
    if (!Object.prototype.hasOwnProperty.call(v, k)) {
      throw new ClosedError('INVALID_REQUEST', `missing member ${k} in ${what}`);
    }
  }
}
