// Section 6.1: normalized views and origin maps.
//
// Every normalized character carries an origin interval in (block, byte)
// space: [b0,s0) .. [b1,e1). For a single-block interval b0==b1. Synthetic
// concat separators carry b0=-1 (no origin). A match maps back to the
// smallest original interval covering its contributing bytes in each block,
// including intervening removed controls.

import { parseJsonAux, JsonLimitError } from './jcs.ts';
import {
  caseFoldCp,
  graphemeClusters,
  isDefaultIgnorable,
  isWhiteSpace,
} from './unicode.ts';

// Mid-screening conditions that still produce a committed hold Decision.
export class HoldSignal extends Error {
  readonly reason: 'LIMIT' | 'INVALID_UTF8';
  constructor(reason: 'LIMIT' | 'INVALID_UTF8') {
    super(reason);
    this.name = 'HoldSignal';
    this.reason = reason;
  }
}

export interface AChar {
  cp: number;
  b0: number; // block of interval start (-1 => synthetic, no origin)
  s0: number; // byte offset start in b0
  b1: number; // block of interval end
  e1: number; // byte offset end in b1
}

const SYNTH: Omit<AChar, 'cp'> = { b0: -1, s0: 0, b1: -1, e1: 0 };

export function acharText(chars: AChar[]): string {
  return String.fromCodePoint(...chars.map((c) => c.cp));
}

// Byte offset of each code point in `text` (UTF-8). Returns array indexed by
// code-point ordinal -> [byteStart, byteEnd).
export function utf8ByteSpans(text: string): [number, number][] {
  const spans: [number, number][] = [];
  let b = 0;
  for (const ch of text) {
    const n = ch.length === 2 ? 4 : Buffer.byteLength(ch, 'utf8');
    spans.push([b, b + n]);
    b += n;
  }
  return spans;
}

// ---------------------------------------------------------------------------
// Decoding pass (view D input). One left-to-right source pass; generated
// characters are never rescanned.
// ---------------------------------------------------------------------------

const NAMED_ENTITIES: Record<string, number> = {
  amp: 0x26,
  lt: 0x3c,
  gt: 0x3e,
  quot: 0x22,
  apos: 0x27,
};

const HEXD = /[0-9a-fA-F]/;

function isHexAt(text: string, i: number): boolean {
  return i < text.length && HEXD.test(text[i]!);
}

// Decodes `text` into annotated chars. `stringSpans` are code-unit spans of
// JSON string content when the whole block is a complete JSON value; escapes
// decode only inside them. `blockIdx` is the block index for origins.
export function decodePass(
  text: string,
  blockIdx: number,
  byteSpans: [number, number][],
  cuToCp: number[], // code-unit index -> code point ordinal
  stringSpans: [number, number][] | null,
): AChar[] {
  const out: AChar[] = [];
  const lit = (cpIdx: number, s: number, e: number): void => {
    out.push({ cp: cpAt(text, cpIdx), b0: blockIdx, s0: s, b1: blockIdx, e1: e });
  };
  // stringSpans sorted; pointer
  let sp = 0;
  const inString = (cu: number): boolean => {
    while (sp < stringSpans!.length && stringSpans![sp]![1] <= cu) sp++;
    return sp < stringSpans!.length && stringSpans![sp]![0] <= cu && cu < stringSpans![sp]![1];
  };

  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text.charCodeAt(i);
    const cpOrd = cuToCp[i]!;
    const [bs, be] = byteSpans[cpOrd]!;

    if (c === 0x5c && stringSpans !== null && inString(i)) {
      // JSON escape inside a string token
      const e = text.charCodeAt(i + 1);
      const escBytes = (k: number): [number, number] => {
        // byte range covering k code units starting at i
        const first = byteSpans[cuToCp[i]!]!;
        const last = byteSpans[cuToCp[i + k - 1]!]!;
        return [first[0], last[1]];
      };
      let consumed = 0;
      let cp = -1;
      switch (e) {
        case 0x22: cp = 0x22; consumed = 2; break;
        case 0x5c: cp = 0x5c; consumed = 2; break;
        case 0x2f: cp = 0x2f; consumed = 2; break;
        case 0x62: cp = 0x08; consumed = 2; break;
        case 0x66: cp = 0x0c; consumed = 2; break;
        case 0x6e: cp = 0x0a; consumed = 2; break;
        case 0x72: cp = 0x0d; consumed = 2; break;
        case 0x74: cp = 0x09; consumed = 2; break;
        case 0x75: {
          const h1 = text.slice(i + 2, i + 6);
          if (/^[0-9a-fA-F]{4}$/.test(h1)) {
            const v1 = parseInt(h1, 16);
            if (v1 >= 0xd800 && v1 <= 0xdbff) {
              const h2 = text.slice(i + 8, i + 12);
              if (text[i + 6] === '\\' && text[i + 7] === 'u' && /^[0-9a-fA-F]{4}$/.test(h2)) {
                const v2 = parseInt(h2, 16);
                if (v2 >= 0xdc00 && v2 <= 0xdfff) {
                  cp = 0x10000 + ((v1 - 0xd800) << 10) + (v2 - 0xdc00);
                  consumed = 12;
                }
              }
            } else if (!(v1 >= 0xdc00 && v1 <= 0xdfff)) {
              cp = v1;
              consumed = 6;
            }
          }
          break;
        }
      }
      if (consumed > 0 && cp >= 0) {
        const [s, e2] = escBytes(consumed);
        out.push({ cp, b0: blockIdx, s0: s, b1: blockIdx, e1: e2 });
        i += consumed;
        continue;
      }
      lit(cpOrd, bs, be);
      i++;
      continue;
    }

    if (c === 0x26) {
      // & entity — longest applicable = must end at ';'
      const semi = text.indexOf(';', i + 1);
      if (semi > i + 1 && semi - i <= 32) {
        const name = text.slice(i + 1, semi);
        let cp = -1;
        if (Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, name)) {
          cp = NAMED_ENTITIES[name]!;
        } else if (name.startsWith('#x') || name.startsWith('#X')) {
          const d = name.slice(2);
          if (/^[0-9a-fA-F]+$/.test(d)) cp = parseInt(d, 16);
        } else if (name.startsWith('#')) {
          const d = name.slice(1);
          if (/^[0-9]+$/.test(d)) cp = parseInt(d, 10);
        }
        if (cp >= 0 && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff)) {
          const s = byteSpans[cuToCp[i]!]![0];
          const e2 = byteSpans[cuToCp[semi]!]![1];
          out.push({ cp, b0: blockIdx, s0: s, b1: blockIdx, e1: e2 });
          i = semi + 1;
          continue;
        }
      }
      lit(cpOrd, bs, be);
      i++;
      continue;
    }

    if (c === 0x25 && i + 2 < n && isHexAt(text, i + 1) && isHexAt(text, i + 2)) {
      // maximal run of %XX escapes
      let j = i;
      const bytes: number[] = [];
      while (
        j + 2 < n &&
        text.charCodeAt(j) === 0x25 &&
        isHexAt(text, j + 1) &&
        isHexAt(text, j + 2)
      ) {
        bytes.push(parseInt(text.slice(j + 1, j + 3), 16));
        j += 3;
      }
      const runEndCu = j; // exclusive
      const s = byteSpans[cuToCp[i]!]![0];
      const e2 = byteSpans[cuToCp[runEndCu - 1]!]![1];
      const dec = new TextDecoder('utf-8', { fatal: true });
      let decoded: string;
      try {
        decoded = dec.decode(new Uint8Array(bytes));
      } catch {
        throw new HoldSignal('INVALID_UTF8');
      }
      for (const ch of decoded) {
        out.push({ cp: ch.codePointAt(0)!, b0: blockIdx, s0: s, b1: blockIdx, e1: e2 });
      }
      i = runEndCu;
      continue;
    }

    lit(cpOrd, bs, be);
    i++;
  }
  return out;
}

function cpAt(text: string, cu: number): number {
  const c = text.charCodeAt(cu);
  if (c >= 0xd800 && c <= 0xdbff) {
    return 0x10000 + ((c - 0xd800) << 10) + (text.charCodeAt(cu + 1) - 0xdc00);
  }
  return c;
}

// ---------------------------------------------------------------------------
// Normalization: grapheme clusters -> NFKC -> casefold -> DICP removal ->
// whitespace collapse. Returns annotated output chars.
// ---------------------------------------------------------------------------

export function normalizeChars(chars: AChar[]): AChar[] {
  const cps = chars.map((c) => c.cp);
  const clusters = graphemeClusters(cps);
  const out: AChar[] = [];
  for (const [cs, ce] of clusters) {
    const cluster = chars.slice(cs, ce);
    const origin: Omit<AChar, 'cp'> = {
      b0: cluster[0]!.b0,
      s0: cluster[0]!.s0,
      b1: cluster[cluster.length - 1]!.b1,
      e1: cluster[cluster.length - 1]!.e1,
    };
    const str = String.fromCodePoint(...cluster.map((c) => c.cp));
    const nfkc = str.normalize('NFKC');
    for (const ch of nfkc) {
      for (const fcp of caseFoldCp(ch.codePointAt(0)!)) {
        out.push({ cp: fcp, ...origin });
      }
    }
  }
  // remove Default_Ignorable_Code_Point
  const noIgn = out.filter((c) => !isDefaultIgnorable(c.cp));
  // whitespace: map to ASCII space, collapse maximal runs
  const collapsed: AChar[] = [];
  let run: AChar | null = null;
  const flush = () => {
    if (run) collapsed.push(run);
    run = null;
  };
  for (const c of noIgn) {
    if (isWhiteSpace(c.cp)) {
      if (run) {
        run.b1 = c.b1;
        run.e1 = c.e1;
        if (c.b0 < run.b0 || run.b0 === -1) {
          run.b0 = c.b0;
          run.s0 = c.s0;
        }
      } else {
        run = { cp: 0x20, b0: c.b0, s0: c.s0, b1: c.b1, e1: c.e1 };
      }
    } else {
      flush();
      collapsed.push(c);
    }
  }
  flush();
  return collapsed;
}

// Pure normalization of a literal string (pack rule compile path) — no
// origin tracking needed.
export function normalizeLiteral(text: string): string {
  const spans = utf8ByteSpans(text);
  const chars: AChar[] = [];
  let cpIdx = 0;
  for (const ch of text) {
    chars.push({ cp: ch.codePointAt(0)!, b0: 0, s0: spans[cpIdx]![0], b1: 0, e1: spans[cpIdx]![1] });
    cpIdx++;
  }
  return acharText(normalizeChars(chars));
}

// Build the code-unit index -> code point ordinal map for a string.
export function buildCuToCp(text: string): number[] {
  const map = new Array<number>(text.length);
  let ord = 0;
  for (let i = 0; i < text.length; i++) {
    map[i] = ord;
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) i++;
    ord++;
  }
  return map;
}

// ---------------------------------------------------------------------------
// Views per block + multi-block concatenations.
// ---------------------------------------------------------------------------

export interface BlockViews {
  literal: AChar[]; // raw literal chars
  decoded: AChar[]; // once-decoded chars (pre-normalization)
  L: AChar[]; // normalized literal
  D: AChar[]; // normalized decoded
}

export interface CandidateViews {
  perBlock: BlockViews[];
  // normalized rule/model screening views: per-block L and D, plus (for
  // multi-block results) the one-space and no-separator concatenations of
  // each.
  ruleViews: AChar[][];
  // inputs to the encoding predicate: literal text, once-decoded text, and
  // their one-space / no-separator concatenations (pre case folding).
  predicateInputs: AChar[][];
  // normalized view byte total (for the 262144 cap accounting)
  normalizedBytes: number;
}

export const NORMALIZED_CAP = 262144;

export function buildViews(blocks: { index: number; text: string }[]): CandidateViews {
  const perBlock: BlockViews[] = [];
  let normalizedBytes = 0;
  for (const b of blocks) {
    const text = b.text;
    const byteSpans = utf8ByteSpans(text);
    const cuToCp = buildCuToCp(text);
    const literal: AChar[] = [];
    let k = 0;
    for (const ch of text) {
      literal.push({
        cp: ch.codePointAt(0)!,
        b0: b.index,
        s0: byteSpans[k]![0],
        b1: b.index,
        e1: byteSpans[k]![1],
      });
      k++;
    }
    let aux: ReturnType<typeof parseJsonAux> = null;
    try {
      aux = parseJsonAux(text);
    } catch (e) {
      if (e instanceof JsonLimitError) throw new HoldSignal('LIMIT');
      throw e;
    }
    const decoded = decodePass(text, b.index, byteSpans, cuToCp, aux ? aux.stringSpans : null);
    const L = normalizeChars(literal);
    const D = normalizeChars(decoded);
    normalizedBytes += Buffer.byteLength(acharText(L), 'utf8') + Buffer.byteLength(acharText(D), 'utf8');
    perBlock.push({ literal, decoded, L, D });
  }

  const ruleViews: AChar[][] = [];
  const predicateInputs: AChar[][] = [];
  for (const bv of perBlock) {
    ruleViews.push(bv.L, bv.D);
    predicateInputs.push(bv.literal, bv.decoded);
  }
  if (perBlock.length > 1) {
    for (const kind of ['L', 'D'] as const) {
      const joinedSpace: AChar[] = [];
      const joinedNone: AChar[] = [];
      perBlock.forEach((bv, i) => {
        if (i > 0) joinedSpace.push({ cp: 0x20, ...SYNTH });
        joinedSpace.push(...bv[kind]);
        joinedNone.push(...bv[kind]);
      });
      ruleViews.push(joinedSpace, joinedNone);
      normalizedBytes += Buffer.byteLength(acharText(joinedSpace), 'utf8');
      normalizedBytes += Buffer.byteLength(acharText(joinedNone), 'utf8');
    }
    for (const kind of ['literal', 'decoded'] as const) {
      const joinedSpace: AChar[] = [];
      const joinedNone: AChar[] = [];
      perBlock.forEach((bv, i) => {
        if (i > 0) joinedSpace.push({ cp: 0x20, ...SYNTH });
        joinedSpace.push(...bv[kind]);
        joinedNone.push(...bv[kind]);
      });
      predicateInputs.push(joinedSpace, joinedNone);
    }
  }
  if (normalizedBytes > NORMALIZED_CAP) throw new HoldSignal('LIMIT');
  return { perBlock, ruleViews, predicateInputs, normalizedBytes };
}

// Map a match over normalized chars [i0,i1) to per-block source intervals.
// `blockLens` gives the UTF-8 byte length of each block.
export function matchToSpans(
  chars: AChar[],
  i0: number,
  i1: number,
  blockLens: number[],
): { block: number; start: number; end: number }[] {
  const contrib = new Map<number, [number, number]>();
  for (let i = i0; i < i1; i++) {
    const c = chars[i]!;
    if (c.b0 < 0) continue; // synthetic separator: no origin
    for (let b = c.b0; b <= c.b1; b++) {
      const s = b === c.b0 ? c.s0 : 0;
      const e = b === c.b1 ? c.e1 : blockLens[b] ?? 0;
      const cur = contrib.get(b);
      if (!cur) contrib.set(b, [s, e]);
      else {
        if (s < cur[0]) cur[0] = s;
        if (e > cur[1]) cur[1] = e;
      }
    }
  }
  return [...contrib.entries()]
    .map(([block, [start, end]]) => ({ block, start, end }))
    .sort((a, b) => a.block - b.block);
}
