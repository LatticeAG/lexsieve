// Vendored Unicode 15.1.0 tables (scripts/gen_unicode_tables.mjs) plus the
// grapheme cluster segmenter (UAX #29), full case folding (C+F mappings),
// and the property lookups the screening pipeline needs. Unicode data is
// vendored and pinned by digest per spec section 2; NFKC uses the host
// runtime's String.prototype.normalize (ICU) and is the only non-vendored
// table — recorded in STATUS.md.

import tables from './unicode_15_1.json' with { type: 'json' };

export type Ranges = [number, number][];

export const UNICODE_VERSION: string = tables.unicode;
export const UNICODE_TABLE_SHA256 = '9442ce4c0e8e131200034e90ca568dc0b6255418db0fecdf29a83a78d73ee999';

const gcb = tables.gcb as unknown as Record<string, Ranges>;
const extPict = tables.extended_pictographic as unknown as Ranges;
const dicpRanges = tables.default_ignorable as unknown as Ranges;
const wsRanges = tables.white_space as unknown as Ranges;
const catLetter = tables.categories.letter as unknown as Ranges;
const catNumber = tables.categories.number as unknown as Ranges;
const catPc = tables.categories.connectorPunctuation as unknown as Ranges;
const casefoldMap = tables.casefold as unknown as Record<string, number[]>;

function inRanges(ranges: Ranges, cp: number): boolean {
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const r = ranges[mid]!;
    if (cp < r[0]) hi = mid - 1;
    else if (cp > r[1]) lo = mid + 1;
    else return true;
  }
  return false;
}

export type Gcb =
  | 'Other' | 'Prepend' | 'CR' | 'LF' | 'Control' | 'Extend'
  | 'Regional_Indicator' | 'SpacingMark' | 'L' | 'V' | 'T' | 'LV' | 'LVT' | 'ZWJ';

export function gcbOf(cp: number): Gcb {
  for (const prop of ['Prepend', 'CR', 'LF', 'Control', 'Extend', 'Regional_Indicator', 'SpacingMark', 'L', 'V', 'T', 'LV', 'LVT', 'ZWJ'] as const) {
    const r = gcb[prop];
    if (r && inRanges(r, cp)) return prop;
  }
  return 'Other';
}

export function isExtendedPictographic(cp: number): boolean {
  return inRanges(extPict, cp);
}

export function isDefaultIgnorable(cp: number): boolean {
  return inRanges(dicpRanges, cp);
}

export function isWhiteSpace(cp: number): boolean {
  return inRanges(wsRanges, cp);
}

export function isTokenChar(cp: number): boolean {
  return inRanges(catLetter, cp) || inRanges(catNumber, cp) || inRanges(catPc, cp);
}

// Full default case folding: CaseFolding.txt status C+F, vendored.
export function caseFoldCp(cp: number): number[] {
  const m = casefoldMap[String(cp)];
  return m ?? [cp];
}

export function caseFoldString(s: string): string {
  let out = '';
  for (const ch of s) {
    for (const cp of caseFoldCp(ch.codePointAt(0)!)) out += String.fromCodePoint(cp);
  }
  return out;
}

// --- UAX #29 extended grapheme cluster segmentation -----------------------

function isGcbControl(g: Gcb): boolean {
  return g === 'Control' || g === 'CR' || g === 'LF';
}

// Returns cluster boundaries: an array of [start,end) index pairs over cps.
export function graphemeClusters(cps: number[]): [number, number][] {
  const n = cps.length;
  const out: [number, number][] = [];
  if (n === 0) return out;
  const g = cps.map(gcbOf);
  let start = 0;
  // State for GB11: index of the most recent ZWJ that is preceded by
  // ExtPict Extend* — i.e. an ExtPict char followed only by Extend chars.
  let extPictBeforeZwRun = false; // set when current position is after ZWJ with GB11 left context
  let riRun = g[0] === 'Regional_Indicator' ? 1 : 0; // consecutive RI count ending at i-1

  for (let i = 1; i < n; i++) {
    const prev = g[i - 1]!;
    const cur = g[i]!;
    let brk = true; // GB999 default

    if (prev === 'CR' && cur === 'LF') brk = false; // GB3
    else if (isGcbControl(prev) || isGcbControl(cur)) brk = true; // GB4/GB5
    else if (prev === 'L' && (cur === 'L' || cur === 'V' || cur === 'LV' || cur === 'LVT')) brk = false; // GB6
    else if ((prev === 'LV' || prev === 'V') && (cur === 'V' || cur === 'T')) brk = false; // GB7
    else if ((prev === 'LVT' || prev === 'T') && cur === 'T') brk = false; // GB8
    else if (cur === 'Extend' || cur === 'ZWJ') brk = false; // GB9
    else if (cur === 'SpacingMark') brk = false; // GB9a
    else if (prev === 'Prepend') brk = false; // GB9b
    else if (prev === 'ZWJ' && extPictBeforeZwRun && isExtendedPictographic(cps[i]!)) brk = false; // GB11
    else if (prev === 'Regional_Indicator' && cur === 'Regional_Indicator' && riRun % 2 === 1) brk = false; // GB12/13

    if (brk) {
      out.push([start, i]);
      start = i;
    }
    // update GB11/GB12 state for position i (as "previous" for i+1)
    if (cur === 'ZWJ') {
      // look back: cps[i-1-...] Extend* then ExtPict
      let j = i - 1;
      while (j >= start && g[j] === 'Extend') j--;
      extPictBeforeZwRun = j >= 0 && isExtendedPictographic(cps[j]!);
    } else if (cur !== 'Extend') {
      extPictBeforeZwRun = false;
    }
    riRun = cur === 'Regional_Indicator' ? (prev === 'Regional_Indicator' ? riRun + 1 : 1) : 0;
  }
  out.push([start, n]);
  return out;
}
