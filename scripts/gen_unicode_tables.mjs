#!/usr/bin/env node
// Generates src/unicode_15_1.json and python/lexsieve/unicode_15_1.json from
// vendored Unicode Character Database 15.1.0 files.
//
// Usage: node scripts/gen_unicode_tables.mjs <ucd-dir>
//   <ucd-dir> must contain the UCD 15.1.0 files:
//     GraphemeBreakProperty.txt  (ucd/auxiliary/)
//     emoji-data.txt             (ucd/emoji/)
//     DerivedCoreProperties.txt
//     PropList.txt
//     CaseFolding.txt
//     UnicodeData.txt
// The output embeds the SHA-256 digest of each input file so the vendored
// data is pinned by digest, as required by the LexSieve specification.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ucdDir = process.argv[2];
if (!ucdDir) {
  console.error('usage: node scripts/gen_unicode_tables.mjs <ucd-dir>');
  process.exit(2);
}

const FILES = [
  'GraphemeBreakProperty.txt',
  'emoji-data.txt',
  'DerivedCoreProperties.txt',
  'PropList.txt',
  'CaseFolding.txt',
  'UnicodeData.txt',
];

const digests = {};
const texts = {};
for (const f of FILES) {
  const buf = readFileSync(join(ucdDir, f));
  digests[f] = createHash('sha256').update(buf).digest('hex');
  texts[f] = buf.toString('utf8');
}

function parseRanges(text, wanted) {
  // returns Map prop -> [[lo,hi],...]
  const out = new Map();
  for (const rawLine of text.split('\n')) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    const [rangePart, propPart] = line.split(';').map((s) => s.trim());
    if (!wanted.has(propPart)) continue;
    const [loS, hiS] = rangePart.split('..');
    const lo = parseInt(loS, 16);
    const hi = hiS === undefined ? lo : parseInt(hiS, 16);
    if (!out.has(propPart)) out.set(propPart, []);
    out.get(propPart).push([lo, hi]);
  }
  for (const v of out.values()) v.sort((a, b) => a[0] - b[0]);
  return out;
}

const GCB_PROPS = [
  'Prepend', 'CR', 'LF', 'Control', 'Extend', 'Regional_Indicator',
  'SpacingMark', 'L', 'V', 'T', 'LV', 'LVT', 'ZWJ',
];
const gcb = parseRanges(texts['GraphemeBreakProperty.txt'], new Set(GCB_PROPS));

const extPict = parseRanges(texts['emoji-data.txt'], new Set(['Extended_Pictographic']));

const dicp = parseRanges(texts['DerivedCoreProperties.txt'], new Set(['Default_Ignorable_Code_Point']));

const ws = parseRanges(texts['PropList.txt'], new Set(['White_Space']));

// General categories needed by the tokenizer: L*, N*, Pc.
const catRanges = { letter: [], number: [], connectorPunctuation: [] };
{
  const lines = texts['UnicodeData.txt'].split('\n');
  const push = (cat, lo, hi) => {
    if (cat.startsWith('L')) catRanges.letter.push([lo, hi]);
    else if (cat.startsWith('N')) catRanges.number.push([lo, hi]);
    else if (cat === 'Pc') catRanges.connectorPunctuation.push([lo, hi]);
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const fields = line.split(';');
    const cp = parseInt(fields[0], 16);
    const name = fields[1];
    const cat = fields[2];
    if (name.endsWith(', First>')) {
      const hi = parseInt(lines[i + 1].split(';')[0], 16);
      push(cat, cp, hi);
      i++; // consume the Last> line
      continue;
    }
    push(cat, cp, cp);
  }
}
function mergeRanges(rs) {
  rs.sort((a, b) => a[0] - b[0]);
  const out = [];
  for (const r of rs) {
    const last = out[out.length - 1];
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
    else out.push([r[0], r[1]]);
  }
  return out;
}
catRanges.letter = mergeRanges(catRanges.letter);
catRanges.number = mergeRanges(catRanges.number);
catRanges.connectorPunctuation = mergeRanges(catRanges.connectorPunctuation);

// Full case folding: status C and F mappings from CaseFolding.txt.
const casefold = {};
for (const rawLine of texts['CaseFolding.txt'].split('\n')) {
  const line = rawLine.replace(/#.*$/, '').trim();
  if (!line) continue;
  const [cpS, status, mapS] = line.split(';').map((s) => s.trim());
  if (status !== 'C' && status !== 'F') continue;
  const cp = parseInt(cpS, 16);
  const mapped = mapS.split(' ').map((h) => parseInt(h, 16));
  casefold[cp] = mapped;
}

const table = {
  unicode: '15.1.0',
  source_digests: digests,
  gcb: Object.fromEntries(gcb),
  extended_pictographic: extPict.get('Extended_Pictographic') ?? [],
  default_ignorable: dicp.get('Default_Ignorable_Code_Point') ?? [],
  white_space: ws.get('White_Space') ?? [],
  categories: catRanges,
  casefold,
};

const json = JSON.stringify(table);
writeFileSync(new URL('../src/unicode_15_1.json', import.meta.url), json + '\n');
writeFileSync(new URL('../python/lexsieve/unicode_15_1.json', import.meta.url), json + '\n');
console.log('wrote src/unicode_15_1.json and python/lexsieve/unicode_15_1.json', json.length, 'bytes');
console.log('table digest', createHash('sha256').update(json).digest('hex'));
