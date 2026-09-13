// Exports the conformance corpus (test/vectors.ts) to fixtures/conformance/
// as locked JSON + manifest.json with file hashes (spec 12: the fixtures
// directory must include an immutable manifest of file hashes and license
// metadata). Re-run after any change to test/vectors.ts.
import { writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { VECTORS } from '../src/eval/vectors.ts';

mkdirSync('fixtures/conformance', { recursive: true });

const corpus = { v: 1, suite: 'conformance', license: 'MIT', vectors: VECTORS };
const bytes = Buffer.from(JSON.stringify(corpus), 'utf8');
writeFileSync('fixtures/conformance/vectors.json', bytes);

const manifest = {
  v: 1,
  suites: {
    conformance: {
      file: 'conformance/vectors.json',
      sha256: createHash('sha256').update(bytes).digest('hex'),
      license: 'MIT',
      description: 'LexSieve protocol-1 conformance vectors TV-L--01..60',
      count: VECTORS.length,
    },
  },
};
writeFileSync('fixtures/manifest.json', JSON.stringify(manifest, null, 2) + '\n');
console.log(`wrote ${VECTORS.length} vectors`);
