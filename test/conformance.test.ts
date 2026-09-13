// Section 20 conformance suite: all 60 TV-L vectors run through the
// integration harness. Expected is compared structurally with no ignored
// members; unknown ops/fields/IDs are harness failures.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { VECTORS, type Vector } from '../src/eval/vectors.ts';
import { runVector } from '../src/eval/harness.ts';
import { deepEqualJson } from './util.ts';

// Locked vector ID set — unknown or missing IDs fail.
const EXPECTED_IDS = Array.from({ length: 60 }, (_, i) => `TV-L--${String(i + 1).padStart(2, '0')}`);

test('vector ID set is exactly TV-L--01..60', () => {
  assert.deepEqual(VECTORS.map((v) => v.id), EXPECTED_IDS);
});

for (const v of VECTORS) {
  test(`${v.id}`, () => {
    const actual = runVector(v as Vector);
    for (const k of Object.keys(v.expected)) {
      assert.ok(
        Object.prototype.hasOwnProperty.call(actual, k),
        `missing output member ${k}; actual=${JSON.stringify(actual)}`,
      );
    }
    for (const k of Object.keys(actual)) {
      assert.ok(
        Object.prototype.hasOwnProperty.call(v.expected, k),
        `unexpected output member ${k}=${JSON.stringify(actual[k])}`,
      );
    }
    assert.ok(
      deepEqualJson(actual, v.expected),
      `expected ${JSON.stringify(v.expected)}\nactual   ${JSON.stringify(actual)}`,
    );
  });
}
