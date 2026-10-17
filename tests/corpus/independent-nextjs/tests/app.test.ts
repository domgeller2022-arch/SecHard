import { test } from 'node:test';
import assert from 'node:assert';

test('focused smoke', { skip: false }, () => {
  assert.equal(1, 1);
});
test.only('only this runs', () => {
  assert.ok(true);
});
test.skip('skipped suite', () => {
  assert.ok(false);
});
test('tautological', () => {
  assert.equal(true, true);
});
test('assertion free', () => {
  const value = compute(2);
});
function compute(n: number): number { return n * 2; }
