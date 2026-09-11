import { test } from 'node:test';
import assert from 'node:assert/strict';
import { unwrapDemoResult } from '../plugin/src/client-result.mjs';

test('Typert success envelope becomes renderable demo state, not the envelope', () => {
  const state = { phase: 'success', events: [{ text: 'HTTP 200' }], result: { verified: true } };
  assert.equal(unwrapDemoResult({ ok: true, value: state }), state);
  assert.deepEqual(unwrapDemoResult({ ok: true, value: state }).events.map(item => item.text), ['HTTP 200']);
});
test('remote failure and malformed successful responses never replace renderable state', () => {
  assert.throws(() => unwrapDemoResult({ ok: false, error: { message: 'Access denied' } }), /Access denied/);
  assert.throws(() => unwrapDemoResult({ ok: true, value: { phase: 'idle' } }), /Invalid demo service response/);
});
