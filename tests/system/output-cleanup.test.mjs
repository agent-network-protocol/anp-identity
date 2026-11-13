import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { withPublishedIdentity } from '../support/published-identity.mjs';
import { loadTestFactor } from '../support/config.mjs';

test('ID-S10 ordinary public outputs omit secrets and exact cleanup removes only this publication', { timeout: 180000 }, async () => {
  const factor = await loadTestFactor();
  let clientId, observedRuntime;
  await withPublishedIdentity('e1', async (runtime, published) => {
    observedRuntime = runtime;
    clientId = published.clientId;
    const pending = await runtime.rpc('access', { requestId: randomUUID(), purpose: 'Inspect public output only',
      identity: published.reference, operation: { action: 'read' } });
    const review = await runtime.rpc('manager/getRequest', pending.id);
    const approved = await runtime.rpc('manager/decide', { requestId: pending.id, expectedVersion: pending.version,
      decision: 'approve', identity: published.reference, mode: 'once', reviewedSnapshot: review.snapshot });
    const identity = await runtime.rpc('read', { grantId: approved.grantId, executionId: randomUUID() });
    const metadataResponse = await fetch(clientId, { redirect: 'error', signal: AbortSignal.timeout(15000) });
    assert.equal(metadataResponse.status, 200);
    const metadata = await metadataResponse.json();
    assert.equal(new URL(metadata.jwks_uri).origin, 'https://awiki.me');
    const jwksResponse = await fetch(metadata.jwks_uri, { redirect: 'error', signal: AbortSignal.timeout(15000) });
    assert.equal(jwksResponse.status, 200);
    const jwks = await jwksResponse.json();
    assert.ok(jwks.keys.length > 0);
    for (const key of jwks.keys) {
      assert.equal(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some(name => Object.hasOwn(key, name)), false);
    }
    const output = JSON.stringify({ identity, metadata, jwks });
    // Assert booleans so a failure never renders a secret-bearing string.
    assert.equal(output.includes(factor.phone), false);
    assert.equal(output.includes(factor.code), false);
    assert.equal(Boolean(process.env.DEEPSEEK_API_KEY && output.includes(process.env.DEEPSEEK_API_KEY)), false);
    assert.equal(/-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----/u.test(output), false);
    assert.equal(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/u.test(output), false);
    assert.deepEqual(runtime.outputSecretStatus(), { factorPresent: false, privateKeyPresent: false,
      compactAssertionPresent: false, modelKeyPresent: false });
  });
  assert.deepEqual(observedRuntime.outputSecretStatus(), { factorPresent: false, privateKeyPresent: false,
    compactAssertionPresent: false, modelKeyPresent: false });
  // The fixture independently compares the other test-factor owners before/after deletion.
  const removed = await fetch(clientId, { redirect: 'error', signal: AbortSignal.timeout(15000) });
  assert.ok([404, 410].includes(removed.status));
  await removed.body?.cancel();
});
