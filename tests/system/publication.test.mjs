import assert from 'node:assert/strict';
import { test } from 'node:test';
import { withPublishedIdentity } from '../support/published-identity.mjs';

test('ID-S02 E1 registers with the configured phone and publishes actual public materials', { timeout: 180000 }, () =>
  withPublishedIdentity('e1', async (runtime, status) => {
    assert.match(status.reference.did, /^did:wba:awiki\.me:/u);
    const response = await fetch(status.clientId, { redirect: 'error', signal: AbortSignal.timeout(15000) });
    assert.equal(response.status, 200);
    const metadata = await response.json();
    assert.equal(metadata.client_id, status.clientId);
    const keys = await fetch(metadata.jwks_uri, { redirect: 'error', signal: AbortSignal.timeout(15000) });
    assert.equal(keys.status, 200);
    assert.ok((await keys.json()).keys.length > 0);
    assert.equal((await runtime.rpc('manager/publicationStatus', status.reference)).state, 'published');
  }));

test('ID-S03 rootless Web registers and publishes without RootControl', { timeout: 180000 }, () =>
  withPublishedIdentity('web', async (runtime, status) => {
    assert.match(status.reference.did, /^did:web:awiki\.me:/u);
    const document = await runtime.rpc('manager/publicDocument', status.reference);
    assert.equal(JSON.stringify(document).includes('RootControl'), false);
    const response = await fetch(status.clientId, { redirect: 'error', signal: AbortSignal.timeout(15000) });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).client_id, status.clientId);
  }));
