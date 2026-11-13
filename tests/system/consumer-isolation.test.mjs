import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { withPublishedIdentity } from '../support/published-identity.mjs';

const require = createRequire(new URL('../../packages/dsh-anp-identity/package.json', import.meta.url));
const { parse, stringify } = require('yaml');
const anpConsumer = '@anp-acceptance/identity-consumer/anp-consumer';
const papConsumer = '@anp-acceptance/identity-consumer/pap-consumer';

test('ID-S08 published identity keeps installed ANP and PAP consumers and signing purposes isolated', { timeout: 420000 }, async t => {
  for (const profile of ['e1', 'web']) await t.test(profile, { timeout: 200000 }, () =>
    withPublishedIdentity(profile, async (runtime, published) => {
      const response = await fetch('https://agent-network-protocol.com/.well-known/poppy.json',
        { signal: AbortSignal.timeout(15000) });
      assert.equal(response.status, 200);
      const metadata = await response.text();
      const company = new URL(response.url).origin;
      assert.equal(company, 'https://agent.agent-network-protocol.com');
      assert.equal(JSON.parse(metadata).protocol_version, '0.3');
      const resource = company + '/pap/api/protocols';
      const discovery = { profile: 'pap_session', issuer: company, resource, companyId: company,
        metadataDigest: createHash('sha256').update(metadata).digest('hex'), expiresAt: Date.now() + 120000,
        sources: { resource: response.url, authorizationServer: response.url } };
      // A task-owned Host policy is the public configuration approval, not a catalog mutation.
      const patchPath = join(runtime.profile, 'cordis.patch.yml');
      await runtime.stop();
      const patch = parse(await readFile(patchPath, 'utf8'));
      const identity = patch.find(entry => entry.insert).insert.find(entry => entry.id === 'identity');
      identity.config.protocolPolicies = [{ id: 'acceptance-pap', version: 1, consumer: papConsumer,
        owner: '@agent-network-protocol/dsh-anp-identity', identity: published.reference, profiles: ['pap_session'],
        issuers: [company], resources: [resource], publicTargets: false, scopes: [], expiresAt: discovery.expiresAt }];
      await writeFile(patchPath, stringify(patch), { mode: 0o600 });
      await runtime.start();
      const pending = await runtime.rpc('isolation/anp/access', { requestId: randomUUID(),
        purpose: 'Read the public protocol catalog through ANP', identity: published.reference });
      assert.equal(pending.caller.consumer, anpConsumer);
      const review = await runtime.rpc('manager/getRequest', pending.id);
      const approved = await runtime.rpc('manager/decide', { requestId: pending.id, expectedVersion: pending.version,
        decision: 'approve', identity: published.reference, mode: 'permanent', reviewedSnapshot: review.snapshot });
      await assert.rejects(runtime.rpc('isolation/pap/openOtherGrant', approved.grantId));
      await assert.rejects(runtime.rpc('open', approved.grantId));
      const read = async () => {
        const value = await runtime.rpc('isolation/anp/read', { grantId: approved.grantId, executionId: randomUUID() });
        assert.equal(value.status, 200);
        assert.ok(Array.isArray(value.versions) && value.versions.length > 0);
        return value;
      };
      assert.equal((await read()).status, 200);
      const bind = () => runtime.rpc('isolation/pap/bind', { identityRef: published.reference,
        policyRef: 'acceptance-pap', requestedScopes: [], discovery });
      assert.equal((await bind()).purpose, 'pap_session');
      const delegate = () => runtime.rpc('isolation/pap/delegate');
      assert.deepEqual(await delegate(), { verified: true, clientId: published.clientId });
      await assert.rejects(runtime.rpc('isolation/pap/wrongPurpose'), { code: 'capability_forbidden' });
      await runtime.rpc('isolation/pap/dispose');
      await assert.rejects(delegate());
      assert.equal((await read()).status, 200);
      await bind();
      const grant = (await runtime.rpc('manager/grants', published.reference)).find(value => value.id === approved.grantId);
      await runtime.rpc('manager/revoke', { grantId: grant.id, expectedVersion: grant.version });
      await assert.rejects(read());
      assert.deepEqual(await delegate(), { verified: true, clientId: published.clientId });
      await assert.rejects(runtime.rpc('isolation/pap/bind', { identityRef: published.reference,
        policyRef: 'acceptance-pap', requestedScopes: ['admin'], discovery }), { code: 'capability_forbidden' });
      assert.deepEqual(await delegate(), { verified: true, clientId: published.clientId });
    }, { runtimeOptions: { consumerIsolation: true } }));
});
