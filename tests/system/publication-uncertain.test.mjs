import assert from 'node:assert/strict';
import { test } from 'node:test';
import { withPublishedIdentity } from '../support/published-identity.mjs';

test('ID-S09 a lost real publication receipt reconciles through the public manager without repeating the document update', { timeout: 420000 }, async t => {
  for (const profile of ['e1', 'web']) await t.test(profile, { timeout: 200000 }, () =>
    withPublishedIdentity(profile, async (runtime, published) => {
      assert.equal(published.state, 'published');
      assert.equal((await runtime.rpc('manager/publicationStatus', published.reference)).state, 'published');
      const metadata = await fetch(published.clientId, { redirect: 'error', signal: AbortSignal.timeout(15000) });
      assert.equal(metadata.status, 200);
      assert.equal((await metadata.json()).client_id, published.clientId);
      assert.deepEqual(await runtime.rpc('publication/abort-boundary'), { abortAvailable: false });
    }, {
      beforeOtp: runtime => runtime.rpc('fault/publication-receipt'),
      afterOtp: async (runtime, reference) => {
        const deadline = Date.now() + 60000;
        let bootstrap;
        while (Date.now() < deadline) {
          bootstrap = (await runtime.rpc('manager/registrationBootstrapStatus'))[0];
          if (['blocked', 'registration_uncertain', 'published'].includes(bootstrap?.phase)) break;
          await new Promise(resolve => setTimeout(resolve, 200));
        }
        const before = await runtime.rpc('fault/publication-status');
        assert.equal(before.applied, true, JSON.stringify(before));
        assert.equal(bootstrap?.phase, 'blocked');
        assert.equal(bootstrap.reason, 'publication_failed');
        assert.ok(before.updates.length > 0);
        for (let index = 1; index < before.updates.length; index++)
          assert.equal(before.updates[index].documentVersion, before.updates[index - 1].documentVersion + 1);
        assert.equal((await runtime.rpc('manager/publicationStatus', reference)).state, 'failed');
        // This manager operation queries authoritative checkpoints and reconciles the pending native change.
        const published = await runtime.rpc('manager/retryPublication', reference);
        assert.equal(published.state, 'published');
        const after = await runtime.rpc('fault/publication-status');
        assert.equal(after.applied, true);
        assert.deepEqual(after.updates, before.updates);
        assert.equal((await runtime.rpc('manager/listIdentities')).length, 1);
        return { ...published, reference };
      },
    }));
});
