import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { writeFile, unlink, readdir, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRuntime } from './runtime.mjs';
import { identityOperator } from './identity-operator.mjs';
import { loadTestFactor, AcceptanceError, IDENTITY_ORIGIN } from './config.mjs';
import { withFactorLock } from './factor-lock.mjs';

/** Public capability discovery precedes any factor challenge or remote registration. */
export async function verifyIdentityProfile(profile) {
  const response = await fetch(IDENTITY_ORIGIN + '/user-service/v1/server-info',
    { redirect: 'error', signal: AbortSignal.timeout(15000) });
  if (response.status !== 200) throw new AcceptanceError('acceptance_identity_capabilities_unavailable');
  const methods = (await response.json()).identity?.did_methods;
  const selected = Array.isArray(methods) ? methods.filter(method => method.id === (profile === 'e1' ? 'wba' : 'web')) : [];
  if (selected.length !== 1 || typeof selected[0].create !== 'boolean')
    throw new AcceptanceError('acceptance_identity_capabilities_invalid');
  if (!selected[0].create) throw new AcceptanceError('acceptance_target_' + profile + '_creation_disabled');
}

async function until(runtime, phase) {
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    const status = (await runtime.rpc('manager/registrationBootstrapStatus'))[0];
    if (status?.phase === phase) return status;
    if (['blocked', 'registration_uncertain', 'disposed'].includes(status?.phase))
      throw new AcceptanceError('acceptance_registration_' + status.phase + '_' + (status.reason ?? 'unknown'));
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  throw new AcceptanceError('acceptance_registration_timeout');
}

/** Real public registration, with exact recovery input persisted before submitting OTP. */
export async function withPublishedIdentity(profile, run, { runtimeOptions = {}, beforeOtp, afterOtp } = {}) {
  return withFactorLock(async () => {
    await verifyIdentityProfile(profile);
    for (const name of await readdir(tmpdir())) {
      if (!name.startsWith('dsh-acceptance-')) continue;
      try {
        const recovery = join(tmpdir(), name, 'identity-recovery.json');
        const info = await lstat(recovery);
        if (info.uid === process.getuid()) throw new AcceptanceError('acceptance_identity_recovery_required; recovery=' + recovery);
      } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    const factor = await loadTestFactor();
    assert.equal((await identityOperator({ action: 'preflight' })).ready, true);
    const runtime = await createRuntime({ ...runtimeOptions, outputAuditFactor: factor });
    const runId = randomUUID(), handle = 'systestdw' + runId.replaceAll('-', '').slice(0, 16);
    let scope, peers, registered = false;
    const recovery = join(runtime.root, 'identity-recovery.json');
    try {
      await runtime.start();
      const onboarding = await runtime.rpc('manager/registrationOnboardingStatus');
      const started = await runtime.rpc('manager/startIdentityRegistration', {
        expectedOrigin: 'https://awiki.me', expectedVersion: onboarding.version,
        handle, label: 'DSH acceptance ' + profile, profile, phone: factor.phone,
      });
      assert.equal(started.status, 'awaiting_approval');
      assert.deepEqual(await runtime.rpc('manager/listIdentities'), []);
      const review = await runtime.rpc('manager/getRequest', started.requestId);
      const approved = await runtime.rpc('manager/decide', { requestId: started.requestId,
        expectedVersion: review.request.version, decision: 'approve' });
      assert.ok(approved.result?.reference);
      scope = { runId, handle, did: approved.result.reference.did };
      await writeFile(recovery, JSON.stringify(scope), { mode: 0o600, flag: 'wx' });
      peers = await identityOperator({ action: 'peers', ...scope });
      await writeFile(join(runtime.root, 'identity-peer-baseline.json'), JSON.stringify(peers), { mode: 0o600, flag: 'wx' });
      await until(runtime, 'awaiting_phone_verification');
      await beforeOtp?.(runtime);
      await runtime.rpc('manager/submitRegistrationOtp', { code: factor.code });
      const published = afterOtp ? await afterOtp(runtime, approved.result.reference) : await until(runtime, 'published');
      registered = true;
      assert.equal(new URL(published.clientId).origin, 'https://awiki.me');
      assert.equal((await identityOperator({ action: 'observe', ...scope })).matched, true);
      await run(runtime, published);
    } finally {
      // Drain registration/publication before attempting remote cleanup.
      await runtime.stop();
      try {
        if (scope) {
          const cleaned = await identityOperator({ action: 'cleanup', ...scope });
          assert.equal(cleaned.cleanupComplete, true);
          if (registered) assert.equal(cleaned.accountsDeleted, 1);
          if (peers) assert.deepEqual(await identityOperator({ action: 'peers', ...scope }), peers);
          await unlink(recovery);
        }
      } catch (error) {
        throw new AcceptanceError(error.code + '; recovery=' + recovery);
      }
      await runtime.dispose();
    }
  });
}
