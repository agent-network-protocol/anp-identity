import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { createRuntime } from '../support/runtime.mjs';

const referenceEqual = (a, b) => assert.deepEqual(a, b);
const creation = (label = 'DSH system authorization') => ({ requestId: randomUUID(),
  purpose: 'Verify the ordinary consumer authorization boundary',
  parameters: { profile: 'e1', label, domain: 'awiki.me', path: '/awiki/user/acceptance-' + randomUUID() } });
async function withRuntime(run) {
  const runtime = await createRuntime();
  try { await runtime.start(); await run(runtime); }
  finally { await runtime.dispose(); }
}
async function create(runtime) {
  const input = creation();
  const pending = await runtime.rpc('create', input);
  assert.equal(pending.status, 'pending');
  assert.equal(pending.result, undefined);
  const approved = await runtime.rpc('manager/decide', { requestId: pending.id,
    expectedVersion: pending.version, decision: 'approve' });
  assert.equal(approved.executionStatus, 'succeeded');
  assert.ok(approved.result?.reference);
  return approved.result;
}
async function grant(runtime, reference, mode) {
  const pending = await runtime.rpc('access', { requestId: randomUUID(), purpose: 'Read public identity',
    identity: reference, operation: { action: 'read' } });
  const review = await runtime.rpc('manager/getRequest', pending.id);
  assert.ok(review.snapshot);
  return runtime.rpc('manager/decide', { requestId: pending.id, expectedVersion: pending.version,
    decision: 'approve', identity: reference, mode, reviewedSnapshot: review.snapshot });
}
async function remove(runtime, result) {
  for (const current of await runtime.rpc('manager/grants', result.reference)) {
    if (current.status === 'active') await runtime.rpc('manager/revoke', { grantId: current.id, expectedVersion: current.version });
  }
  await runtime.rpc('manager/deleteIdentity', { reference: result.reference, confirmationName: result.label });
  assert.equal((await runtime.rpc('manager/listIdentities')).length, 0);
}

test('ID-S01 candidate packages load in the actual isolated DSH CLI', { timeout: 180000 }, t => withRuntime(async runtime => {
  const health = await runtime.rpc('health');
  assert.notEqual(health.status, 'unavailable');
  assert.equal(runtime.evidence.runtime, 'actual-dsh-cli');
  assert.ok(runtime.evidence.pid > 0);
  const installation = runtime.evidence.installation;
  assert.equal(installation.subject.version, runtime.evidence.candidateVersion);
  assert.equal(installation.identity.version, runtime.evidence.candidateVersion);
  assert.equal(installation.platform, process.platform);
  assert.equal(installation.arch, process.arch);
  assert.match(installation.subject.tarballSha256, /^[a-f0-9]{64}$/u);
  assert.match(installation.native.sha256, /^[a-f0-9]{64}$/u);
  assert.equal(installation.native.version, installation.native.wrapperVersion);
  assert.ok(installation.native.path.startsWith(runtime.profile + '/node_modules/'));
  t.diagnostic(JSON.stringify(installation));
  for (const path of Object.values(runtime.evidence.installed)) {
    assert.ok(path.startsWith(runtime.profile + '/node_modules/'));
    assert.equal(path.includes('/src/'), false);
  }
  assert.deepEqual(await runtime.rpc('manager/listIdentities'), []);
}));

test('ID-S04 denied and cancelled creation never creates an identity', { timeout: 180000 }, () => withRuntime(async runtime => {
  const cancelled = await runtime.rpc('create', creation('Cancelled identity'));
  const result = await runtime.rpc('cancelCreate', { requestId: cancelled.id, expectedVersion: cancelled.version });
  assert.equal(result.status, 'cancelled');
  await assert.rejects(runtime.rpc('manager/decide', { requestId: cancelled.id,
    expectedVersion: cancelled.version, decision: 'approve' }));
  const denied = await runtime.rpc('create', creation());
  assert.equal(denied.status, 'pending');
  assert.deepEqual(await runtime.rpc('manager/listIdentities'), []);
  const decided = await runtime.rpc('manager/decide', { requestId: denied.id, expectedVersion: denied.version, decision: 'deny' });
  assert.equal(decided.status, 'denied');
  await assert.rejects(runtime.rpc('create', creation()), { code: 'request_previously_denied' });
  assert.deepEqual(await runtime.rpc('manager/listIdentities'), []);
}));

test('ID-S05 once-only authorization cannot be reused for another execution', { timeout: 180000 }, () => withRuntime(async runtime => {
  const identity = await create(runtime);
  try {
    await assert.rejects(runtime.rpc('read', { grantId: randomUUID(), executionId: randomUUID() }));
    const access = await grant(runtime, identity.reference, 'once');
    assert.equal(access.status, 'approved');
    const executionId = randomUUID();
    const read = await runtime.rpc('read', { grantId: access.grantId, executionId });
    referenceEqual(read.reference, identity.reference);
    await assert.rejects(runtime.rpc('read', { grantId: access.grantId, executionId: randomUUID() }));
    const execution = await runtime.rpc('execution', executionId);
    assert.equal(execution.status, 'succeeded');
  } finally { await remove(runtime, identity); }
}));

test('ID-S06 revocation fences an already retained authorized identity', { timeout: 180000 }, () => withRuntime(async runtime => {
  const identity = await create(runtime);
  try {
    const access = await grant(runtime, identity.reference, 'permanent');
    const read = await runtime.rpc('read', { grantId: access.grantId, executionId: randomUUID() });
    referenceEqual(read.reference, identity.reference);
    const current = (await runtime.rpc('manager/grants', identity.reference)).find(item => item.id === access.grantId);
    await runtime.rpc('manager/revoke', { grantId: current.id, expectedVersion: current.version });
    // The retained lease has the old grant version; new acquisition sees revoked state.
    await assert.rejects(runtime.rpc('read', { grantId: access.grantId, executionId: randomUUID() }), { code: 'grant_conflict' });
    await assert.rejects(runtime.rpc('open', access.grantId), { code: 'grant_inactive' });
  } finally { await remove(runtime, identity); }
}));

test('ID-S07 a real Host restart restores the same identity and persistent grant', { timeout: 180000 }, () => withRuntime(async runtime => {
  const identity = await create(runtime);
  try {
    const access = await grant(runtime, identity.reference, 'permanent');
    await runtime.rpc('read', { grantId: access.grantId, executionId: randomUUID() });
    const pid = runtime.evidence.pid;
    await runtime.stop(); await runtime.start();
    assert.notEqual(runtime.evidence.pid, pid);
    const listed = await runtime.rpc('manager/listIdentities');
    assert.equal(listed.length, 1); referenceEqual(listed[0].reference, identity.reference);
    referenceEqual((await runtime.rpc('read', { grantId: access.grantId, executionId: randomUUID() })).reference, identity.reference);
  } finally { await remove(runtime, identity); }
}));
