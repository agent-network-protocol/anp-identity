import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { createRuntime } from '../support/runtime.mjs';
import { withUserBrowser } from '../support/browser-actor.mjs';
import { loadTestFactor, AcceptanceError } from '../support/config.mjs';
import { withFactorLock } from '../support/factor-lock.mjs';
import { identityOperator } from '../support/identity-operator.mjs';
import { writeFile, unlink, readdir, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyIdentityProfile } from '../support/published-identity.mjs';

test('ID-E01 a real model opens creation and the user approves and verifies through the actual UI', { timeout: 420000 }, () =>
  withFactorLock(async () => {
    const factor = await loadTestFactor();
    if (!/^\+[1-9][0-9]{6,14}$/u.test(factor.phone))
      throw new AcceptanceError('acceptance_ui_test_factor_incompatible');
    for (const name of await readdir(tmpdir())) {
      if (!name.startsWith('dsh-acceptance-')) continue;
      try {
        if ((await lstat(join(tmpdir(), name, 'identity-recovery.json'))).uid === process.getuid())
          throw new AcceptanceError('acceptance_identity_recovery_required');
      } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    assert.equal((await identityOperator({ action: 'preflight' })).ready, true);
    await verifyIdentityProfile('e1');
    const runtime = await createRuntime({ web: true, realModel: true, outputAuditFactor: factor });
    const runId = randomUUID(), handle = 'systestdw' + runId.replaceAll('-', '').slice(0, 16);
    const recovery = join(runtime.root, 'identity-recovery.json');
    let scope, peers;
    try {
      await runtime.start();
      await withUserBrowser(runtime, async actor => {
        await actor.openIdentities();
        const requested = await runtime.rpc('model/task', { task:
          '请帮我建立用于三方服务的公共身份，打开创建入口。我会自己在真实身份界面批准和填写验证信息，不要在聊天里索要手机号、邮箱或验证码。' }, { timeoutMs: 180000 });
        assert.ok(requested.calls.some(call => call.name === 'identity_request_creation' && call.value?.ok === true));
        const name = actor.page.getByLabel('身份名称', { exact: true });
        try { await name.waitFor({ timeout: 10000 }); }
        catch (error) {
          if (error.name !== 'TimeoutError') throw error;
          await actor.page.getByRole('button', { name: '创建公共身份', exact: true }).click();
        }
        await name.fill('DSH GUI acceptance');
        await actor.page.getByLabel('Handle', { exact: true }).fill(handle);
        await actor.enterPhone(factor.phone);
        await actor.page.getByRole('button', { name: '申请创建并注册', exact: true }).click();
        const approval = actor.page.getByRole('dialog').filter({ has: actor.page.getByRole('button', { name: '允许创建', exact: true }) });
        await approval.waitFor({ timeout: 15000 });
        assert.ok((await approval.innerText()).includes(handle + '.awiki.me'));
        assert.deepEqual(await runtime.rpc('manager/listIdentities'), []);
        scope = { runId, handle, did: 'did:wba:awiki.me:awiki:user:' + handle };
        await writeFile(recovery, JSON.stringify(scope), { mode: 0o600, flag: 'wx' });
        peers = await identityOperator({ action: 'peers', ...scope });
        await writeFile(join(runtime.root, 'identity-peer-baseline.json'), JSON.stringify(peers), { mode: 0o600, flag: 'wx' });
        await approval.getByRole('button', { name: '允许创建', exact: true }).click();
        await actor.page.getByLabel('短信验证码', { exact: true }).waitFor({ timeout: 60000 });
        const current = (await runtime.rpc('manager/listIdentities'));
        assert.equal(current.length, 1);
        assert.ok(current[0].reference.did.startsWith(scope.did + ':e1_'));
        scope = { ...scope, did: current[0].reference.did };
        await writeFile(recovery, JSON.stringify(scope), { mode: 0o600 });
        await actor.enterOtp(factor.code);
        const deadline = Date.now() + 60000;
        let published;
        while (Date.now() < deadline) {
          published = (await runtime.rpc('manager/registrationBootstrapStatus'))[0];
          if (published?.phase === 'published') break;
          if (['blocked', 'registration_uncertain', 'disposed'].includes(published?.phase))
            throw new AcceptanceError('acceptance_registration_' + published.phase);
          await new Promise(resolve => setTimeout(resolve, 200));
        }
        assert.equal(published?.phase, 'published');
        assert.equal(published.reference.did, scope.did);
        await actor.page.getByText('已发布', { exact: true }).first().waitFor();
        assert.equal((await identityOperator({ action: 'observe', ...scope })).matched, true);
        const publicDid = await runtime.rpc('manager/publicDocument', published.reference);
        assert.equal(publicDid.id, scope.did);
        const response = await fetch(published.clientId, { redirect: 'error', signal: AbortSignal.timeout(15000) });
        assert.equal(response.status, 200);
        assert.equal((await response.json()).client_id, published.clientId);
        const result = await runtime.rpc('model/followup', { task:
          '我已在身份界面完成批准和验证。请重新查询身份状态，显示 DID 和发布状态；只报告工具确认的结果，不要再次创建或申请验证。' }, { timeoutMs: 180000 });
        const status = result.calls.filter(call => call.name === 'identity_status' && call.value?.ok === true).at(-1);
        assert.ok(status);
        assert.deepEqual(status.value.value.identities.map(identity => identity.reference), [published.reference]);
        assert.equal(status.value.value.identities[0].state, 'published');
        assert.ok(result.output.includes(scope.did));
        const modelOutput = JSON.stringify([requested, result]);
        assert.equal(modelOutput.includes(factor.phone), false);
        assert.equal(modelOutput.includes(factor.code), false);
        assert.equal(result.calls.some(call => call.name === 'identity_request_creation'), false);
      });
    } finally {
      await runtime.stop();
      if (scope) {
        try {
          assert.equal((await identityOperator({ action: 'cleanup', ...scope })).cleanupComplete, true);
          if (peers) assert.deepEqual(await identityOperator({ action: 'peers', ...scope }), peers);
          await unlink(recovery);
        } catch { throw new AcceptanceError('acceptance_identity_recovery_required; recovery=' + recovery); }
      }
      await runtime.dispose();
    }
  }));

test('ID-E02 a real UI rejection prevents model-requested identity creation', { timeout: 300000 }, () =>
  withFactorLock(async () => {
    const factor = await loadTestFactor();
    if (!/^\+[1-9][0-9]{6,14}$/u.test(factor.phone))
      throw new AcceptanceError('acceptance_ui_test_factor_incompatible');
    const runtime = await createRuntime({ web: true, realModel: true });
    let phase = 'startup';
    try {
      await runtime.start();
      await withUserBrowser(runtime, async actor => {
        await actor.openIdentities();
        phase = 'model_request';
        const requested = await runtime.rpc('model/task', { task:
          '请帮我创建一个用于登录三方服务的公共身份，打开创建入口。我会自己在界面输入验证信息，请不要在聊天中索要手机号或验证码。' }, { timeoutMs: 180000 });
        assert.ok(requested.calls.some(call => call.name === 'identity_request_creation' && call.value?.ok === true));
        phase = 'form';
        const nameInput = actor.page.getByLabel('身份名称', { exact: true });
        try { await nameInput.waitFor({ state: 'visible', timeout: 10000 }); }
        catch (error) {
          if (error.name !== 'TimeoutError') throw error;
          await actor.page.getByRole('button', { name: '创建公共身份', exact: true }).click();
        }
        const handle = 'systestdw' + randomUUID().replaceAll('-', '').slice(0, 16);
        phase = 'name';
        await actor.page.getByLabel('身份名称', { exact: true }).fill('Rejected DSH identity');
        await actor.page.getByLabel('Handle', { exact: true }).fill(handle);
        phase = 'phone';
        await actor.enterPhone(factor.phone);
        phase = 'submit';
        await actor.page.getByRole('button', { name: '申请创建并注册', exact: true }).click();
        const approval = actor.page.getByRole('dialog').filter({ has: actor.page.getByRole('button', { name: '允许创建', exact: true }) });
        phase = 'approval';
        await approval.waitFor({ timeout: 15000 });
        assert.ok((await approval.innerText()).includes(handle + '.awiki.me'));
        assert.deepEqual(await runtime.rpc('manager/listIdentities'), []);
        await approval.getByRole('button', { name: '拒绝', exact: true }).click();
        phase = 'denied_status';
        const deadline = Date.now() + 15000;
        let denied;
        while (Date.now() < deadline) {
          denied = (await runtime.rpc('manager/listRequests', true)).find(request => request.kind === 'create' && request.parameters.handle === handle + '.awiki.me');
          if (denied?.status === 'denied') break;
          await new Promise(resolve => setTimeout(resolve, 100));
        }
        assert.equal(denied?.status, 'denied');
        assert.equal(denied.result, undefined);
        phase = 'model_followup';
        const response = await runtime.rpc('model/followup', { task:
          '我拒绝了创建。请查询当前身份状态并说明结果，不要再次申请创建。' }, { timeoutMs: 180000 });
        assert.ok(response.calls.some(call => call.name === 'identity_status' && call.value?.ok === true));
        assert.equal(response.calls.some(call => call.name === 'identity_request_creation'), false);
        assert.deepEqual(await runtime.rpc('manager/listIdentities'), []);
      });
    } catch (error) {
      if (typeof error.code === 'string') error.code += '; phase=' + phase;
      throw error;
    } finally { await runtime.dispose(); }
  }));
