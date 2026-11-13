import assert from 'node:assert/strict';
import { test } from 'node:test';
import { withPublishedIdentity } from '../support/published-identity.mjs';
import { withUserBrowser } from '../support/browser-actor.mjs';

const consumer = '@anp-acceptance/identity-consumer/anp-consumer';
function successfulRead(turn) {
  const calls = turn.calls.filter(call => call.name === 'acceptance_identity_catalog');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].value?.ok, true);
  assert.equal(calls[0].value.value.status, 200);
  assert.ok(calls[0].value.value.versions.length > 0);
  assert.equal(turn.calls.some(call => /^(?:bash|pwsh|web_fetch|mcp__|pap_)/u.test(call.name)), false);
}

test('ID-E04 real UI once approval, a new operation and revocation fence a real model consumer', { timeout: 420000 }, () =>
  withPublishedIdentity('e1', async (runtime, published) => {
    await withUserBrowser(runtime, async actor => {
      await actor.openIdentities();
      const approval = actor.page.getByRole('dialog').filter({ has: actor.page.getByRole('button', { name: '允许授权', exact: true }) });
      async function approve(model, mode, sent) {
        model.catch(() => {});
        const reached = await Promise.race([approval.waitFor({ timeout: 120000 }).then(() => true), model.then(() => false)]);
        assert.equal(reached, true);
        assert.ok((await approval.innerText()).includes(consumer));
        assert.ok((await approval.innerText()).includes('agent.agent-network-protocol.com'));
        assert.equal((await runtime.rpc('network/status')).businessRequests, sent);
        const pending = (await runtime.rpc('manager/listRequests')).filter(value => value.kind === 'access' && value.status === 'pending');
        assert.equal(pending.length, 1);
        assert.equal(pending[0].caller.consumer, consumer);
        const choice = approval.getByLabel('使用哪个身份', { exact: true });
        assert.ok((await choice.locator('option:checked').innerText()).includes(published.reference.did));
        await approval.getByRole('radio', { name: mode === 'once' ? /^单次授权/u : /^永久授权/u }).check();
        await approval.getByRole('button', { name: '允许授权', exact: true }).click();
        const turn = await model;
        successfulRead(turn);
        const reviewed = await runtime.rpc('manager/getRequest', pending[0].id);
        assert.equal(reviewed.request.mode, mode);
        assert.equal(reviewed.grant.mode, mode);
        assert.deepEqual(reviewed.grant.identity, published.reference);
        return reviewed;
      }
      const first = await approve(runtime.rpc('model/task', { task:
        '请通过已安装的身份验收读取工具读取官网协议目录一次。我会在身份界面批准。不要自行审批、创建身份、读取文件或改走其他协议。' }, { timeoutMs: 180000 }), 'once', 0);
      assert.equal(first.grant.status, 'consumed');
      assert.equal((await runtime.rpc('network/status')).businessRequests, 1);
      const second = await approve(runtime.rpc('model/followup', { task:
        '请用同一个身份验收读取工具再读取一次最新目录。这是新的操作，我会在身份界面重新决定权限，请等待批准。不要复用已消费的单次授权或改走其他通道。' }, { timeoutMs: 180000 }), 'permanent', 1);
      assert.notEqual(second.request.id, first.request.id);
      assert.notEqual(second.grant.id, first.grant.id);
      assert.equal(second.grant.status, 'active');
      assert.equal((await runtime.rpc('isolation/anp/tool-status')).consumedReuseRejected, 1);
      assert.equal((await runtime.rpc('network/status')).businessRequests, 2);
      const identity = actor.page.getByRole('navigation', { name: '我的身份', exact: true })
        .getByRole('button').filter({ hasText: published.reference.did });
      await identity.click();
      const grantRow = actor.page.locator('.anpi-row').filter({ has: actor.page.getByText(consumer, { exact: true }) })
        .filter({ has: actor.page.getByText('全部权限 · 永久授权', { exact: true }) });
      await grantRow.getByRole('button', { name: '撤销', exact: true }).waitFor({ timeout: 15000 });
      assert.equal(await grantRow.count(), 1);
      await grantRow.getByRole('button', { name: '撤销', exact: true }).click();
      const revoke = actor.page.getByRole('dialog', { name: '撤销授权', exact: true });
      await revoke.getByRole('button', { name: '确认撤销', exact: true }).click();
      const deadline = Date.now() + 15000;
      while ((await runtime.rpc('manager/getRequest', second.request.id)).grant.status !== 'revoked') {
        assert.ok(Date.now() < deadline);
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      const history = await runtime.rpc('manager/listRequests', true);
      const denied = await runtime.rpc('model/followup', { task:
        '我已在身份界面撤销你的持续授权。请通过同一个身份验收读取工具尝试一次并准确报告结果；不要重新申请权限、重试、读取文件或换其他通道。' }, { timeoutMs: 180000 });
      const attempts = denied.calls.filter(call => call.name === 'acceptance_identity_catalog');
      assert.equal(attempts.length, 1);
      assert.equal(attempts[0].value.ok, false);
      assert.ok(['grant_conflict', 'grant_inactive'].includes(attempts[0].value.error));
      assert.match(denied.output, /撤销|无权|权限|授权/u);
      assert.equal(denied.calls.some(call => /^(?:bash|pwsh|web_fetch|mcp__|pap_|identity_request_creation)/u.test(call.name)), false);
      assert.equal((await runtime.rpc('network/status')).businessRequests, 2);
      assert.deepEqual(await runtime.rpc('manager/listRequests', true), history);
    });
  }, { runtimeOptions: { web: true, realModel: true, consumerIsolation: true } }));
