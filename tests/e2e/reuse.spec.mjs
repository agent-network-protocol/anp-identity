import assert from 'node:assert/strict';
import { test } from 'node:test';
import { withPublishedIdentity } from '../support/published-identity.mjs';
import { withUserBrowser } from '../support/browser-actor.mjs';

async function inspectExistingUi(runtime, reference) {
  await withUserBrowser(runtime, async actor => {
    await actor.openIdentities();
    const identity = actor.page.getByRole('navigation', { name: '我的身份', exact: true })
      .getByRole('button').filter({ hasText: reference.did });
    assert.equal(await identity.count(), 1);
    await identity.click();
    assert.equal(await identity.getAttribute('aria-current'), 'true');
    await actor.page.getByText('已发布', { exact: true }).first().waitFor({ timeout: 15000 });
  });
}
function assertExistingStatus(turn, reference) {
  const status = turn.calls.filter(call => call.name === 'identity_status' && call.value?.ok === true);
  assert.ok(status.length > 0);
  assert.deepEqual(status.at(-1).value.value.identities.map(identity => identity.reference), [reference]);
  assert.equal(status.at(-1).value.value.identities[0].state, 'published');
  assert.equal(turn.calls.some(call => call.name === 'identity_request_creation'), false);
  assert.equal(turn.calls.some(call => /^(?:bash|pwsh|web_fetch|mcp__)/u.test(call.name)), false);
  assert.ok(turn.output.includes(reference.did));
  assert.match(turn.output, /已发布|published/iu);
}

test('ID-E03 a real model and identity UI reuse the existing published identity without a new factor challenge', { timeout: 300000 }, () =>
  withPublishedIdentity('e1', async (runtime, published) => {
    await inspectExistingUi(runtime, published.reference);
    const requests = await runtime.rpc('manager/listRequests', true);
    const before = await runtime.rpc('network/status');
    assert.ok(before.factorRequests > 0);
    const turn = await runtime.rpc('model/task', { task:
      '我已经有公共身份。请检查当前已有身份及发布状态，显示它的 DID 和发布状态，说明能否继续使用它。不需要创建新身份，也不要再次申请手机号验证；不要访问文件或执行 shell。' }, { timeoutMs: 180000 });
    assertExistingStatus(turn, published.reference);
    assert.deepEqual(await runtime.rpc('manager/listRequests', true), requests);
    assert.equal((await runtime.rpc('network/status')).factorRequests, before.factorRequests);
    assert.deepEqual((await runtime.rpc('manager/listIdentities')).map(identity => identity.reference), [published.reference]);
  }, { runtimeOptions: { web: true, realModel: true } }));

test('ID-E05 an actual Host restart preserves the identity and model session with honest tool status', { timeout: 420000 }, () =>
  withPublishedIdentity('e1', async (runtime, published) => {
    const first = await runtime.rpc('model/task', { task:
      '请查询当前公共身份及发布状态，显示 DID 和发布状态，记住本次会话看到的身份；不要创建新身份或访问文件。' }, { timeoutMs: 180000 });
    assertExistingStatus(first, published.reference);
    const requests = await runtime.rpc('manager/listRequests', true);
    const pid = runtime.evidence.pid;
    await runtime.stop();
    await runtime.start();
    assert.notEqual(runtime.evidence.pid, pid);
    await inspectExistingUi(runtime, published.reference);
    const available = await runtime.rpc('tools');
    assert.ok(available.includes('identity_status'));
    assert.ok(available.includes('identity_connection_guide'));
    const before = await runtime.rpc('network/status');
    const resumed = await runtime.rpc('model/resume', { sessionId: first.sessionId, task:
      'DSH 已关闭并重新启动。请重新查询当前公共身份和发布状态，显示 DID 和发布状态，与重启前本次会话看到的身份比较，说明是否保持同一身份；只报告工具能确认的事实，不要创建身份、请求验证或访问文件。' }, { timeoutMs: 180000 });
    assert.equal(resumed.sessionId, first.sessionId);
    assertExistingStatus(resumed, published.reference);
    assert.deepEqual(await runtime.rpc('manager/listRequests', true), requests);
    assert.equal((await runtime.rpc('network/status')).factorRequests, before.factorRequests);
    assert.deepEqual((await runtime.rpc('manager/listIdentities')).map(identity => identity.reference), [published.reference]);
  }, { runtimeOptions: { web: true, realModel: true } }));
