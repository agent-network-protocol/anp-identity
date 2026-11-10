/** Real installed-caller/owner boundary with native custody; no live service or UI evidence. */
import { expect, it } from 'vitest'
import type AnpIdentityService from '../src/index.js'
import { initialProtocolPolicy } from '../src/protocol-policy-types.js'
import { createNativeProtocolFixture } from './helpers/native-protocol-fixture.js'

it('only the owner edits protocol settings; installed adapters receive revocable decisions, not management powers', async () => {
  const f = await createNativeProtocolFixture({ consumer: '@awiki/dsh-pap/plugin',
    additionalConsumers: [{ consumer: '@deepseek-ai/dsh-mcp-client' }],
    domainAccess: { enabled: true, scopes: ['protocol.read'], secretStore: 'local-file' } })
  try {
    const manager = f.managerContext.anpIdentity as AnpIdentityService
    const { schema: _schema, version: _version, ...policy } = initialProtocolPolicy()
    policy.write.mode = 'allow_all'
    await expect(f.service.protocolManagement(f.context)).rejects.toMatchObject({ code: 'consumer_forbidden' })
    await expect(f.service.configureProtocolPolicy(f.context, { expectedVersion: 0, policy })).rejects.toMatchObject({ code: 'consumer_forbidden' })
    expect(() => f.service.bindProtocolPolicy(f.context, 'anp')).toThrow(expect.objectContaining({ code: 'consumer_forbidden' }))
    const before = await manager.protocolManagement(f.managerContext)
    expect(before.policy.version).toBe(0)
    expect(before.protocols.find(item => item.protocol === 'pap')).toMatchObject({ installed: true, enabled: true, ready: false, managedAdapters: 0, unmanagedAdapters: 1 })
    const client = f.service.bindProtocolPolicy(f.context, 'pap')
    expect(f.service.bindProtocolPolicy(f.context, 'pap')).toBe(client)
    expect(Object.keys(client).sort()).toEqual(['assertNoDenial', 'classifyHttp', 'classifyMcp', 'classifyScopes', 'evaluate', 'forget', 'register'])
    const target = client.register({ discoveryOrigin: 'https://shop.example', destinations: ['https://agent.shop.example'] })
    const pending = await client.evaluate(target, { url: 'https://agent.shop.example/posts', effect: 'write' })
    expect(pending.decision).toBe('ask')
    await manager.configureProtocolPolicy(f.managerContext, { expectedVersion: 0, policy })
    await expect(pending.assertActive()).rejects.toMatchObject({ code: 'protocol_policy_changed' })
    expect((await client.evaluate(target, { url: 'https://agent.shop.example/posts', effect: 'write' })).decision).toBe('allow')
    const after = await manager.protocolManagement(f.managerContext)
    expect(after.protocols.find(item => item.protocol === 'pap')).toMatchObject({ ready: true, managedAdapters: 1, unmanagedAdapters: 0 })
    expect(after.protocols.find(item => item.protocol === 'mcp')).toMatchObject({ installed: true, ready: false, managedAdapters: 0, unmanagedAdapters: 1 })
    expect(after.protocols.find(item => item.protocol === 'anp')).toMatchObject({ installed: false, enabled: false })
    const request = new Request('https://agent.shop.example/posts', {method:'POST',body:'denied exact content'})
    await client.assertNoDenial(request.clone())
    const consent = f.service.bindDomainOperationConsumer(f.context)
    const refused = await consent.request({requestId:'denied-policy-test',purpose:'Exact operation refusal',request:request.clone()})
    await f.management.decide({requestId:refused.id,expectedVersion:refused.version,decision:'deny'})
    await expect(client.assertNoDenial(request.clone())).rejects.toMatchObject({code:'request_previously_denied'})
    await client.assertNoDenial(new Request(request.url,{method:'POST',body:'different operation'}))
    await expect(manager.configureProtocolPolicy(f.managerContext, { expectedVersion: 0, policy })).rejects.toMatchObject({ code: 'protocol_policy_conflict' })
  } finally { await f.dispose() }
// Native publication and the durable ledger are integration setup, not a short latency assertion.
}, 30000)

it('does not report an expired global domain permission as ready even with a managed adapter', async () => {
  const f = await createNativeProtocolFixture({ consumer: '@awiki/dsh-pap/plugin',
    domainAccess: { enabled: true, scopes: [], expiresAt: Date.now() - 1000 } })
  try {
    f.service.bindProtocolPolicy(f.context, 'pap')
    const state = await (f.managerContext.anpIdentity as AnpIdentityService).protocolManagement(f.managerContext)
    expect(state.protocols.find(item => item.protocol === 'pap')).toMatchObject({ managedAdapters: 1, ready: false })
  } finally { await f.dispose() }
}, 30000)
