import { Context } from '@deepseek-ai/cordis'
import { afterEach, expect, it, vi } from 'vitest'
import { registerConfigurationTools, type ConfigurationHandlers } from '../src/configuration-tools.js'
import { initialProtocolPolicy } from '../src/protocol-policy-types.js'

const roots: Context[] = []
afterEach(async () => { await Promise.all(roots.splice(0).map(ctx => ctx.fiber.dispose())) })
async function fixture() {
  const ctx = new Context(); roots.push(ctx)
  const tools = new Map<string, any>()
  const agent = { id: 'owner-agent', session: { header: {} } }
  let owner = true, outcome = 'allowed-once'
  let policy = initialProtocolPolicy()
  let defaultIdentity = { schema: 1 as const, version: 0, identity: null }
  let registrationService = { origin: 'https://awiki.me', version: 0 }
  const reference = { storeId: 'store', identityId: 'short-identity', did: 'did:wba:identity.example:long-published-did' }
  const handlers: ConfigurationHandlers = {
    assertOwner: () => { if (!owner) throw new Error('consumer_forbidden') },
    protocols: vi.fn(async () => ({ policy: structuredClone(policy), domainAccessEnabled: true, protocols: [] })),
    setProtocols: vi.fn(async (input, check) => { check(); if (input.expectedVersion !== policy.version) throw new Error('protocol_policy_conflict'); policy = { schema: 1, version: policy.version + 1, ...input.policy }; return structuredClone(policy) }),
    identity: vi.fn(async () => ({ defaultIdentity, registrationService, identities: [{ reference, state: 'published' }] })),
    setDefault: vi.fn(async (input, check) => { check(); return { schema: 1 as const, version: input.expectedVersion + 1, identity: input.identity } }),
    setRegistration: vi.fn(async (input, check) => { check(); registrationService = { origin: input.origin, version: input.expectedVersion + 1 }; return registrationService }),
  }
  const approval = vi.fn<(input: object) => Promise<string>>(async () => outcome)
  ctx.provide('tools', { register(definition: any) { tools.set(definition.name, definition) } })
  ctx.provide('agents', { get(id: string) { return id === agent.id ? agent : undefined } })
  ctx.provide('approval', { request: approval })
  registerConfigurationTools(ctx, handlers)
  await new Promise(resolve => setTimeout(resolve, 0))
  const signal = new AbortController()
  const execution = { agent, callId: 'call-1', signal: signal.signal }
  const call = (name: string, args: unknown, exec: any = execution) => tools.get(name).execute(args, exec)
  const input = () => { const { schema: _schema, version: _version, ...rules } = structuredClone(policy); rules.write.mode = 'allow_all'; return { action: 'set', expectedVersion: policy.version, policy: rules } }
  return { ctx, tools, agent, handlers, call, input, approval, execution, signal,
    reject: (value: string) => { outcome = value }, revoke: () => { owner = false },
    externalChange: () => { policy.version++ } }
}
it('queries both shared settings without a side effect or confirmation and rejects forged caller arguments', async () => {
  const f = await fixture()
  expect([...f.tools.keys()]).toEqual(['protocol_permissions', 'identity_settings'])
  expect(await f.call('protocol_permissions', { action: 'get' })).toMatchObject({ ok: true, value: { policy: { version: 0 } } })
  expect(await f.call('identity_settings', { action: 'get' })).toMatchObject({ ok: true, value: { defaultIdentity: { version: 0 }, registrationService: { origin: 'https://awiki.me' } } })
  expect(f.approval).not.toHaveBeenCalled()
  for (const args of [{ action: 'get', consumer: 'owner' }, { action: 'get', identity: null }, { action: 'set', expectedVersion: 0 }])
    expect(await f.call('protocol_permissions', args)).toMatchObject({ ok: false, error: { code: 'invalid_parameters' } })
  expect(await f.call('identity_settings', { action: 'set_registration_service', expectedVersion: 0, origin: 'https://service.example', otp: '123456' })).toMatchObject({ ok: false, error: { code: 'invalid_parameters' } })
})
it('confirms the exact persistent diff once, then writes through the shared backend with a rechecked caller', async () => {
  const f = await fixture(), input = f.input()
  const result = await f.call('protocol_permissions', input)
  expect(result).toMatchObject({ ok: true, value: { applied: true, confirmation: { status: 'approved', scope: 'configuration_change', presentation: 'in_session' }, before: { version: 0, write: { mode: 'ask' } }, after: { version: 1, write: { mode: 'allow_all' } } } })
  expect(f.approval).toHaveBeenCalledOnce()
  expect(f.approval.mock.calls[0]![0]).toMatchObject({ agent: f.agent, callId: 'call-1', toolName: 'protocol_permissions' })
  expect(JSON.stringify(f.approval.mock.calls[0])).toContain('allow_all')
  expect(await f.call('protocol_permissions', { action: 'get' })).toMatchObject({ value: { policy: { version: 1, write: { mode: 'allow_all' } } } })
  expect(await f.call('protocol_permissions', input)).toMatchObject({ ok: false, error: { code: 'protocol_policy_conflict' } })
  expect(f.approval).toHaveBeenCalledOnce()
})
it.each(['unavailable', 'rejected', 'cancelled'])('fails closed when owner approval is %s', async outcome => {
  const f = await fixture(); f.reject(outcome)
  expect(await f.call('protocol_permissions', f.input())).toMatchObject({ ok: false })
  expect(f.handlers.setProtocols).not.toHaveBeenCalled()
})
it('rejects fake agents, delegated writes, absent signals, cancelled calls and disposed owner registration', async () => {
  const f = await fixture()
  expect(await f.call('protocol_permissions', f.input(), { ...f.execution, agent: { ...f.agent } })).toMatchObject({ error: { code: 'configuration_caller_forbidden' } })
  expect(await f.call('protocol_permissions', f.input(), { agent: f.agent })).toMatchObject({ error: { code: 'configuration_cancelled' } })
  Object.assign(f.agent.session.header, { origin: 'subagent' })
  expect(await f.call('protocol_permissions', f.input())).toMatchObject({ error: { code: 'configuration_caller_forbidden' } })
  expect(await f.call('protocol_permissions', { action: 'get' })).toMatchObject({ ok: true })
  f.revoke()
  expect(await f.call('identity_settings', { action: 'get' })).toMatchObject({ error: { code: 'consumer_forbidden' } })
  expect(f.approval).not.toHaveBeenCalled()
})
it('does not transfer a confirmation to a concurrently changed policy or revoked owner', async () => {
  const f = await fixture()
  f.approval.mockImplementationOnce(async () => { f.externalChange(); return 'allowed-once' })
  expect(await f.call('protocol_permissions', f.input())).toMatchObject({ error: { code: 'protocol_policy_conflict' } })
  f.approval.mockImplementationOnce(async () => { f.revoke(); return 'allowed-once' })
  expect(await f.call('protocol_permissions', f.input())).toMatchObject({ error: { code: 'consumer_forbidden' } })
})
it('changes only the requested identity preference and never accepts lifecycle or secret fields', async () => {
  const f = await fixture()
  expect(await f.call('identity_settings', { action: 'set_default', expectedVersion: 0, identity: null })).toMatchObject({ ok: true, value: { after: { identity: null, version: 1 } } })
  expect(f.handlers.setRegistration).not.toHaveBeenCalled()
  expect(await f.call('identity_settings', { action: 'set_registration_service', expectedVersion: 0, origin: 'https://Service.Example/' })).toMatchObject({ ok: true, value: { after: { origin: 'https://service.example', version: 1 } } })
  expect(await f.call('identity_settings', { action: 'set_registration_service', expectedVersion: 1, origin: 'https://name:secret@service.example/' })).toMatchObject({ error: { code: 'registration_service_invalid_origin' } })
  expect(await f.call('identity_settings', { action: 'set_default', expectedVersion: 0, identity: null, approve: true })).toMatchObject({ error: { code: 'invalid_parameters' } })
  expect(await f.call('identity_settings', { action: 'sign', key: 'private' })).toMatchObject({ error: { code: 'invalid_parameters' } })
  expect(f.approval).toHaveBeenCalledTimes(2)
})
it('cancels before committing if the tool lifetime ends while the owner is answering', async () => {
  const f = await fixture()
  f.approval.mockImplementationOnce(async () => { f.signal.abort(); return 'allowed-once' })
  expect(await f.call('protocol_permissions', f.input())).toMatchObject({ error: { code: 'configuration_cancelled' } })
  expect(f.handlers.setProtocols).not.toHaveBeenCalled()
})
it('keeps captured definitions unavailable after their owner registration is disposed', async () => {
  const f = await fixture()
  const definition = f.tools.get('protocol_permissions')
  await f.ctx.fiber.dispose()
  expect(await definition.execute(f.input(), f.execution)).toMatchObject({ ok: false, error: { code: 'configuration_caller_forbidden' } })
  expect(f.approval).not.toHaveBeenCalled()
  expect(f.handlers.setProtocols).not.toHaveBeenCalled()
})

it('resolves only a returned published identity id and never accepts a model-reconstructed DID', async () => {
  const f = await fixture()
  expect(await f.call('identity_settings', { action: 'set_default', expectedVersion: 0, identityId: 'short-identity' })).toMatchObject({ ok: true, value: { after: { identity: { identityId: 'short-identity', did: 'did:wba:identity.example:long-published-did' } } } })
  expect(await f.call('identity_settings', { action: 'set_default', expectedVersion: 0, identityId: 'not-published' })).toMatchObject({ ok: false, error: { code: 'published_identity_required' } })
  expect(await f.call('identity_settings', { action: 'set_default', expectedVersion: 0, identity: { storeId: 'store', identityId: 'short-identity', did: 'copied-wrong-did' } })).toMatchObject({ ok: false, error: { code: 'invalid_parameters' } })
  expect(await f.call('identity_settings', { action: 'set_default', expectedVersion: 0, identity: null, identityId: 'short-identity' })).toMatchObject({ ok: false, error: { code: 'invalid_parameters' } })
  expect(f.approval).toHaveBeenCalledOnce()
})
