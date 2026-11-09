/** Actual Harness registry/executor/approval audit plus native owner storage; no live UI/service claim. */
import { pathToFileURL } from 'node:url'
import { join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { expect, it } from 'vitest'
import type AnpIdentityService from '../src/index.js'
import { registerConfigurationTools } from '../src/configuration-tools.js'
import { createNativeProtocolFixture } from './helpers/native-protocol-fixture.js'

const source = process.env.DSH_SHARED_HARNESS_SOURCE
interface Agent { id: string; session: { append(type: string, value: object): void; snapshotEvents(): { type: string; data: any }[] } }
it.skipIf(!source)('actual DSH tools mutate the native owner backend only after a real approval audit and disappear on unload', async () => {
  const from = (path: string) => import(/* @vite-ignore */ pathToFileURL(join(source!, path)).href)
  const kit = await from('packages/test-support/agent-loop-testkit/src/index.ts') as {
    mountAgentLoopTestDependencies(ctx: Context): Promise<void>
    mountAgentLoopTestHarness(ctx: Context): Promise<{ create(id: string): Promise<Agent> }>
  }
  const { executeToolFixture } = await from('packages/test-support/tool-testkit/src/index.ts') as {
    executeToolFixture(ctx: Context, input: object): Promise<{ isError: boolean; value?: any }>
  }
  const approvalModule = await from('packages/interaction/user-approval/src/index.ts')
  const f = await createNativeProtocolFixture({ consumer: '@awiki/dsh-pap/plugin',
    domainAccess: { enabled: true, scopes: ['protocol.read'], secretStore: 'local-file' } })
  try {
    const ctx = f.rootContext
    const service = f.managerContext.anpIdentity as AnpIdentityService
    await kit.mountAgentLoopTestDependencies(ctx)
    await ctx.plugin(approvalModule.default, { policy: 'ask' })
    const driver = await kit.mountAgentLoopTestHarness(ctx)
    const agent = await driver.create('native-configuration-agent')
    agent.session.append('turn/start', { turn: 1 })
    registerConfigurationTools(f.managerContext, {
      assertOwner: () => { service.acquireManagement(f.managerContext) },
      protocols: () => service.protocolManagement(f.managerContext),
      setProtocols: (input, check) => service.configureProtocolPolicy(f.managerContext, input, check),
      identity: async () => ({ defaultIdentity: await service.defaultIdentity(f.managerContext), registrationService: await service.registrationServiceSettings(f.managerContext), identities: [{ reference: f.reference, state: 'published' }] }),
      setDefault: (input, check) => service.configureDefaultIdentity(f.managerContext, input, check),
      setRegistration: (input, check) => service.configureRegistrationService(f.managerContext, input, check),
    })
    await new Promise(resolve => setTimeout(resolve, 0))
    let serial = 0
    const call = (name: string, args: object) => executeToolFixture(ctx, { agent, name, arguments: args, callId: 'settings-' + serial++, signal: new AbortController().signal })
    const before = await call('protocol_permissions', { action: 'get' })
    expect(before.isError).toBe(false)
    expect(before.value).toMatchObject({ ok: true, value: { policy: { version: 0 } } })
    const { schema: _schema, version: _version, ...policy } = structuredClone(before.value.value.policy)
    policy.write.mode = 'allow_all'
    const unavailable = await call('protocol_permissions', { action: 'set', expectedVersion: 0, policy })
    expect(unavailable.value).toMatchObject({ ok: false, error: { code: 'configuration_approval_required' } })
    expect((await service.protocolManagement(f.managerContext)).policy.version).toBe(0)
    const removeAnswerer = ctx.on('approval/request' as any, async () => 'allowed-once')
    expect((await call('protocol_permissions', { action: 'set', expectedVersion: 0, policy })).value).toMatchObject({ ok: true, value: { after: { version: 1, write: { mode: 'allow_all' } } } })
    expect((await call('identity_settings', { action: 'set_default', expectedVersion: 0, identityId: f.reference.identityId })).value).toMatchObject({ ok: true, value: { after: { version: 1, identity: f.reference } } })
    expect((await call('identity_settings', { action: 'set_registration_service', expectedVersion: 0, origin: 'https://future.example' })).value).toMatchObject({ ok: true, value: { after: { version: 1, origin: 'https://future.example' } } })
    expect((await call('identity_settings', { action: 'get' })).value).toMatchObject({ ok: true, value: { defaultIdentity: { version: 1 }, registrationService: { origin: 'https://future.example' } } })
    removeAnswerer()
    const audit = agent.session.snapshotEvents().filter(event => event.type.startsWith('approval/'))
    expect(audit.filter(event => event.type === 'approval/asked')).toHaveLength(4)
    expect(audit.filter(event => event.type === 'approval/decided').map(event => event.data.outcome)).toEqual(['unavailable', 'allowed-once', 'allowed-once', 'allowed-once'])
    expect(audit.find(event => event.type === 'approval/asked')?.data.reason).toContain('"write":{"mode":"allow_all"')
    expect(JSON.stringify(audit)).not.toMatch(/privateKey|access_token|client_assertion|otp/u)
    await f.managerContext.fiber.dispose()
    expect((await call('identity_settings', { action: 'get' })).isError).toBe(true)
  } finally { await f.dispose() }
}, 30000)
