/** Native Host ownership and domain binding evidence, not public service or browser evidence. */
import { expect, it } from 'vitest'
import type AnpIdentityService from '../src/index.js'
import { createNativeProtocolFixture } from './helpers/native-protocol-fixture.js'

it('only the installed owner sets a published default and every fresh adapter binding observes its version', async () => {
  const f = await createNativeProtocolFixture({ consumer: '@awiki/dsh-pap/plugin',
    additionalConsumers: [{ consumer: '@deepseek-ai/dsh-mcp-client/domain' }, { consumer: '@agent-network-protocol/dsh-anp/plugin' }],
    domainAccess: { enabled: true, scopes: ['protocol.read'], secretStore: 'local-file' } })
  try {
    const service = f.managerContext.anpIdentity as AnpIdentityService
    await expect(f.service.defaultIdentity(f.context)).rejects.toMatchObject({ code: 'consumer_forbidden' })
    await expect(f.service.configureDefaultIdentity(f.context, { expectedVersion: 0, identity: f.reference })).rejects.toMatchObject({ code: 'consumer_forbidden' })
    const before = await f.service.resolveDomainAccess(f.context, 'pap_session')
    const papHost = f.service.bindPapHostConsumer(f.context)
    await papHost.resolveBinding(f.reference, before.policyRef, 'pap_session')
    const retained = await f.service.bindProtocolConsumer(f.context).registerValidatedTarget({ identityRef: f.reference,
      policyRef: before.policyRef, requestedScopes: [], discovery: { profile: 'pap_session', companyId: 'https://company.example',
        issuer: 'https://company.example', resource: 'https://company.example/api', tokenEndpoint: 'https://company.example/token',
        metadataDigest: 'a'.repeat(64), expiresAt: Date.now() + 60000, sources: {
          resource: 'https://company.example/.well-known/pap', authorizationServer: 'https://company.example/.well-known/oauth-authorization-server' } } })
    await retained.assertActive()
    expect(await service.defaultIdentity(f.managerContext)).toMatchObject({ version: 0, identity: null })
    expect(await service.configureDefaultIdentity(f.managerContext, { expectedVersion: 0, identity: f.reference })).toMatchObject({ version: 1, identity: f.reference })
    await expect(retained.getOAuthClientIdentity()).rejects.toMatchObject({ code: 'capability_forbidden' })
    await expect(papHost.assertActive()).rejects.toMatchObject({ code: 'capability_forbidden' })
    const after = await f.service.resolveDomainAccess(f.context, 'pap_session')
    expect(after.identityRef).toEqual(f.reference)
    expect(after.stateRoot).toBe(before.stateRoot)
    expect(after.policyRef).not.toBe(before.policyRef)
    for (const [consumer, profile] of [['@deepseek-ai/dsh-mcp-client/domain', 'mcp_machine'], ['@agent-network-protocol/dsh-anp/plugin', 'anp']] as const) {
      const adapter = f.getConsumer(consumer)
      expect((await f.service.resolveDomainAccess(adapter.context, profile)).identityRef).toEqual(f.reference)
    }
    await expect(service.configureDefaultIdentity(f.managerContext, { expectedVersion: 0, identity: null })).rejects.toThrow('default_identity_conflict')
    await expect(service.configureDefaultIdentity(f.managerContext, { expectedVersion: 1, identity: { ...f.reference, identityId: 'missing' } })).rejects.toThrow()
    expect(await service.defaultIdentity(f.managerContext)).toMatchObject({ version: 1, identity: f.reference })
    const controller = new AbortController(); controller.abort()
    await expect(service.configureDefaultIdentity(f.managerContext, { expectedVersion: 1, identity: null }, () => controller.signal.throwIfAborted())).rejects.toThrow()
    expect(await service.defaultIdentity(f.managerContext)).toMatchObject({ version: 1 })
    await service.configureDefaultIdentity(f.managerContext, { expectedVersion: 1, identity: null })
    expect((await f.service.resolveDomainAccess(f.context, 'pap_session')).policyRef).not.toBe(before.policyRef)
  } finally { await f.dispose() }
}, 30000)
