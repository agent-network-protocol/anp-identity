import { describe, expect, it, vi } from 'vitest'
import type { Context } from '@deepseek-ai/cordis'
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import { Config } from '../src/index.js'
import { ProtocolIdentityAuthority } from '../src/target-policy.js'
import type { ProtocolUsePolicy, ValidatedTargetEvidence } from '../src/protocol-client.js'
import type { PublicationCoordinator } from '../src/publication.js'

const identity = { storeId: 'store', identityId: 'identity', did: 'did:web:identity.example' }
const consumer = '@deepseek-ai/dsh-mcp-client'
const publicJwk = { kty: 'EC', crv: 'P-256', x: 'a'.repeat(43), y: 'b'.repeat(43), kid: identity.did + '#oauth', alg: 'ES256', use: 'sig' }
const evidence: ValidatedTargetEvidence = { profile: 'mcp_machine', issuer: 'https://issuer.example', resource: 'https://resource.example/mcp', tokenEndpoint: 'https://issuer.example/token', metadataDigest: 'a'.repeat(64), expiresAt: Date.now() + 60000, sources: { resource: 'https://resource.example/.well-known/oauth-protected-resource/mcp', authorizationServer: 'https://issuer.example/.well-known/oauth-authorization-server' } }
function fixture(profile: ValidatedTargetEvidence['profile'] = 'mcp_machine', publicTargets = false, scopes = ['agent.self.read']) {
  const context = {} as Context
  const policy: ProtocolUsePolicy = { id: 'approved-policy', version: 3, consumer, owner: '@agent-network-protocol/dsh-anp-identity', identity,
    profiles: [profile], issuers: [evidence.issuer], resources: [evidence.resource], publicTargets, scopes, expiresAt: Date.now() + 60000 }
  let active = true
  let generation = Symbol('provider')
  let backendAvailable = true
  const sign = vi.fn(async () => 'signed-assertion')
  const info = vi.fn(async () => ({ storeId: identity.storeId, schemaCompatible: true, identityCount: 1,
    health: 'ready' as const, backendAvailable }))
  const native = { info, signOAuthClientAssertion: sign } as unknown as ProviderLease
  const host = { resolveCaller: (ctx: Context) => { if (ctx !== context || !active) throw new Error('consumer_forbidden'); return { consumer, displayName: consumer } },
    assertCaller: () => { if (!active) throw new Error('consumer_forbidden') }, providerGeneration: () => generation,
    withNative: async <T>(operation: (native: ProviderLease) => Promise<T>) => operation(native) }
  const publications = { requirePublished: async () => ({ clientId: 'https://identity.example/client.json', version: 4, key: publicJwk, config: { capabilities: { mcpMachine: true, papSession: true, papAccount: true }, redirectUris: [] } }) } as unknown as PublicationCoordinator
  const authority = new ProtocolIdentityAuthority([policy], host, publications)
  const client = authority.bind(context)
  return { client, context, authority, policy, sign, info, native, setAvailable: (value: boolean) => { backendAvailable = value },
    deactivate: () => { active = false }, reload: () => { generation = Symbol('reload') } }
}

describe('protocol target policies', () => {
  it('permits an empty scope ceiling only for PAP Session and never widens its requested scopes', async () => {
    const f = fixture('pap_session', false, [])
    const discovery = { ...evidence, profile: 'pap_session' as const, companyId: 'https://company.example' }
    const lease = await f.client.registerValidatedTarget({ identityRef: identity, policyRef: f.policy.id, discovery, requestedScopes: [] })
    await lease.assertActive()
    await expect(f.client.registerValidatedTarget({ identityRef: identity, policyRef: f.policy.id, discovery, requestedScopes: ['admin'] })).rejects.toThrow()
    expect(() => fixture('mcp_machine', false, [])).toThrow()
    expect(() => fixture('pap_account', false, [])).toThrow()
    lease.dispose()
  })
  it('binds exact Context, identity, target, scope and generation without implicit grants', async () => {
    const f = fixture()
    expect(() => f.authority.bind({} as Context)).toThrow()
    const lease = await f.client.registerValidatedTarget({ identityRef: identity, policyRef: f.policy.id, discovery: evidence, requestedScopes: ['agent.self.read'] })
    expect(await lease.getOAuthClientIdentity()).toMatchObject({ algorithm: 'ES256', signerMode: 'local', clientId: 'https://identity.example/client.json' })
    await expect(lease.signOAuthClientAssertion({})).rejects.toThrow()
    await lease.signOAuthClientAssertion(lease.targetRef)
    expect(f.sign).toHaveBeenCalledWith(identity, { client_id: 'https://identity.example/client.json', audience: evidence.issuer, key: { kid: publicJwk.kid } })
    for (const changed of [{ identityRef: { ...identity, did: 'did:web:other.example' } }, { requestedScopes: ['admin'] }, { discovery: { ...evidence, resource: 'https://resource.example/other' } }]) {
      await expect(f.client.registerValidatedTarget({ identityRef: identity, policyRef: f.policy.id, discovery: evidence, requestedScopes: ['agent.self.read'], ...changed })).rejects.toThrow()
    }
    f.reload()
    await expect(lease.signOAuthClientAssertion(lease.targetRef)).rejects.toThrow()
  })
  it('does not return an assertion after revocation during signing', async () => {
    const f = fixture()
    const lease = await f.client.registerValidatedTarget({ identityRef: identity, policyRef: f.policy.id, discovery: evidence, requestedScopes: ['agent.self.read'] })
    f.sign.mockImplementation(async () => { f.deactivate(); return 'must-not-escape' })
    await expect(lease.signOAuthClientAssertion(lease.targetRef)).rejects.toThrow()
  })
  it('checks current native backend availability for an old lease and permits recovery without changing its grant', async () => {
    const f = fixture()
    const lease = await f.client.registerValidatedTarget({ identityRef: identity, policyRef: f.policy.id, discovery: evidence, requestedScopes: ['agent.self.read'] })
    await lease.getOAuthClientIdentity()
    f.setAvailable(false)
    await expect(lease.assertActive()).rejects.toMatchObject({ code: 'provider_unavailable' })
    await expect(lease.signOAuthClientAssertion(lease.targetRef)).rejects.toMatchObject({ code: 'provider_unavailable' })
    expect(f.sign).not.toHaveBeenCalled()
    f.setAvailable(true)
    await lease.assertActive()
    await expect(lease.signOAuthClientAssertion(lease.targetRef)).resolves.toBe('signed-assertion')
  })
  it('withholds an assertion when the backend becomes unavailable during signing', async () => {
    const f = fixture()
    const lease = await f.client.registerValidatedTarget({ identityRef: identity, policyRef: f.policy.id, discovery: evidence, requestedScopes: ['agent.self.read'] })
    f.sign.mockImplementation(async () => { f.setAvailable(false); return 'must-not-escape' })
    await expect(lease.signOAuthClientAssertion(lease.targetRef)).rejects.toMatchObject({ code: 'provider_unavailable' })
  })
  it.each(['caller', 'provider', 'expiry'] as const)('rechecks %s authorization after the native info await', async changed => {
    const f = fixture()
    const lease = await f.client.registerValidatedTarget({ identityRef: identity, policyRef: f.policy.id, discovery: evidence, requestedScopes: ['agent.self.read'] })
    f.info.mockImplementationOnce(async () => {
      if (changed === 'caller') f.deactivate()
      else if (changed === 'provider') f.reload()
      else vi.spyOn(Date, 'now').mockReturnValue(f.policy.expiresAt + 1)
      return { storeId: identity.storeId, schemaCompatible: true, identityCount: 1, health: 'ready', backendAvailable: true }
    })
    try { await expect(lease.assertActive()).rejects.toThrow() }
    finally { vi.restoreAllMocks() }
    expect(f.sign).not.toHaveBeenCalled()
  })
  it('rejects a provider without the native backend availability handshake', async () => {
    const f = fixture()
    const lease = await f.client.registerValidatedTarget({ identityRef: identity, policyRef: f.policy.id, discovery: evidence, requestedScopes: ['agent.self.read'] })
    const unsupported = await f.info()
    Reflect.deleteProperty(unsupported, 'backendAvailable')
    f.info.mockResolvedValueOnce(unsupported)
    await expect(lease.assertActive()).rejects.toMatchObject({ code: 'provider_incompatible' })
    expect(f.sign).not.toHaveBeenCalled()
  })
  it('accepts bounded unfamiliar public targets only through explicit preauthorization', async () => {
    const f = fixture('mcp_machine', true)
    const authority = f.authority
    const client = authority.bind(f.context)
    await expect(client.registerValidatedTarget({ identityRef: identity, policyRef: f.policy.id,
      discovery: { ...evidence, issuer: 'https://unfamiliar.example', resource: 'https://different.example/mcp' }, requestedScopes: ['agent.self.read'] })).resolves.toHaveProperty('targetRef')
    await expect(client.registerValidatedTarget({ identityRef: identity, policyRef: f.policy.id,
      discovery: { ...evidence, expiresAt: Date.now() - 1 }, requestedScopes: ['agent.self.read'] })).rejects.toThrow()
  })
  it('rejects forged PAP scope/key references and cross-purpose key use through executors', async () => {
    const f = fixture('pap_account')
    const lease = await f.client.registerValidatedTarget({ identityRef: identity, policyRef: f.policy.id,
      discovery: { ...evidence, profile: 'pap_account', companyId: 'https://company.example' }, requestedScopes: ['agent.self.read'] })
    const scope = lease.bindPapScope({ userId: 'user', accountSlot: 'account' })
    await expect(lease.createDelegatedKey({}, 'op')).rejects.toThrow()
    await expect(lease.issuePapDelegation(scope, { keyRef: {}, ttlSeconds: 60 })).rejects.toThrow()
    await expect(lease.signDpopProof(scope, { keyRef: {}, httpMethod: 'GET', httpUri: evidence.resource })).rejects.toThrow()
    lease.dispose()
    await expect(lease.getOAuthClientIdentity()).rejects.toThrow()
  })
})

it('rejects an explicitly configured remote signer', () => { expect(() => Config({ signerMode: 'remote' } as never)).toThrow() })
