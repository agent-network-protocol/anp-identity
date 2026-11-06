/** Authority units; production native/device callback evidence is owned by the actual Loader and B component lanes. */
import { Context } from '@deepseek-ai/cordis'
import { afterEach, expect, it, vi } from 'vitest'
import type { IdentityReference } from '@agent-network-protocol/anp-identity'
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import { ProtocolIdentityAuthority } from '../src/target-policy.js'
import type { PublicationCoordinator } from '../src/publication.js'
import type { PublicationRecord } from '../src/publication-types.js'
import type { ProtocolUsePolicy, ValidatedTargetEvidence } from '../src/protocol-client.js'
import type { PapCallbackClaimOperation, PapCallbackClaimResult, PapCallbackRegisterOperation, PapCallbackRegistrationResult } from '../src/pap-callback.js'

afterEach(() => vi.restoreAllMocks())
const reference: IdentityReference = { storeId: 'store', identityId: 'identity', did: 'did:web:identity.example' }
const consumer = '@agentconnect/dsh-pap/plugin'
const clientId = 'https://identity.example/user-service/v1/agent-clients/document/client.json'
const redirect = 'https://identity.example/user-service/v1/pap-callback'
const issuer = 'https://company.example'
const resource = 'https://company.example/api'

function fixture(account = true) {
  const context = new Context(), other = new Context()
  let generation = Symbol('provider'), managerActive = true
  const policy: ProtocolUsePolicy = { id: 'pap-policy', version: 1, consumer, owner: '@agent-network-protocol/dsh-anp-identity',
    identity: reference, profiles: ['pap_session', 'pap_account'], issuers: [issuer, 'https://other.example'],
    resources: [resource, 'https://other.example/api'], publicTargets: false, scopes: ['read', 'write'], expiresAt: Date.now() + 3600000 }
  const record: PublicationRecord = { operationId: 'publication', expectedVersion: 0, state: 'published', clientId, version: 1,
    config: { backend: 'actual-manager-backend', documentId: 'document', clientName: 'Identity', redirectUris: account ? [redirect] : [],
      capabilities: { mcpMachine: false, papSession: true, papAccount: account } },
    key: { kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'B'.repeat(43), kid: reference.did + '#oauth', alg: 'ES256', use: 'sig' },
    metadata: '{}', jwks: '{}', metadataSha256: 'a'.repeat(64) }
  const publications = { requirePublished: vi.fn(async () => record) } as unknown as PublicationCoordinator
  const native = { info: vi.fn(async () => ({ storeId: reference.storeId, schemaCompatible: true, identityCount: 1,
    health: 'ready', backendAvailable: true })), publicIdentity: vi.fn(async () => ({ reference, document: { id: reference.did } })) } as unknown as ProviderLease
  const host = { resolveCaller: (caller: Context) => {
    if (caller !== context && caller !== other) throw new Error('consumer_forbidden')
    return { consumer, displayName: consumer }
  }, assertCaller: () => {}, providerGeneration: () => generation, withNative: async <T>(operation: (provider: ProviderLease) => Promise<T>) => operation(native) }
  const authority = new ProtocolIdentityAuthority([policy], host, publications)
  const receipts = new Map<string, Record<string, unknown>>()
  const effects = vi.fn()
  let claimResponse: () => Promise<PapCallbackClaimResult> = async () => ({ code: 'private-business-code', state: 's'.repeat(32), iss: issuer })
  function execute(input: PapCallbackRegisterOperation): Promise<PapCallbackRegistrationResult>
  function execute(input: PapCallbackClaimOperation): Promise<PapCallbackClaimResult>
  async function execute(input: PapCallbackRegisterOperation | PapCallbackClaimOperation): Promise<PapCallbackRegistrationResult | PapCallbackClaimResult> {
    effects(input.action)
    return input.action === 'pap-callback-register'
      ? { transaction_id: input.callback.transaction_id, callback_uri: redirect, expires_at: input.callback.expires_at }
      : claimResponse()
  }
  const callbackAuthority = vi.fn(async () => ({
    assertActive: async () => { if (!managerActive) throw new Error('provider_disposed') }, operations: { execute },
    reserve: async (id: string, binding: Record<string, unknown>) => {
      if (!receipts.has(id)) receipts.set(id, structuredClone(binding))
      return structuredClone(receipts.get(id)!)
    }, read: async (id: string) => receipts.get(id),
  }))
  const top = authority.bindPapHost(context, callbackAuthority)
  const target = async (caller = context, selectedIssuer = issuer, selectedResource = resource, scopes = ['read', 'write']) => {
    const discovery: ValidatedTargetEvidence = { profile: 'pap_account', issuer: selectedIssuer, resource: selectedResource,
      tokenEndpoint: selectedIssuer + '/token', companyId: selectedIssuer, metadataDigest: 'a'.repeat(64), expiresAt: Date.now() + 300000,
      sources: { resource: selectedIssuer + '/.well-known/company', authorizationServer: selectedIssuer + '/.well-known/oauth-authorization-server' } }
    return authority.bind(caller).registerValidatedTarget({ identityRef: reference, policyRef: policy.id, discovery, requestedScopes: scopes })
  }
  const register: PapCallbackRegisterOperation = { action: 'pap-callback-register', operationId: 'register_transaction', callback: {
    transaction_id: 'transaction', client_id: clientId, issuer, redirect_uri: redirect, state_sha256: 'a'.repeat(64), claim_sha256: 'b'.repeat(64),
    expires_at: new Date(Date.now() + 300000).toISOString().replace('.000Z', 'Z').replace(/\.\d{3}Z$/u, 'Z'),
  } }
  const claim: PapCallbackClaimOperation = { action: 'pap-callback-claim', operationId: 'claim_transaction', callback: { transaction_id: 'transaction', claim_secret: Buffer.alloc(32, 1).toString('base64url') } }
  return { context, other, policy, record, authority, top, target, callbackAuthority, effects, receipts, register, claim,
    stopManager: () => { managerActive = false }, rotateProvider: () => { generation = Symbol('replacement') },
    holdClaim: (reply: () => Promise<PapCallbackClaimResult>) => { claimResponse = reply } }
}

it('resolves a published no-AS Session identity without requiring an account callback or a device driver', async () => {
  const f = fixture(false)
  expect(await f.top.resolveBinding(reference, f.policy.id, 'pap_session')).toEqual({ binding: { identityRef: reference, ownerRef: f.policy.owner, clientId } })
  expect(f.callbackAuthority).not.toHaveBeenCalled()
  await expect(f.top.resolveBinding(reference, f.policy.id, 'pap_account')).rejects.toMatchObject({ code: 'provider_incompatible' })
  await expect(f.top.resolveBinding(reference, 'unconfigured', 'pap_session')).rejects.toMatchObject({ code: 'capability_forbidden' })
})

it('requires an opaque account target from the same installed caller before registering or claiming', async () => {
  const f = fixture()
  expect(await f.top.resolveBinding(reference, f.policy.id, 'pap_account')).toEqual({ binding: { identityRef: reference, ownerRef: f.policy.owner, clientId }, redirectUri: redirect })
  await expect(f.top.callbackManagementFor({ identityRef: reference, policyRef: f.policy.id, targetRef: {} })).rejects.toMatchObject({ code: 'capability_forbidden' })
  const otherTarget = await f.target(f.other)
  await expect(f.top.callbackManagementFor({ identityRef: reference, policyRef: f.policy.id, targetRef: otherTarget.targetRef })).rejects.toMatchObject({ code: 'capability_forbidden' })
  expect(f.effects).not.toHaveBeenCalled()
  const lease = await f.target()
  const driver = await f.top.callbackManagementFor({ identityRef: reference, policyRef: f.policy.id, targetRef: lease.targetRef })
  await expect(driver.execute({ ...f.register, callback: { ...f.register.callback, issuer: 'https://other.example' } })).rejects.toMatchObject({ code: 'capability_forbidden' })
  expect(f.effects).not.toHaveBeenCalled()
  await driver.execute(f.register)
  expect(await driver.execute(f.claim)).toEqual({ code: 'private-business-code', state: 's'.repeat(32), iss: issuer })
  driver.dispose()
  await expect(driver.execute(f.claim)).rejects.toMatchObject({ code: 'provider_disposed' })
  expect(f.effects).toHaveBeenCalledTimes(2)
})

it('keeps a registered transaction bound to its Company, resource and scope when new targets are acquired', async () => {
  const f = fixture(); const lease = await f.target()
  const driver = await f.top.callbackManagementFor({ identityRef: reference, policyRef: f.policy.id, targetRef: lease.targetRef })
  await driver.execute(f.register)
  for (const args of [
    [issuer, resource, ['read']],
    ['https://other.example', 'https://other.example/api', ['read', 'write']],
  ] as const) {
    const changed = await f.target(f.context, args[0], args[1], [...args[2]])
    const changedDriver = await f.top.callbackManagementFor({ identityRef: reference, policyRef: f.policy.id, targetRef: changed.targetRef })
    await expect(changedDriver.execute(f.claim)).rejects.toMatchObject({ code: 'capability_forbidden' })
  }
  expect(f.effects).toHaveBeenCalledTimes(1)
  expect(JSON.stringify([...f.receipts.values()])).not.toContain('private-business-code')
})

it('does not return an in-flight private claim after publication rotation and rejects a disposed manager', async () => {
  const f = fixture(); const lease = await f.target()
  const driver = await f.top.callbackManagementFor({ identityRef: reference, policyRef: f.policy.id, targetRef: lease.targetRef })
  await driver.execute(f.register)
  let release!: (reply: PapCallbackClaimResult) => void
  f.holdClaim(() => new Promise(resolve => { release = resolve }))
  const pending = driver.execute(f.claim)
  const rejected = expect(pending).rejects.toMatchObject({ code: 'capability_forbidden' })
  await vi.waitFor(() => expect(f.effects).toHaveBeenCalledTimes(2))
  f.record.version += 1
  release({ code: 'must-not-return', state: 's'.repeat(32), iss: issuer })
  await rejected
  const current = await f.target()
  const currentDriver = await f.top.callbackManagementFor({ identityRef: reference, policyRef: f.policy.id, targetRef: current.targetRef })
  f.stopManager()
  await expect(currentDriver.execute(f.claim)).rejects.toThrow('provider_disposed')
  expect(f.effects).toHaveBeenCalledTimes(2)
  f.rotateProvider()
  await expect(f.top.assertActive()).rejects.toMatchObject({ code: 'provider_disposed' })
})
