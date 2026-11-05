import { createPublicKey, verify } from 'node:crypto'
import { expect, it } from 'vitest'
import { createNativeProtocolFixture } from './helpers/native-protocol-fixture.js'

it('routes C leases to real local A custody and restores purpose/scope-bound handles', async () => {
  const f = await createNativeProtocolFixture()
  let stage = 'register'
  try {
    const lease = await f.client.registerValidatedTarget({ identityRef: f.reference, policyRef: f.policyRef, requestedScopes: ['pap.read'], discovery: {
      profile: 'pap_account', companyId: 'https://company.example', issuer: 'https://company.example', resource: 'https://company.example/api', tokenEndpoint: 'https://company.example/token',
      metadataDigest: 'a'.repeat(64), expiresAt: Date.now() + 60000, sources: { resource: 'https://company.example/.well-known/pap', authorizationServer: 'https://company.example/.well-known/oauth-authorization-server' } } })
    const scope = lease.bindPapScope({ userId: 'user', accountSlot: 'one' })
    const sessionKey = await lease.createDelegatedKey(scope, 'session-key-operation').catch(error => { throw new Error('create_session', { cause: error }) })
    stage = 'dpop'
    const dpopKey = await lease.createDpopKey(scope, 'dpop-key-operation')
    expect(sessionKey.purpose).toBe('pap_session'); expect(dpopKey.purpose).toBe('pap_dpop')
    stage = 'delegation'
    const delegation = await lease.issuePapDelegation(scope, { keyRef: sessionKey.keyRef, ttlSeconds: 60 })
    stage = 'identity'
    const identity = await lease.getOAuthClientIdentity()
    const [header, payload, signature] = delegation.split('.') as [string, string, string]
    expect(verify('sha256', Buffer.from(header + '.' + payload), { key: createPublicKey({ key: identity.publicJwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url'))).toBe(true)
    stage = 'signDpop'
    const dpop = await lease.signDpopProof(scope, { keyRef: dpopKey.keyRef, httpMethod: 'GET', httpUri: 'https://company.example/api' })
    expect(dpop.split('.')).toHaveLength(3)
    await expect(lease.signDpopProof(scope, { keyRef: sessionKey.keyRef, httpMethod: 'GET', httpUri: 'https://company.example/api' })).rejects.toThrow()
    stage = 'restore'
    const restored = await lease.restorePapKey(scope, { handle: dpopKey.handle, purpose: 'pap_dpop', generation: dpopKey.generation })
    expect(restored.thumbprint).toBe(dpopKey.thumbprint)
    await expect(lease.signDpopProof(scope, { keyRef: restored.keyRef, httpMethod: 'GET', httpUri: 'https://company.example/other' })).rejects.toThrow()
    stage = 'retire'
    await lease.retireTemporaryKey(scope, restored.keyRef)
    await expect(lease.restorePapKey(scope, { handle: dpopKey.handle, purpose: 'pap_dpop', generation: dpopKey.generation })).rejects.toThrow()
    lease.dispose()
    await expect(lease.getOAuthClientIdentity()).rejects.toThrow()
  } catch (error) { throw new Error(stage, { cause: error }) } finally { await f.dispose() }
})
