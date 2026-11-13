import { describe, expect, it } from 'vitest'
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import { createManagedPublicationDriver, type ManagementCredentialBroker } from '../src/management-driver.js'
import { PapCallbackManagementError } from '../src/pap-callback.js'
import { pluginError } from '../src/errors.js'

const reference = { storeId: 'store', identityId: 'identity', did: 'did:web:identity.example:callback' }
const origin = 'https://identity.example'
const clientId = origin + '/cgw/client.json'
const secret = Buffer.alloc(32, 7).toString('base64url')
const registration = () => ({ transaction_id: 'callback-transaction', client_id: clientId, issuer: 'https://company.example',
  redirect_uri: origin + '/user-service/v1/pap-callback', state_sha256: 'a'.repeat(64), claim_sha256: 'b'.repeat(64),
  expires_at: new Date(Date.now() + 300000).toISOString().replace(/\.\d{3}Z$/u, 'Z') })
const payload = { code: 'synthetic-authorization-code', state: 's'.repeat(43), iss: 'https://company.example' }
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } })

async function fixture() {
  const proofs: Array<{ method: string; params: Record<string, unknown> }> = []
  const bindings = new Map<string, Record<string, unknown>>()
  let active = true
  let claimResponse = () => Promise.resolve(json(payload))
  const broker: ManagementCredentialBroker = {
    get: async () => ({ accessToken: 'synthetic-management-token', deviceId: 'device', signingKeyId: reference.did + '#device', audience: 'service' }),
    set: async () => {},
    reserveOperation: async (_ref, _origin, id, body) => {
      if (!bindings.has(id)) bindings.set(id, structuredClone(body))
      return structuredClone(bindings.get(id)!)
    },
  }
  const native = { prepareHttpSignature: async () => ({ headerPatch: [{ name: 'signature-input', value: 'unit-signature-input' }, { name: 'signature', value: 'unit-http-signature' }] }), signManagementProof: async (_ref: unknown, request: { method: string; params: Record<string, unknown> }) => {
    proofs.push(request); return { type: 'awiki-device-signature-v1', signature: 'unit-signature' }
  } } as unknown as ProviderLease
  const driver = await createManagedPublicationDriver({ reference, origin, credentials: broker,
    assertActive: async () => { if (!active) throw pluginError('provider_disposed') },
    withNative: async operation => operation(native),
    fetch: async input => {
      const request = input as Request
      expect(request.headers.has('authorization')).toBe(false)
      expect(request.headers.has('signature-input')).toBe(true)
      expect(request.headers.has('signature')).toBe(true)
      const body = await request.json() as Record<string, unknown>
      if (request.url.endsWith('/did-auth/rpc')) return json({ result: { did: reference.did, checkpoint: { document_version: 1, registry_version: 1, document_hash: 'sha256:' + 'A'.repeat(43) },
        devices: [{ device_id: 'device', signing_key_id: reference.did + '#device', status: 'active', role: 'admin', management_ready: true }] } })
      if (request.url.endsWith('/resolve')) return json({ did: reference.did, document_id: 'one', client_id: clientId, jwks_uri: origin + '/keys/current.json' })
      if (request.url.endsWith('/pap-callback-register')) {
        const callback = body.callback as ReturnType<typeof registration>
        return json({ did: reference.did, document_id: 'one', transaction_id: callback.transaction_id, callback_uri: callback.redirect_uri, expires_at: callback.expires_at })
      }
      if (request.url.endsWith('/pap-callback-claim')) return claimResponse()
      throw new Error('unexpected_fixture_route')
    },
  })
  return { driver, proofs, bindings, deactivate: () => { active = false }, setClaimResponse: (next: () => Promise<Response>) => { claimResponse = next } }
}

describe('restricted PAP callback management', () => {
  it('uses the exact native methods and paths, and accepts a private claim payload without publisher fields', async () => {
    const f = await fixture()
    const callback = registration()
    const registered = await f.driver.execute({ action: 'pap-callback-register', operationId: 'register_callback-transaction', callback })
    expect(registered).toEqual({ transaction_id: callback.transaction_id, callback_uri: callback.redirect_uri, expires_at: callback.expires_at })
    expect(f.proofs.at(-1)).toMatchObject({ method: 'agent_client_pap_callback_register', params: { http_path: '/user-service/v1/agent-clients/device/pap-callback-register', target_did: reference.did } })
    const claimed = await f.driver.execute({ action: 'pap-callback-claim', operationId: 'claim_callback-transaction', callback: { transaction_id: callback.transaction_id, claim_secret: secret } })
    expect(claimed).toEqual(payload)
    expect(f.proofs.at(-1)).toMatchObject({ method: 'agent_client_pap_callback_claim', params: { http_path: '/user-service/v1/agent-clients/device/pap-callback-claim', target_did: reference.did } })
    expect([...f.bindings.keys()]).toEqual(['agent_client_pap_callback_register:register_callback-transaction'])
    f.setClaimResponse(async () => json({ state: payload.state, iss: payload.iss, error: 'access_denied' }))
    await expect(f.driver.execute({ action: 'pap-callback-claim', operationId: 'claim_error', callback: { transaction_id: callback.transaction_id, claim_secret: secret } })).resolves.toMatchObject({ error: 'access_denied' })
  })
  it('rejects arbitrary actions, sensitive registration additions and mismatched client/relay before signing', async () => {
    const f = await fixture(); const before = f.proofs.length
    for (const command of [
      { action: 'device_document_update', operationId: 'unknown', callback: registration() },
      { action: 'pap-callback-register', operationId: 'one', callback: { ...registration(), code_verifier: 'must-not-be-signed' } },
      { action: 'pap-callback-register', operationId: 'two', callback: { ...registration(), client_id: clientId + '/other' } },
      { action: 'pap-callback-register', operationId: 'three', callback: { ...registration(), redirect_uri: origin + '/dynamic' } },
    ]) await expect(f.driver.execute(command as never)).rejects.toMatchObject({ code: 'invalid_request' })
    expect(f.proofs).toHaveLength(before)
  })
  it('rejects changed registration material under an existing operation instead of replacing the pickup secret', async () => {
    const f = await fixture(); const callback = registration()
    await f.driver.execute({ action: 'pap-callback-register', operationId: 'stable-operation', callback })
    const before = f.proofs.length
    await expect(f.driver.execute({ action: 'pap-callback-register', operationId: 'stable-operation', callback: { ...callback, claim_sha256: 'c'.repeat(64) } })).rejects.toMatchObject({ code: 'catalog_conflict' })
    expect(f.proofs).toHaveLength(before)
  })
  it('preserves only documented management errors and makes no automatic pickup retry', async () => {
    const f = await fixture()
    f.setClaimResponse(async () => json({ error: 'callback_not_ready' }, 409))
    const before = f.proofs.length
    await expect(f.driver.execute({ action: 'pap-callback-claim', operationId: 'claim_pending', callback: { transaction_id: 'callback-transaction', claim_secret: secret } })).rejects.toBeInstanceOf(PapCallbackManagementError)
    expect(f.proofs).toHaveLength(before + 1)
    f.setClaimResponse(async () => { throw new Error('arbitrary-sensitive-network-error') })
    await expect(f.driver.execute({ action: 'pap-callback-claim', operationId: 'claim_unknown', callback: { transaction_id: 'callback-transaction', claim_secret: secret } })).rejects.toMatchObject({ code: 'provider_unavailable' })
    expect(f.bindings.size).toBe(0)
  })
  it('withholds a received claim when the Host management capability is disposed in flight', async () => {
    const f = await fixture()
    let entered!: () => void; let release!: (value: Response) => void
    const started = new Promise<void>(resolve => { entered = resolve })
    const held = new Promise<Response>(resolve => { release = resolve })
    f.setClaimResponse(async () => { entered(); return held })
    const pending = f.driver.execute({ action: 'pap-callback-claim', operationId: 'claim_inflight', callback: { transaction_id: 'callback-transaction', claim_secret: secret } })
    const rejected = expect(pending).rejects.toMatchObject({ code: 'provider_disposed' })
    await started; f.deactivate(); release(json(payload)); await rejected
  })
})
