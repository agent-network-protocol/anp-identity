/** Exact HTTP signing transport; cryptographic interoperability is covered by management-live. */
import { expect, it } from 'vitest'
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import { createManagedPublicationDriver, type ManagementCredentialBroker } from '../src/management-driver.js'
import { pluginError } from '../src/errors.js'

const reference = { storeId: 'store', identityId: 'identity', did: 'did:wba:identity.example:user:agent' }
const origin = 'https://identity.example'
async function fixture() {
  const sends: Request[] = []
  const signing: Array<{ kid: string; body?: Buffer }> = []
  let active = true, fail = false, revokeOnSign = false
  const native = {
    async prepareHttpSignature(request: { kid: string; body?: Buffer }) {
      signing.push(request)
      if (fail) throw pluginError('provider_unavailable')
      if (revokeOnSign) active = false
      return { headerPatch: [{ name: 'signature-input', value: 'unit-input' }, { name: 'signature', value: 'unit-signature' }] }
    },
    async signManagementProof() { return { type: 'awiki-device-signature-v1', signature: 'operation-proof' } },
  } as unknown as ProviderLease
  const credentials: ManagementCredentialBroker = {
    async get() { return { deviceId: 'device', signingKeyId: reference.did + '#device', accessToken: 'expired-token-must-not-be-sent' } },
    async set() {}, async reserveOperation(_ref, _origin, _op, body) { return body },
  }
  const driver = await createManagedPublicationDriver({ reference, origin, credentials,
    withNative: async run => run(native), assertActive: async () => { if (!active) throw pluginError('provider_disposed') },
    fetch: async input => {
      const request = input as Request
      sends.push(request.clone())
      expect(request.headers.has('authorization')).toBe(false)
      expect(request.headers.get('signature')).toBe('unit-signature')
      if (request.url.endsWith('/did-auth/rpc')) return Response.json({ result: { did: reference.did,
        checkpoint: { document_version: 1, registry_version: 1, document_hash: 'sha256:' + 'A'.repeat(43) },
        devices: [{ device_id: 'device', signing_key_id: reference.did + '#device', status: 'active', role: 'admin', management_ready: true }] } })
      return Response.json({ did: reference.did, document_id: 'one', client_id: origin + '/user-service/v1/agent-clients/one/client.json' })
    },
  })
  return { driver, sends, signing, setFailure: () => { fail = true }, revokeOnSign: () => { revokeOnSign = true } }
}

it('signs registry, resolve and public readback with the stored device key, never the expired bearer', async () => {
  const f = await fixture()
  await f.driver.backend.readPublic('one', 'client.json')
  await f.driver.backend.readPublic('one', 'jwks.json')
  expect(f.sends).toHaveLength(4)
  expect(f.signing.every(request => request.kid === reference.did + '#device')).toBe(true)
  for (let i = 0; i < 2; i++) expect(f.signing[i]!.body!.toString()).toBe(await f.sends[i]!.text())
})

it('does not fall back to stored bearer credentials when HTTP signing fails', async () => {
  const f = await fixture(); const before = f.sends.length; f.setFailure()
  await expect(f.driver.backend.readPublic('one', 'client.json')).rejects.toMatchObject({ code: 'provider_unavailable' })
  expect(f.sends).toHaveLength(before)
})

it('checks the original lifecycle after signing and before the physical send', async () => {
  const f = await fixture(); const before = f.sends.length; f.revokeOnSign()
  await expect(f.driver.backend.readPublic('one', 'client.json')).rejects.toMatchObject({ code: 'provider_disposed' })
  expect(f.sends).toHaveLength(before)
})

it('rejects a different identity before requesting or signing publication work', async () => {
  const f = await fixture(); const before = f.sends.length
  await expect(f.driver.backend.publishDocument({ ...reference, identityId: 'another' }, {} as never, async () => {})).rejects.toMatchObject({ code: 'invalid_request' })
  expect(f.sends).toHaveLength(before)
})
