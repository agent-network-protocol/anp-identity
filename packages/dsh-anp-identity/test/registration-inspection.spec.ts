import { createHash, randomUUID } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, expect, it, vi } from 'vitest'
import { IdentityProvider } from '@agent-network-protocol/anp-identity/provider'
import { canonicalManagementJson, inspectRegisteredDevice } from '../src/management-driver.js'

const cleanups: Array<() => Promise<void>> = []
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup() })

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'registration-inspection-'))
  cleanups.push(() => rm(root, { recursive: true, force: true }))
  const provider = await IdentityProvider.initialize({ stateRoot: root, rootKeyKind: 'local_private_file' })
  const native = provider.acquireLease({ consumer: 'inspection-fixture', capabilities: ['IDENTITY_CREATE', 'IDENTITY_READ', 'IDENTITY_HTTP_SIGNATURE'], ttlSeconds: 60 })
  cleanups.push(async () => native.dispose())
  const identity = await native.create({ profile: 'e1', domain: 'identity.example', pathSegments: ['user', randomUUID()],
    managedKeys: [{ fragment: 'root', role: 'root_control' }, { fragment: 'device', role: 'device_signing' }, { fragment: 'agreement', role: 'e2ee_agreement' }],
    extensions: [{ type: 'device_manifest', value: { devices: [{ deviceId: 'fixture-device', signingKeyId: '#device', e2eeKeyId: '#agreement',
      profiles: ['anp.core.binding.v1', 'anp.identity.discovery.v1', 'anp.direct.base.v1', 'anp.direct.e2ee.v2', 'anp.group.base.v2', 'anp.group.e2ee.v2'] }] } }] })
  const registry = { did: identity.reference.did,
    checkpoint: { document_version: 1, registry_version: 1, document_hash: 'sha256:' + createHash('sha256').update(canonicalManagementJson(identity.document)).digest('base64url') },
    devices: [{ device_id: 'fixture-device', signing_key_id: identity.reference.did + '#device', status: 'active', role: 'admin', management_ready: true }] }
  const inspect = (send: typeof fetch, assertActive = () => {}) => inspectRegisteredDevice({ reference: identity.reference, origin: 'https://identity.example',
    withNative: async operation => operation(native), fetch: send, assertActive })
  return { native, identity, registry, inspect }
}

it('signs only the exact Registry read and never changes the local identity or checkpoint', async () => {
  const f = await fixture()
  const before = await f.native.hostStatus(f.identity.reference)
  const send = vi.fn<typeof fetch>(async input => {
    const request = input as Request
    expect(request.url).toBe('https://identity.example/user-service/v1/did-auth/rpc')
    expect(request.headers.has('signature')).toBe(true)
    expect(request.headers.has('authorization')).toBe(false)
    expect(await request.json()).toMatchObject({ method: 'device_registry_get', params: {} })
    return Response.json({ result: f.registry })
  })
  expect(await f.inspect(send)).toEqual({ outcome: 'verified', httpStatus: 200 })
  expect(send).toHaveBeenCalledOnce()
  expect(await f.native.publicIdentity(f.identity.reference)).toEqual(f.identity)
  expect(await f.native.hostStatus(f.identity.reference)).toEqual(before)
})

it('keeps rejections closed and does not return remote messages or token-shaped fields', async () => {
  const f = await fixture()
  const secret = 'REMOTE-SECRET-MUST-NOT-ESCAPE'
  expect(await f.inspect(async () => Response.json({ error: { code: -32001, message: secret, data: { access_token: secret } } })))
    .toEqual({ outcome: 'rejected', httpStatus: 200, rpcCode: -32001 })
  expect(await f.inspect(async () => Response.json({ detail: secret }, { status: 401 })))
    .toEqual({ outcome: 'rejected', httpStatus: 401 })
  expect(await f.inspect(async () => { throw new Error(secret) })).toEqual({ outcome: 'unavailable' })
})

it.each(['did', 'key', 'role', 'ready', 'checkpoint'] as const)('does not verify a mismatched %s Registry', async changed => {
  const f = await fixture()
  const registry = structuredClone(f.registry)
  if (changed === 'did') registry.did += ':other'
  if (changed === 'key') registry.devices[0]!.signing_key_id += '-other'
  if (changed === 'role') registry.devices[0]!.role = 'reader'
  if (changed === 'ready') registry.devices[0]!.management_ready = false
  if (changed === 'checkpoint') registry.checkpoint.document_hash = 'invalid'
  expect(await f.inspect(async () => Response.json({ result: registry }))).toEqual({ outcome: 'incompatible', httpStatus: 200 })
})

it('honors the owner/provider fence before any physical request', async () => {
  const f = await fixture()
  const send = vi.fn<typeof fetch>()
  const result = await f.inspect(send, () => { throw Object.assign(new Error('private details'), { code: 'provider_disposed' }) })
  expect(result).toEqual({ outcome: 'unavailable', nativeCode: 'provider_disposed' })
  expect(send).not.toHaveBeenCalled()
})
