/** Native cryptography and local registration fences; HTTP authority is a unit double unless explicitly stated. */
import { Context } from '@deepseek-ai/cordis'
import { spawn } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, expect, it } from 'vitest'
import type { JsonValue } from '@agent-network-protocol/anp-identity'
import { IdentityProvider, type ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import AnpIdentityService from '../src/index.js'
import type { NativeProviderRegistry } from '../src/provider-api.js'
import { prepareInitialRegistrationProof } from '../src/initial-registration-proof.js'
import { canonicalManagementJson, registerLocalIdentity, type ManagementCredentialBroker } from '../src/management-driver.js'

const cleanups: Array<() => Promise<void>> = []
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup() })
const origin = 'https://identity.example'
const unsigned = (document: JsonValue) => { const value = structuredClone(document) as Record<string, JsonValue>; delete value.proof; return value }
const hash = (document: JsonValue) => 'sha256:' + createHash('sha256').update(canonicalManagementJson(document)).digest('base64url')

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'c-initial-proof-'))
  cleanups.push(() => rm(root, { recursive: true, force: true }))
  const provider = await IdentityProvider.initialize({ stateRoot: root, rootKeyKind: 'local_private_file' })
  const native = provider.acquireLease({ consumer: 'initial-proof-owner', capabilities: ['IDENTITY_CREATE', 'IDENTITY_READ', 'IDENTITY_SIGN', 'IDENTITY_DOCUMENT_UPDATE', 'IDENTITY_HTTP_SIGNATURE', 'IDENTITY_DELETE'], ttlSeconds: 300 })
  cleanups.push(async () => native.dispose())
  const identity = await native.create({ profile: 'e1', domain: 'identity.example', pathSegments: ['user', randomUUID()],
    managedKeys: [{ fragment: 'root', role: 'root_control' }, { fragment: 'device', role: 'device_signing' }, { fragment: 'agreement', role: 'e2ee_agreement' }],
    extensions: [{ type: 'device_manifest', value: { devices: [{ deviceId: 'dsh-proof-device', signingKeyId: '#device', e2eeKeyId: '#agreement',
      profiles: ['anp.core.binding.v1', 'anp.identity.discovery.v1', 'anp.direct.base.v1',
        'anp.direct.e2ee.v2', 'anp.group.base.v2', 'anp.group.e2ee.v2'] }] } }] })
  const reference = identity.reference
  const credentials: ManagementCredentialBroker = { async get() { return undefined }, async set() {}, async reserveOperation(_ref, _origin, _id, body) { return body } }
  let sent: JsonValue | undefined, sends = 0
  const transport: typeof fetch = async input => {
    const request = input as Request
    const body = await request.json() as { method: string; params: { did_document: JsonValue } }
    sends += 1
    if (body.method === 'register') {
      sent = body.params.did_document
      return Response.json({ result: { state: 'registered', did: reference.did, access_token: 'unit-private-token-not-public' } })
    }
    return Response.json({ result: { did: reference.did, checkpoint: { document_version: 1, registry_version: 1, document_hash: hash(sent!) },
      devices: [{ device_id: 'dsh-proof-device', signing_key_id: reference.did + '#device', status: 'active', role: 'admin', management_ready: true }] } })
  }
  return { root, provider, native, identity, reference, credentials, transport, sent: () => sent, sends: () => sends,
    register: (lease: ProviderLease = native, assertActive?: () => void) => registerLocalIdentity({ reference, origin, credentials, fetch: transport,
      registration: { handle: 'dsh-proof-agent' }, withNative: async run => { assertActive?.(); const result = await run(lease); assertActive?.(); return result },
      ...(assertActive ? { assertActive } : {}) }) }
}

it('sends a fresh proof for the same native identity and adopts the exact first Registry digest only once', async () => {
  const f = await fixture()
  const beforeStatus = await f.native.hostStatus(f.reference)
  await expect(f.register()).resolves.toMatchObject({ state: 'registered', did: f.reference.did })
  const sent = f.sent()!
  expect(unsigned(sent)).toEqual(unsigned(f.identity.document))
  expect(sent).not.toEqual(f.identity.document)
  expect(f.sends()).toBe(2)
  expect((await f.native.publicIdentity(f.reference)).document).toEqual(sent)
  expect((await f.native.hostStatus(f.reference)).rootKeyFingerprint).toBe(beforeStatus.rootKeyFingerprint)
  expect((await f.native.hostStatus(f.reference)).checkpoint).toEqual({ documentVersion: 1, registryVersion: 1, documentDigest: hash(sent) })
  const second = await f.native.signDocumentProof(f.reference, { document: unsigned(sent), options: { proofPurpose: 'assertionMethod', proofType: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022', created: new Date().toISOString(), domain: 'identity.example', challenge: 'second-confirmation' } })
  await expect(f.native.adoptVerifiedDocument(f.reference, { document: second, evidence: { documentVersion: 1, registryVersion: 1, documentDigest: hash(second) } })).rejects.toMatchObject({ code: 'conflict' })
})

it('requires the real native SIGN capability and does not grant it to an ordinary publication lease', async () => {
  const f = await fixture()
  const readUpdate = f.provider.acquireLease({ consumer: 'publication-only', capabilities: ['IDENTITY_READ', 'IDENTITY_DOCUMENT_UPDATE'], ttlSeconds: 60 })
  try { await expect(f.register(readUpdate)).rejects.toMatchObject({ code: 'capability_denied' }); expect(f.sends()).toBe(0) }
  finally { readUpdate.dispose() }
})

it.each(['origin', 'revision', 'state'] as const)('rejects a noninitial or foreign %s snapshot before signing', async changed => {
  const f = await fixture()
  const snapshot = structuredClone(f.identity)
  if (changed === 'revision') snapshot.revision += 1
  if (changed === 'state') snapshot.state = 'revoked'
  await expect(prepareInitialRegistrationProof(f.native, snapshot, changed === 'origin' ? 'https://other.example' : origin)).rejects.toMatchObject({ code: 'provider_incompatible' })
  expect(f.sends()).toBe(0)
})

it('withholds a signed result and sends nothing when the actual native document changes during signing', async () => {
  const f = await fixture()
  const lease = intercept(f.native, async () => { await f.native.prepareOAuthKeyChange(f.reference, { fragment: 'oauth', operation_id: 'concurrent', expected_revision: 1 }) })
  await expect(f.register(lease)).rejects.toMatchObject({ code: 'catalog_conflict' })
  expect(f.sends()).toBe(0)
})

it('withholds a signed result after the original provider or manager authority is revoked', async () => {
  const f = await fixture()
  let active = true
  const lease = intercept(f.native, async () => { active = false })
  await expect(f.register(lease, () => { if (!active) throw Object.assign(new Error('Authority unavailable.'), { code: 'provider_disposed' }) })).rejects.toMatchObject({ code: 'provider_disposed' })
  expect(f.sends()).toBe(0)
})

it('rejects a missing backend result without a physical registration send', async () => {
  const f = await fixture()
  const lease = intercept(f.native, async () => { throw Object.assign(new Error('Backend unavailable.'), { code: 'provider_unavailable' }) })
  await expect(f.register(lease)).rejects.toMatchObject({ code: 'provider_unavailable' })
  expect(f.sends()).toBe(0)
})

it('does not refresh or resend registration when the same broker already holds its registration credential', async () => {
  const f = await fixture()
  f.credentials.get = async () => ({ accessToken: 'unit-existing-token', deviceId: 'device', signingKeyId: f.reference.did + '#device' })
  await expect(f.register()).rejects.toMatchObject({ code: 'catalog_conflict' })
  expect(f.sends()).toBe(0)
})

it('rejects a provider result that changes document intent instead of only its proof', async () => {
  const f = await fixture()
  const lease = new Proxy(f.native, { get(target, key) {
    if (key === 'signDocumentProof') return async (...args: Parameters<ProviderLease['signDocumentProof']>) => {
      const result = await target.signDocumentProof(...args) as Record<string, JsonValue>
      return { ...result, service: [] }
    }
    const value = Reflect.get(target, key, target); return typeof value === 'function' ? value.bind(target) : value
  } })
  await expect(f.register(lease)).rejects.toMatchObject({ code: 'provider_incompatible' })
  expect(f.sends()).toBe(0)
})

it('adds SIGN only to the private initial-register callsite and keeps default publication capabilities unchanged', async () => {
  const f = await fixture()
  const ctx = new Context(); cleanups.push(() => ctx.fiber.dispose())
  const entries: Array<{ options: { name: string }; disabled: boolean; fiber: Context['fiber'] }> = []
  ctx.provide('loader', { *entries() { yield* entries } })
  await ctx.plugin(AnpIdentityService, { stateRoot: f.root })
  const service = ctx.anpIdentity as AnpIdentityService
  const requested: string[][] = []
  ;(service as unknown as NativeProviderRegistry).registerProvider({ protocol: 'anp-identity-node-provider/1', provider: { acquireLease(request) {
    requested.push([...request.capabilities]); return f.provider.acquireLease(request)
  } } })
  await service.health()
  let managerContext!: Context
  await ctx.plugin(Object.assign((context: Context) => { managerContext = context }, { inject: ['anpIdentity'] }))
  entries.push({ options: { name: '@agent-network-protocol/dsh-anp-identity/management-remote' }, disabled: false, fiber: managerContext.fiber })
  requested.length = 0
  await (managerContext.anpIdentity as AnpIdentityService).registerLocalIdentity(managerContext, { reference: f.reference, origin,
    credentials: f.credentials, registration: { handle: 'dsh-proof-agent' }, fetch: f.transport })
  expect(requested.some(caps => caps.includes('IDENTITY_SIGN'))).toBe(true)
  expect(requested.filter(caps => caps.includes('IDENTITY_SIGN')).every(caps => caps.join(',') === 'IDENTITY_READ,IDENTITY_DOCUMENT_UPDATE,IDENTITY_HTTP_SIGNATURE,IDENTITY_SIGN')).toBe(true)
  expect(requested.some(caps => caps.join(',') === 'IDENTITY_READ,IDENTITY_DOCUMENT_UPDATE,IDENTITY_HTTP_SIGNATURE')).toBe(true)
})

const source = process.env.DSH_IDENTITY_USER_SERVICE_SOURCE, python = process.env.DSH_IDENTITY_PYTHON
it.skipIf(!source || !python)('uses actual B SDK validation: a valid native old proof expires while the refreshed same-key proof succeeds', async () => {
  const f = await fixture()
  const old = await f.native.signDocumentProof(f.reference, { document: unsigned(f.identity.document), options: { proofPurpose: 'assertionMethod',
    proofType: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', domain: 'identity.example', challenge: 'old-proof-vector', created: new Date(Date.now() - 601000).toISOString() } })
  const fresh = await prepareInitialRegistrationProof(f.native, f.identity, origin)
  expect(unsigned(old)).toEqual(unsigned(fresh.document))
  const result = await validateWithB([old, fresh.document])
  expect(result).toEqual([{ accepted: true }, { accepted: false, code: 'device.document_proof_expired' }, { accepted: true }])
})

function intercept(native: ProviderLease, afterSign: () => Promise<void>): ProviderLease {
  return new Proxy(native, { get(target, key) {
    if (key === 'signDocumentProof') return async (...args: Parameters<ProviderLease['signDocumentProof']>) => { const result = await target.signDocumentProof(...args); await afterSign(); return result }
    const value = Reflect.get(target, key, target); return typeof value === 'function' ? value.bind(target) : value
  } })
}

async function validateWithB(documents: JsonValue[]): Promise<unknown> {
  const script = 'import json,sys\nfrom datetime import UTC,datetime\nfrom user_service.app.did_auth.multi_device_service import SdkVNextDocumentValidator,MultiDeviceIdentityError\nv=SdkVNextDocumentValidator(allowed_did_domains=("identity.example",))\nr=[]\ndocs=json.load(sys.stdin)\nv.validate(docs[0],now=datetime.fromisoformat(docs[0]["proof"]["created"]));r.append({"accepted":True})\nfor d in docs:\n try:\n  v.validate(d,now=datetime.now(UTC));r.append({"accepted":True})\n except MultiDeviceIdentityError as e:r.append({"accepted":False,"code":e.awiki_code})\nprint(json.dumps(r))'
  const child = spawn(python!, ['-c', script], { cwd: source!, env: { ...process.env, PYTHONPATH: join(source!, 'src') }, stdio: ['pipe', 'pipe', 'pipe'] })
  let output = ''; child.stdout.on('data', value => { output += String(value) }); child.stderr.resume()
  child.stdin.end(JSON.stringify(documents))
  return new Promise((resolve, reject) => {
    child.once('error', () => reject(new Error('The SDK validator is unavailable.')))
    child.once('exit', code => { if (code !== 0) reject(new Error('The SDK validator failed.')); else { try { resolve(JSON.parse(output)) } catch { reject(new Error('Invalid SDK validator result.')) } } })
  })
}
