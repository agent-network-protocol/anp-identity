import { Context } from '@deepseek-ai/cordis'
import { createHash, createPublicKey, verify } from 'node:crypto'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import AnpIdentityService from '../src/index.js'
import { openNativeProvider } from '../src/provider.js'
import type { NativeProviderRegistry } from '../src/provider-api.js'
import type { AccessAuthorizationRequest, CreateAuthorizationRequest } from '../src/authorization-types.js'
import type { UserIdentityClient, UserOperation } from '../src/user-client.js'
import type { PublicationBackend, PreparedClientMaterials } from '../src/publication-types.js'
import { createPublicationBackend, exactHttps, parsePublicJson } from '../src/publication-http.js'

const audience = 'https://issuer.example/token'
const config = { backend: 'test', documentId: 'one', clientName: 'One', redirectUris: ['https://client.example/callback'] }
const sha = (text: string) => createHash('sha256').update(text).digest('hex')

export async function fixture(missingOAuth = false) {
  const root = await mkdtemp(join(tmpdir(), 'identity-publication-'))
  let runtime = await start(root, missingOAuth)
  return {
    root, get service() { return runtime.service }, get manager() { return (runtime.managerContext.anpIdentity as AnpIdentityService).acquireManagement(runtime.managerContext) },
    get managerService() { return runtime.managerContext.anpIdentity as AnpIdentityService },
    get managerContext() { return runtime.managerContext }, get first() { return runtime.first }, get second() { return runtime.second },
    get firstContext() { return runtime.firstContext }, get ctx() { return runtime.ctx },
    async create() {
      const request = await runtime.first.requestCreateIdentity({ requestId: 'create-one', purpose: 'Create an independent identity', parameters: { label: 'One', domain: 'example.com', path: '/publication/one' } })
      const decision = await this.manager.decide({ requestId: request.id, expectedVersion: request.version, decision: 'approve' }) as CreateAuthorizationRequest
      return decision.result!.reference
    },
    async restart() { await runtime.ctx.fiber.dispose(); runtime = await start(root) },
    async [Symbol.asyncDispose]() { await runtime.ctx.fiber.dispose(); await rm(root, { recursive: true, force: true }) },
  }
}
async function start(root: string, missingOAuth = false) {
  const ctx = new Context()
  const entries: Array<{ options: { name: string }; disabled: boolean; fiber: Context['fiber'] }> = []
  ctx.provide('loader', { *entries() { yield* entries } })
  await ctx.plugin(AnpIdentityService, { stateRoot: root, allowConsumers: ['one', 'two'], userConsumers: ['one', 'two'],
    oauthAllowedAudiences: { one: [audience], two: [audience] } })
  const service = ctx.anpIdentity as AnpIdentityService
  async function installed(name: string) {
    let context: Context | undefined
    await ctx.plugin(Object.assign((value: Context) => { context = value }, { inject: ['anpIdentity'] }))
    entries.push({ options: { name }, disabled: false, fiber: context!.fiber })
    return context!
  }
  const managerContext = await installed('@agent-network-protocol/dsh-anp-identity/management-remote')
  const firstContext = await installed('one')
  const secondContext = await installed('two')
  const registration = await openNativeProvider({ stateRoot: root, rootKeyProvider: 'injected', rootKeyProviderId: 'publication', injectedRootKey: Buffer.alloc(32, 89) })
  if (missingOAuth) {
    const acquire = registration.provider.acquireLease.bind(registration.provider)
    registration.provider.acquireLease = request => new Proxy(acquire(request), {
      get(target, key) {
        if (key === 'oauthPublicJwk') return undefined
        const value = Reflect.get(target, key, target)
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
  }
  ;(service as unknown as NativeProviderRegistry).registerProvider(registration)
  await service.health()
  return { ctx, service, managerContext, firstContext,
    first: service.bindUserConsumer(firstContext), second: service.bindUserConsumer(secondContext) }
}
export async function approve(f: Awaited<ReturnType<typeof fixture>>, client: UserIdentityClient,
  identity: Parameters<UserIdentityClient['requestAccess']>[0]['identity'], id: string, operation?: UserOperation, mode: 'once' | 'permanent' = 'permanent') {
  const request = await client.requestAccess({ requestId: id, purpose: 'Use the published identity', ...(identity ? { identity } : {}), ...(operation ? { operation } : {}) })
  const review = await f.manager.getRequest(request.id)
  const grant = await f.manager.decide({ requestId: request.id, expectedVersion: request.version, decision: 'approve', mode,
    reviewedSnapshot: review.snapshot! }) as AccessAuthorizationRequest
  return { identity: await client.openAuthorizedIdentity(grant.grantId!), grant }
}

/** Remote authorization is a test seam; the native key, document session and catalog are real. */
function backendFixture() {
  let row: PreparedClientMaterials | undefined
  let requestHash: string | undefined
  let lost = false
  let damage = false
  let unknown = false
  let prepareCount = 0
  const backend: PublicationBackend = {
    origin: 'https://identity.example',
    clientId: id => `https://identity.example/${id}/client.json`,
    async prepare(id, request) {
      prepareCount++
      const hash = sha(JSON.stringify(request))
      if (row && row.operation_id === request.operation_id) {
        expect(hash).toBe(requestHash)
        return row
      }
      const clientId = await backend.clientId(id)
      const metadata = JSON.stringify({ client_id: clientId, client_name: request.client_name, jwks_uri: 'https://identity.example/public-keys/signing.json',
        redirect_uris: request.redirect_uris, grant_types: ['authorization_code'], response_types: ['code'], token_endpoint_auth_method: 'private_key_jwt', token_endpoint_auth_signing_alg: 'EdDSA' })
      row = { state: 'prepared', client_id: clientId, operation_id: request.operation_id, version: request.expected_version + 1,
        metadata, jwks: JSON.stringify({ keys: ['signing_keys' in request ? request.signing_keys[0] : request.key] }), metadata_sha256: sha(metadata) }
      requestHash = hash
      if (lost) { lost = false; throw new Error('Test lost prepare response') }
      return row
    },
    async activate(_, operationId) {
      expect(row!.operation_id).toBe(operationId)
      row = { ...row!, state: 'published' }
      return row
    },
    async readPublic(_, part) {
      if (damage) return '{}'
      return (part === 'client.json' ? row!.metadata : row!.jwks)!
    },
    async publishDocument(_, session, assertActive) {
      await assertActive()
      const candidate = await session.candidate()
      const evidence = { documentVersion: 2, registryVersion: 2, documentDigest: candidate.candidateDigest }
      if (await session.hostPhase() === 'publication_uncertain') {
        await session.reconcile({ document: candidate.candidateDocument, evidence: { ...evidence, documentDigest: 'sha256:' + candidate.candidateDigest } })
        return
      }
      const attempt = await session.beginPublication()
      if (unknown) { unknown = false; await session.complete(attempt, { result: 'unknown' }); throw new Error('Test lost document response') }
      await session.complete(attempt, { result: 'confirmed', evidence })
    },
  }
  return { backend, losePrepare() { lost = true }, damageReadback() { damage = true }, repairReadback() { damage = false }, loseDocument() { unknown = true }, get prepareCount() { return prepareCount } }
}

describe('shared identity publication with real native custody and approvals', () => {
  it('publishes independently, shares one client, restores permits, and rejects revocation and raw JWT bypass', async () => {
    await using f = await fixture()
    const reference = await f.create()
    const server = backendFixture()
    f.managerService.registerPublicationBackend(f.managerContext, 'test', server.backend)
    expect(() => f.service.acquireManagement()).toThrow()
    expect(() => f.service.acquireManagement(f.ctx)).toThrow()
    expect(() => f.service.acquireManagement(f.firstContext)).toThrow()
    await expect(f.manager.publicationStatus(reference)).resolves.toMatchObject({ state: 'local' })
    await expect(f.manager.publishIdentity({ reference, config: { ...config, redirectUris: [] } })).resolves.toMatchObject({ state: 'awaiting_configuration' })
    expect(server.prepareCount).toBe(0)
    const published = await f.manager.publishIdentity({ reference, config })
    expect(published.state).toBe('published')
    const first = await approve(f, f.first, reference, 'first')
    const second = await approve(f, f.second, reference, 'second')
    expect(await second.identity.oauthClientIdentity()).toEqual(published)
    const token = await first.identity.signOAuthClientAssertion(audience)
    const [header, payload, signature] = token.split('.') as [string, string, string]
    expect(JSON.parse(Buffer.from(payload, 'base64url').toString())).toMatchObject({ iss: published.clientId, sub: published.clientId, aud: audience })
    const catalog = await readFile(join(f.root, 'catalog-v1.json'), 'utf8')
    const record = JSON.parse(catalog).entries[0].publication
    expect(verify(null, Buffer.from(`${header}.${payload}`), createPublicKey({ key: record.key, format: 'jwk' }), Buffer.from(signature, 'base64url'))).toBe(true)
    expect(catalog).not.toContain(token)
    await expect(first.identity.signOAuthClientAssertion('https://evil.example/token')).rejects.toThrow()
    await expect(first.identity.sign({ purpose: 'authentication', payload: Buffer.from(`${header}.${payload}`) })).rejects.toThrow()
    await f.manager.revoke({ grantId: first.grant.grantId!, expectedVersion: 1 })
    await expect(first.identity.signOAuthClientAssertion(audience)).rejects.toThrow()
    await expect(second.identity.signOAuthClientAssertion(audience)).resolves.toContain('.')
    await f.restart()
    expect(await f.manager.publicationStatus(reference)).toEqual(published)
    const resumed = await f.second.openAuthorizedIdentity(second.grant.grantId!)
    await expect(resumed.signOAuthClientAssertion(audience)).resolves.toContain('.')
    await expect(f.first.openAuthorizedIdentity(first.grant.grantId!)).rejects.toThrow()
    await expect(f.service.health()).resolves.toMatchObject({ status: 'ready' })
  })

  it('recovers a lost prepare response and uncertain signed document after restart without new identity/client', async () => {
    await using f = await fixture()
    const reference = await f.create()
    const server = backendFixture()
    f.managerService.registerPublicationBackend(f.managerContext, 'test', server.backend)
    server.losePrepare()
    await expect(f.manager.publishIdentity({ reference, config })).rejects.toThrow()
    const before = JSON.parse(await readFile(join(f.root, 'catalog-v1.json'), 'utf8')).entries[0].publication
    await f.restart()
    f.managerService.registerPublicationBackend(f.managerContext, 'test', server.backend)
    server.loseDocument()
    await expect(f.manager.publishIdentity({ reference, config })).rejects.toThrow()
    await f.restart()
    f.managerService.registerPublicationBackend(f.managerContext, 'test', server.backend)
    const recovered = await f.manager.publishIdentity({ reference, config })
    const after = JSON.parse(await readFile(join(f.root, 'catalog-v1.json'), 'utf8')).entries[0].publication
    expect(recovered.state).toBe('published')
    expect(after.operationId).toBe(before.operationId)
    expect(after.clientId).toBe(before.clientId)
    expect(await f.manager.listIdentities()).toHaveLength(1)
  })

  it('does not mark published on a public readback mismatch and consumes once permission only once', async () => {
    await using f = await fixture()
    const reference = await f.create()
    const server = backendFixture()
    f.managerService.registerPublicationBackend(f.managerContext, 'test', server.backend)
    server.damageReadback()
    await expect(f.manager.publishIdentity({ reference, config })).rejects.toThrow()
    await expect(f.manager.publicationStatus(reference)).resolves.toMatchObject({ state: 'failed' })
    const unready = await approve(f, f.first, reference, 'unready', { action: 'oauth', audience })
    await expect(unready.identity.signOAuthClientAssertion(audience)).rejects.toThrow()
    server.repairReadback()
    await expect(f.manager.publishIdentity({ reference, config })).resolves.toMatchObject({ state: 'published' })
    const once = await approve(f, f.second, reference, 'once', { action: 'oauth', audience }, 'once')
    await expect(once.identity.signOAuthClientAssertion(audience, 'once-execution')).resolves.toContain('.')
    await expect(once.identity.signOAuthClientAssertion(audience, 'second-execution')).rejects.toThrow()
    await f.restart()
    await expect(f.second.openAuthorizedIdentity(once.grant.grantId!)).rejects.toThrow()
  })
})

it('HTTP transport rejects redirects, wrong content types and excessive bodies without leaking inputs', async () => {
  const cases = [new Response('', { status: 302 }), new Response('{}'), new Response('x'.repeat(33000), { headers: { 'content-type': 'application/json' } })]
  for (const response of cases) {
    const backend = createPublicationBackend({ origin: 'https://identity.example', authenticatedFetch: async req => {
      expect(req.redirect).toBe('manual'); expect(req.headers.has('authorization')).toBe(false); return response
    }, publishDocument: async () => {} })
    await expect(backend.activate('one', 'operation')).rejects.toThrow()
  }
  for (const url of ['http://issuer.example/token', 'https://user@issuer.example/token', 'https://issuer.example/../token', 'https://issuer.example/%2e/token', 'https://issuer.example/token?x=1']) expect(() => exactHttps(url)).toThrow()
})


it('strict material JSON rejects duplicate and escaped member names at any depth', () => {
  expect(parsePublicJson('{"one":[1,true,null,{"key":"value"}]}')).toEqual({ one: [1,true,null,{key:'value'}] })
  for (const value of ['{"key":1,"key":2}', '{"key":1,"k\\u0065y":2}', '{"keys":[{"kid":"one","kid":"two"}]}', '['.repeat(34)+'0'+']'.repeat(34)]) {
    expect(() => parsePublicJson(value)).toThrow()
  }
})


it('invalidates a previously published record when a new public readback detects tampering', async () => {
  await using f = await fixture()
  const reference = await f.create()
  const server = backendFixture()
  f.managerService.registerPublicationBackend(f.managerContext, 'test', server.backend)
  await f.manager.publishIdentity({reference,config})
  server.damageReadback()
  await expect(f.manager.retryPublication(reference)).rejects.toThrow()
  await expect(f.manager.publicationStatus(reference)).resolves.toMatchObject({state:'failed'})
  server.repairReadback()
  await expect(f.manager.retryPublication(reference)).resolves.toMatchObject({state:'published'})
})


it('serializes concurrent publications for the same identity across coordinator instances', async () => {
  await using f = await fixture()
  const reference = await f.create()
  const server = backendFixture()
  f.managerService.registerPublicationBackend(f.managerContext,'test',server.backend)
  const { PublicationCoordinator } = await import('../src/publication.js')
  const installed = (f.service as unknown as { publications: InstanceType<typeof PublicationCoordinator> }).publications
  const other = new PublicationCoordinator(installed.store,installed.host)
  const [one,two] = await Promise.all([f.manager.publishIdentity({reference,config}),other.publish(reference,config,server.backend,async () => {})])
  expect(one).toEqual(two)
  expect(one.state).toBe('published')
  expect(server.prepareCount).toBe(1)
})

it('withholds a signed assertion if its grant is revoked while native signing is in flight', async () => {
  await using f = await fixture()
  const reference = await f.create()
  const server = backendFixture()
  f.managerService.registerPublicationBackend(f.managerContext,'test',server.backend)
  await f.manager.publishIdentity({reference,config})
  const approved = await approve(f,f.first,reference,'in-flight')
  const users = (f.service as unknown as {users: import('../src/user-service.js').UserIdentityService}).users
  const original = users.host.withNative.bind(users.host)
  let entered!: () => void
  let release!: () => void
  const start = new Promise<void>(resolve => { entered = resolve })
  const hold = new Promise<void>(resolve => { release = resolve })
  const spy = vi.spyOn(users.host,'withNative').mockImplementation(operation => original(native => operation(new Proxy(native,{
    get(target,key) {
      if (key === 'signOAuthClientAssertion') return async (...args: Parameters<typeof native.signOAuthClientAssertion>) => {
        const token = await native.signOAuthClientAssertion(...args)
        entered(); await hold
        return token
      }
      const value = Reflect.get(target,key,target)
      return typeof value === 'function' ? value.bind(target) : value
    }
  }))))
  const pending = approved.identity.signOAuthClientAssertion(audience)
  // Attach rejection observation before releasing the deliberately blocked native return.
  const rejected = expect(pending).rejects.toThrow()
  await start
  await f.manager.revoke({grantId:approved.grant.grantId!,expectedVersion:1})
  release()
  await rejected
  spy.mockRestore()
})


it('reports an incompatible older native Provider before starting publication', async () => {
  await using f = await fixture(true)
  const reference = await f.create()
  const server = backendFixture()
  f.managerService.registerPublicationBackend(f.managerContext,'test',server.backend)
  await expect(f.manager.publishIdentity({reference,config})).rejects.toMatchObject({code:'provider_incompatible'})
  expect(server.prepareCount).toBe(0)
})


it('uses server-selected client and JWKS URLs without deriving their paths', async () => {
  const requests: string[] = []
  const clientId = 'https://identity.example/cgw/client.json'
  const jwksUri = 'https://identity.example/key-store/active-public-keys'
  const backend = createPublicationBackend({
    origin: 'https://identity.example',
    authenticatedFetch: async request => {
      requests.push(request.url)
      return Response.json({ state: 'local', client_id: clientId, jwks_uri: jwksUri })
    },
    publicFetch: async request => { requests.push(request.url); return Response.json({ keys: [] }) },
    publishDocument: async () => {},
  })
  expect(await backend.clientId('opaque-document-id')).toBe(clientId)
  await backend.readPublic('opaque-document-id', 'jwks.json', jwksUri)
  expect(requests).toEqual([
    'https://identity.example/user-service/v1/agent-clients/opaque-document-id/status', jwksUri,
  ])
  await expect(backend.readPublic('opaque-document-id', 'jwks.json', 'https://other.example/keys')).rejects.toThrow()
  expect(requests).toHaveLength(2)
})
