/** Fixed local component contract: actual C/A plus production B routes and an isolated MySQL. */
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes, randomUUID } from 'node:crypto'
import { Context } from '@deepseek-ai/cordis'
import { expect, it } from 'vitest'
import AnpIdentityService from '../src/index.js'
import { openNativeProvider } from '../src/provider.js'
import { createManagedCallbackFixture } from './helpers/managed-callback-fixture.js'
import { createHash } from 'node:crypto'
import { createAuthenticatedHttp } from '../src/http-auth.js'
import { createManagedPublicationDriver } from '../src/management-driver.js'
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import { EncryptedManagementCredentialBroker } from '../src/management-credentials.js'
import type { NativeProviderRegistry } from '../src/provider-api.js'
import type { CreateAuthorizationRequest } from '../src/authorization-types.js'

const source = process.env.DSH_IDENTITY_USER_SERVICE_SOURCE
const python = process.env.DSH_IDENTITY_PYTHON
it.skipIf(!source || !python)('registers approved E1/Web local Manifests, authenticates actual ready-admin devices and publishes callback-free machine V2', async () => {
  const child = spawn(python!, [join(source!, 'tests/app/cimd/management_bridge.py')], { cwd: source!,
    env: { ...process.env, CIMD_TEST_REAL_MANAGEMENT_BRIDGE: '1', PYTHONPATH: join(source!, 'src') }, stdio: ['pipe', 'pipe', 'pipe'] })
  const replies: Array<{ resolve(value: { status: number; headers: Record<string, string>; body: string }): void; reject(error: Error): void }> = []
  let diagnostics = ''
  child.stderr.on('data', chunk => { diagnostics = (diagnostics + String(chunk)).slice(-5000) })
  const exited = new Promise<void>((resolve, reject) => {
    child.once('error', () => reject(new Error('management_bridge_spawn_failed')))
    child.once('exit', code => { const error = new Error('management_bridge_exited'); while (replies.length) replies.shift()!.reject(error); code === 0 ? resolve() : reject(error) })
  })
  void exited.catch(() => {})
  createInterface({ input: child.stdout }).on('line', line => {
    const next = replies.shift()
    try { const value = JSON.parse(line); if (value.error) next?.reject(new Error('management_bridge_request_failed')); else next?.resolve(value) }
    catch { next?.reject(new Error('management_bridge_protocol_failed')) }
  })
  const call = (value: unknown) => new Promise<{ status: number; headers: Record<string, string>; body: string }>((resolve, reject) => { replies.push({ resolve, reject }); child.stdin.write(JSON.stringify(value) + '\n') })
  let lastFailure = ''
  let dropPrepare = false
  let dropDocument = false
  const transport: typeof fetch = async input => {
    const request = input as Request
    const requestBody = request.body ? await request.text() : null
    const response = await call({ action: 'request', method: request.method, url: request.url, headers: Object.fromEntries(request.headers), body: requestBody })
    const envelope = JSON.parse(response.body)
    if (response.status !== 200 || envelope.error) lastFailure = JSON.stringify({ status: response.status, code: envelope.error?.code, message: envelope.error?.message, detail: envelope.detail }).slice(0, 1500).replace(/Bearer\s+\S+/gu, '[redacted]')
    if (dropPrepare && request.url.endsWith('/agent-clients/device/prepare') && response.status === 200 && !envelope.error) { dropPrepare = false; throw new Error('component_lost_prepare_response') }
    if (dropDocument && request.url.endsWith('/did-auth/rpc') && response.status === 200 && !envelope.error) {
      const outgoing = JSON.parse(requestBody!)
      if (outgoing.method === 'device_document_update') { dropDocument = false; throw new Error('component_lost_document_response') }
    }
    return new Response(response.body, { status: response.status, headers: response.headers })
  }
  const root = await mkdtemp(join(tmpdir(), 'c-b-management-'))
  const key = randomBytes(32)
  const ctx = new Context()
  const entries: Array<{ options: { name: string }; disabled: boolean; fiber: Context['fiber'] }> = []
  ctx.provide('loader', { *entries() { yield* entries } })
  await ctx.plugin(AnpIdentityService, { stateRoot: root, allowConsumers: ['@fixture/creator'], userConsumers: ['@fixture/creator'] })
  const service = ctx.anpIdentity as AnpIdentityService
  const nativeRegistration = await openNativeProvider({ stateRoot: root, rootKeyProvider: 'injected', rootKeyProviderId: 'management-component', injectedRootKey: Buffer.alloc(32, 102) })
  let nativeFailure = ''
  const acquire = nativeRegistration.provider.acquireLease.bind(nativeRegistration.provider)
  nativeRegistration.provider.acquireLease = request => new Proxy(acquire(request), { get(target, property) {
    const value = Reflect.get(target, property, target)
    if (typeof value !== 'function') return value
    return (...args: unknown[]) => {
      const result = Reflect.apply(value, target, args)
      return result instanceof Promise ? result.catch(error => { nativeFailure = String(property) + ':' + (error.code ?? 'unknown'); throw error }) : result
    }
  } })
  ;(service as unknown as NativeProviderRegistry).registerProvider(nativeRegistration)
  await service.health()
  const installed = async (name: string) => { let context!: Context; await ctx.plugin(Object.assign((value: Context) => { context = value }, { inject: ['anpIdentity'] })); entries.push({ options: { name }, disabled: false, fiber: context.fiber }); return context }
  const managerContext = await installed('@agent-network-protocol/dsh-anp-identity/management-remote')
  const creatorContext = await installed('@fixture/creator')
  const managerService = managerContext.anpIdentity as AnpIdentityService
  const manager = managerService.acquireManagement(managerContext)
  const creator = (creatorContext.anpIdentity as AnpIdentityService).bindUserConsumer(creatorContext)
  const credentials = new EncryptedManagementCredentialBroker(join(root, 'management'), async () => Buffer.from(key))
  let creationCode = ''
  const users = (service as unknown as { users: { host: { createIdentity: (...args: unknown[]) => Promise<unknown> } } }).users
  const originalCreate = users.host.createIdentity
  users.host.createIdentity = async (...args) => { try { return await originalCreate(...args) } catch (error) { creationCode = (error as { code?: string }).code ?? (error instanceof Error ? error.message : 'unknown'); throw error } }
  const extraNative: ProviderLease[] = []
  let stage = 'start'
  try {
    for (const profile of ['e1', 'web'] as const) {
      const run = randomUUID().replaceAll('-', '')
      const path = profile === 'web' ? '/awiki/web/' + run : '/awiki/user/' + run
      const request = await creator.requestCreateIdentity({ requestId: 'create-' + profile, purpose: 'Create a managed machine identity', parameters: { profile, usage: 'protocol', label: profile, domain: 'identity.example', path } })
      stage = profile + ':create'
      const approved = await manager.decide({ requestId: request.id, expectedVersion: request.version, decision: 'approve' }) as CreateAuthorizationRequest
      if (!approved.result) throw new Error('create_unknown:' + creationCode + ':' + nativeFailure)
      const reference = approved.result.reference
      stage = profile + ':register'
      const registered = await managerService.registerLocalIdentity(managerContext, { reference, origin: 'https://identity.example', credentials, fetch: transport,
        managementAudience: 'awiki-user-service', registration: { handle: 'dsh-cimd-' + run, email: 'dsh-cimd-' + run + '@example.invalid', ...(profile === 'web' ? { registration_operation_id: randomUUID() } : {}) } })
      expect(registered.state).toBe('registered')
      const credential = await credentials.get(reference, 'https://identity.example')
      expect(credential).toBeDefined()
      const probeNative = nativeRegistration.provider.acquireLease({ consumer: 'http-auth-component', capabilities: ['IDENTITY_READ', 'IDENTITY_HTTP_SIGNATURE'], ttlSeconds: 60 })
      extraNative.push(probeNative)
      const authenticated = createAuthenticatedHttp(reference, probeNative, new Set(['https://identity.example']), async () => {}, async () => credential!.signingKeyId)
      const capture = async () => {
        let signed!: Request
        await authenticated.dispatch(new Request('https://identity.example/user-service/v1/did-auth/rpc', { method: 'POST',
          headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 'signed-probe', method: 'device_registry_get', params: {} }) }),
          async request => { signed = request.clone(); return Response.json({}) })
        expect(signed.headers.has('signature-input')).toBe(true)
        expect(signed.headers.has('signature')).toBe(true)
        expect(signed.headers.has('content-digest')).toBe(true)
        expect(signed.headers.has('authorization')).toBe(false)
        return signed
      }
      const signed = await capture()
      const accepted = await transport(signed.clone())
      expect(accepted.headers.get('authentication-info')).toContain('access_token=')
      expect((await accepted.json()).result.did).toBe(reference.did)
      expect((await (await transport(signed.clone())).json()).error).toMatchObject({ code: -32000 })
      const changedBody = await capture()
      expect((await (await transport(new Request(changedBody, { body: (await changedBody.clone().text()).replace('signed-probe', 'changed-body') }))).json()).error).toMatchObject({ code: -32000 })
      const changedUrl = await capture()
      expect((await (await transport(new Request(changedUrl.url + '?tampered=1', changedUrl))).json()).error).toMatchObject({ code: -32000 })
      lastFailure = ''
      if (profile === 'e1') await credentials.set(reference, 'https://identity.example', { ...credential!, accessToken: 'unusable-old-credential' })
      stage = profile + ':resolve'
      const configured = await managerService.configureManagedPublicationBackend(managerContext, profile, { reference, origin: 'https://identity.example', credentials, fetch: transport })
      stage = profile + ':publish'
      const publication = { reference, config: { backend: profile, documentId: configured.documentId, clientName: profile + ' machine', redirectUris: [],
        activeKid: reference.did + '#oauth', capabilities: { mcpMachine: true, papSession: false, papAccount: false } } }
      let result
      if (profile === 'e1') {
        dropPrepare = true; dropDocument = true
        await expect(manager.publishIdentity(publication)).rejects.toThrow()
        const before = JSON.parse(await readFile(join(root, 'catalog-v1.json'), 'utf8')).entries.find((entry: { did: string }) => entry.did === reference.did).publication
        await expect(manager.retryPublication(reference)).rejects.toThrow()
        result = await manager.retryPublication(reference)
        const after = JSON.parse(await readFile(join(root, 'catalog-v1.json'), 'utf8')).entries.find((entry: { did: string }) => entry.did === reference.did).publication
        expect(after.operationId).toBe(before.operationId); expect(after.clientId).toBe(before.clientId)
        expect(dropPrepare || dropDocument).toBe(false)
      } else result = await manager.publishIdentity(publication)
      expect(result.state).toBe('published')
      expect(result.algorithm).toBe('ES256')
      expect(result.clientId).toContain('/agent-clients/' + configured.documentId + '/client.json')
      await expect(manager.retryPublication(reference)).resolves.toMatchObject({ state: 'published', clientId: result.clientId })
      if (profile === 'web') {
        stage = 'web:concurrent-document-conflict'
        const withNative = async <T>(runNative: (native: ProviderLease) => Promise<T>) => {
          const native = nativeRegistration.provider.acquireLease({ consumer: 'component-controller', capabilities: ['IDENTITY_READ', 'IDENTITY_DOCUMENT_UPDATE', 'IDENTITY_HTTP_SIGNATURE'], ttlSeconds: 60 })
          try { return await runNative(native) } finally { native.dispose() }
        }
        const driver = await createManagedPublicationDriver({ reference, origin: 'https://identity.example', credentials, fetch: transport, withNative })
        const pendingNative = nativeRegistration.provider.acquireLease({ consumer: 'component-candidate', capabilities: ['IDENTITY_READ', 'IDENTITY_DOCUMENT_UPDATE'], ttlSeconds: 60 })
        extraNative.push(pendingNative)
        const pending = await pendingNative.prepareDocumentChange(reference, { changes: [{ change: 'bind_oauth_client',
          clientId: result.clientId!, kid: result.keyId!, metadataSha256: 'f'.repeat(64) }] })
        const candidate = await pending.candidate()
        const base = candidate.baseEvidence
        const auth = (await credentials.get(reference, 'https://identity.example'))!
        const before = await driver.readVerifiedDocument()
        const remoteDocument = { ...(before.document as Record<string, unknown>), service: [
          ...((before.document as { service?: unknown[] }).service ?? []),
          { id: reference.did + '#concurrent-b', type: 'ExampleService', serviceEndpoint: 'https://resource.example/b' },
        ] }
        const params = { operation_id: randomUUID(), expected_document_version: before.evidence.documentVersion,
          expected_document_hash: before.evidence.documentDigest, expected_registry_version: before.evidence.registryVersion,
          authorizing_device_id: auth.deviceId, new_document: remoteDocument }
        const proof = await withNative(native => native.signManagementProof(reference, { key: { kid: auth.signingKeyId }, method: 'device_document_update',
          params: params as import('@agent-network-protocol/anp-identity').JsonValue, audience: auth.audience! }))
        const changed = await transport(new Request('https://identity.example/user-service/v1/did-auth/rpc', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + auth.accessToken },
          body: JSON.stringify({ jsonrpc: '2.0', id: randomUUID(), method: 'device_document_update', params: { ...params, authorizing_device_proof: proof } }) }))
        const changedEnvelope = await changed.json() as { error?: unknown; result?: { checkpoint?: { document_version: number } } }
        expect(changedEnvelope.error == null).toBe(true)
        expect(changedEnvelope.result?.checkpoint?.document_version).toBe(before.evidence.documentVersion + 1)
        await expect(driver.backend.publishDocument(reference, pending, async () => {})).rejects.toMatchObject({ code: 'catalog_conflict' })
        const after = await driver.readVerifiedDocument()
        expect(JSON.stringify(after.document)).toContain('#concurrent-b')
        expect(JSON.stringify(after.document)).not.toContain('f'.repeat(64))
        expect((await pending.candidate()).baseEvidence).toEqual(base)
        expect(await pending.hostPhase()).toBe('prepared')
      }
      configured.dispose()
    }
    await call({ action: 'close' }); await exited
  } catch (error) {
    // Only component stage and native/stable error code are surfaced; bridge credentials never enter assertion diffs.
    const code = (error as { code?: string }).code ?? (error instanceof Error ? error.message : 'unknown')
    if (code === 'management_bridge_exited') throw new Error(stage + ':' + code + ':' + diagnostics.replace(/Bearer\s+\S+/gu, 'Bearer [redacted]'))
    throw new Error(stage + ':' + code + ':' + lastFailure)
  } finally {
    if (child.exitCode === null) { child.stdin.end(); child.kill('SIGTERM') }
    await exited.catch(() => {}); extraNative.forEach(native => native.dispose()); await ctx.fiber.dispose(); key.fill(0); await rm(root, { recursive: true, force: true })
  }
}, 180000)


it.skipIf(!source || !python)('publishes a real PAP account and relays a callback for one original-device claim without replaying private data', async () => {
  const fixture = await createManagedCallbackFixture({ source: source!, python: python!, profile: 'web' })
  const state = randomBytes(32).toString('base64url')
  const claimSecret = randomBytes(32).toString('base64url')
  const transactionId = 'callback-' + randomUUID().replaceAll('-', '')
  const issuer = 'https://company.example'
  const code = randomBytes(32).toString('base64url')
  const callback = { transaction_id: transactionId, client_id: fixture.clientId, issuer,
    redirect_uri: fixture.origin + '/user-service/v1/pap-callback',
    state_sha256: createHash('sha256').update(state).digest('hex'), claim_sha256: createHash('sha256').update(claimSecret).digest('hex'),
    expires_at: new Date(Date.now() + 300000).toISOString().replace(/\.\d{3}Z$/u, 'Z') }
  try {
    const registered = await fixture.callbackManagement.execute({ action: 'pap-callback-register', operationId: 'register_' + transactionId, callback })
    expect(registered.callback_uri).toBe(callback.redirect_uri)
    const claim = () => fixture.callbackManagement.execute({ action: 'pap-callback-claim', operationId: 'claim_' + transactionId,
      callback: { transaction_id: transactionId, claim_secret: claimSecret } })
    await expect(claim()).rejects.toMatchObject({ code: 'callback_not_ready' })
    const wrong = await fixture.fetch(new Request(callback.redirect_uri + '?' + new URLSearchParams({ code, state, iss: 'https://other.example' })))
    expect(wrong.status).toBe(400)
    const response = await fixture.fetch(new Request(callback.redirect_uri + '?' + new URLSearchParams({ code, state, iss: issuer })))
    expect(response.status).toBe(200)
    const visible = await response.text()
    expect(visible.includes(code) || visible.includes(state)).toBe(false)
    const claimed = await claim()
    // Compare booleans so failed assertions do not print callback codes, state or pickup secrets.
    expect('code' in claimed && claimed.code === code && claimed.state === state && claimed.iss === issuer).toBe(true)
    await expect(claim()).rejects.toMatchObject({ code: 'callback_claimed' })
    const replay = await fixture.fetch(new Request(callback.redirect_uri + '?' + new URLSearchParams({ code, state, iss: issuer })))
    expect(replay.status).toBe(409)
    const capability = fixture.callbackManagement
    await fixture.dispose()
    await expect(capability.execute({ action: 'pap-callback-claim', operationId: 'claim_disposed', callback: { transaction_id: transactionId, claim_secret: claimSecret } })).rejects.toMatchObject({ code: 'provider_disposed' })
  } finally { await fixture.dispose() }
}, 180000)
