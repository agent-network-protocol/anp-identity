/** Real C approval/native custody -> B registration/publication -> Context-bound machine consumer.
 * B owns production authority and raw public bytes. Only SMTP delivery and the local Store master are fixtures.
 */
import { spawn } from 'node:child_process'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { Context } from '@deepseek-ai/cordis'
import type { IdentityReference, JsonValue } from '@agent-network-protocol/anp-identity'
import { IdentityProvider } from '../../../../bindings/node/provider.js'
import AnpIdentityService from '../../src/index.js'
import type { CreateAuthorizationRequest } from '../../src/authorization-types.js'
import { EncryptedManagementCredentialBroker } from '../../src/management-credentials.js'
import type { NativeProviderRegistry } from '../../src/provider-api.js'
import type { ProtocolIdentityClient, ProtocolUsePolicy } from '../../src/protocol-client.js'
import { exactHttps } from '../../src/publication-http.js'
import type { OAuthClientIdentity, PublicationCapabilities } from '../../src/publication-types.js'

interface RegisteredProtocolFixtureOptions {
  publicationOrigin: string
  source?: string
  python?: string
  profile?: 'e1' | 'web'
  consumer?: string
  profiles?: ProtocolUsePolicy['profiles']
  scopes?: string[]
  issuers: string[]
  resources: string[]
  /** Compatibility input: this fixture deliberately supports machine-only publication. */
  publicationCapabilities?: PublicationCapabilities
  redirectUris?: string[]
}
interface PublicationSnapshot {
  version: number
  keyId: string
  metadataSha256: string
  jwksSha256: string
}
interface RotationResult extends PublicationSnapshot { previous: PublicationSnapshot }
interface BridgeHttpReply { status: number; headers: Record<string, string>; body: string }
interface PendingReply {
  resolve(value: unknown): void
  reject(error: Error): void
  timer: ReturnType<typeof setTimeout>
}

function publicationOrigin(value: string): string {
  if (value === 'https://identity.example') return value
  const port = /^https:\/\/localhost:([1-9][0-9]{0,4})$/u.exec(value)?.[1]
  if (!port || Number(port) > 65535) throw new Error('registered_protocol_invalid_publication_origin')
  return value
}

/** Create an approved registered native identity, publish B's machine-only bytes, then install its Host policy.
 * @param options - Already-bound TLS origin and consumer/issuer/resource/scope ceiling; source/environment are explicit or use the owning test environment variables.
 * @returns Only the real Context-bound client, public reference/materials/document and teardown. No native lease, Agent key or management credential escapes.
 */
export async function createRegisteredProtocolFixture(options: RegisteredProtocolFixtureOptions): Promise<{
  context: Context
  client: ProtocolIdentityClient
  reference: IdentityReference
  policyRef: string
  readonly publicMaterials: { metadata: string; jwks: string }
  publicDocument(): Promise<JsonValue>
  /** Publish a fresh same-DID key through actual C/B management; never changes the protocol Context. */
  rotateOAuthKey(): Promise<RotationResult>
  /** Close the real C provider registration/leases, not the underlying Store or OS keyring. */
  closeRegisteredProvider(): Promise<{ closed: 'c-native-provider-registration'; storeLocked: false }>
  provenance: { publisher: 'user-service'; registration: 'production-command'; publication: 'prepare-bind-activate-readback'; machineOnly: true; metadataSha256: string; jwksSha256: string }
  dispose(): Promise<void>
}> {
  const origin = publicationOrigin(options.publicationOrigin)
  const source = options.source ?? process.env.DSH_IDENTITY_USER_SERVICE_SOURCE
  const python = options.python ?? process.env.DSH_IDENTITY_PYTHON
  if (!source || !python) throw new Error('registered_protocol_explicit_b_environment_required')
  const profiles = options.profiles ?? ['mcp_machine']
  const capabilities = options.publicationCapabilities ?? { mcpMachine: true, papSession: false, papAccount: false }
  if (profiles.length !== 1 || profiles[0] !== 'mcp_machine' || !capabilities.mcpMachine || capabilities.papSession || capabilities.papAccount
    || (options.redirectUris?.length ?? 0) !== 0) throw new Error('registered_protocol_requires_machine_only')
  const consumer = options.consumer ?? '@deepseek-ai/dsh-mcp-client'
  const issuers = [...options.issuers], resources = [...options.resources]
  const scopes = [...(options.scopes ?? ['agent.self.read', 'catalog.read'])]
  if (!consumer || !issuers.length || !resources.length || !scopes.length || new Set(scopes).size !== scopes.length
    || scopes.some(scope => !scope || /[\s\u0000-\u001f\u007f]/u.test(scope))) throw new Error('registered_protocol_invalid_policy')
  issuers.forEach(value => exactHttps(value)); resources.forEach(value => exactHttps(value))
  const profile = options.profile ?? 'e1'
  const child = spawn(python, [join(source, 'tests/app/cimd/management_bridge.py')], { cwd: source,
    env: { ...process.env, CIMD_TEST_REAL_MANAGEMENT_BRIDGE: '1', CIMD_TEST_PUBLICATION_ORIGIN: origin, PYTHONPATH: join(source, 'src') }, stdio: ['pipe', 'pipe', 'pipe'] })
  const queue: PendingReply[] = []
  let stopped = false
  const fail = () => { while (queue.length) { const item = queue.shift()!; clearTimeout(item.timer); item.reject(new Error('registered_protocol_bridge_unavailable')) } }
  child.stderr.resume()
  child.stdin.on('error', fail)
  const exited = new Promise<void>((resolve, reject) => {
    child.once('error', () => { stopped = true; fail(); reject(new Error('registered_protocol_bridge_unavailable')) })
    child.once('exit', code => { stopped = true; fail(); code === 0 ? resolve() : reject(new Error('registered_protocol_bridge_unavailable')) })
  })
  void exited.catch(() => {})
  createInterface({ input: child.stdout }).on('line', line => {
    const pending = queue.shift()
    if (!pending) return
    clearTimeout(pending.timer)
    try { const value = JSON.parse(line); if (value.error) pending.reject(new Error('registered_protocol_bridge_unavailable')); else pending.resolve(value) }
    catch { pending.reject(new Error('registered_protocol_bridge_unavailable')) }
  })
  const call = (value: unknown, timeoutMs = 15000) => new Promise<unknown>((resolve, reject) => {
    if (stopped) { reject(new Error('registered_protocol_bridge_unavailable')); return }
    const timer = setTimeout(() => { stopped = true; fail(); child.stdin.end(); child.kill('SIGTERM') }, timeoutMs)
    queue.push({ resolve, reject, timer })
    child.stdin.write(JSON.stringify(value) + '\n', error => { if (error) fail() })
  })
  const transport: typeof fetch = async (input, init) => {
    const request = new Request(input, init)
    if (new URL(request.url).origin !== origin) throw new Error('registered_protocol_bridge_origin_mismatch')
    const raw = await call({ action: 'request', method: request.method, url: request.url,
      headers: Object.fromEntries(request.headers), body: request.body ? await request.text() : null })
    const reply = raw as BridgeHttpReply
    if (!Number.isInteger(reply.status) || typeof reply.body !== 'string' || !reply.headers) throw new Error('registered_protocol_invalid_bridge_reply')
    return new Response(reply.body, { status: reply.status, headers: reply.headers })
  }
  const root = await mkdtemp(join(tmpdir(), 'c-b-registered-protocol-'))
  const encryptionKey = randomBytes(32)
  let context: Context | undefined
  let closeBackend: (() => void) | undefined
  let disposed = false
  const dispose = async () => {
    if (disposed) return
    disposed = true
    closeBackend?.(); closeBackend = undefined
    await context?.fiber.dispose().catch(() => {})
    if (!stopped) await call({ action: 'close' }, 30000).catch(() => {})
    child.stdin.end()
    let timer: ReturnType<typeof setTimeout> | undefined
    await Promise.race([exited.catch(() => {}), new Promise<void>(resolve => { timer = setTimeout(resolve, 30000) })])
    if (timer !== undefined) clearTimeout(timer)
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM')
    await exited.catch(() => {})
    encryptionKey.fill(0)
    await rm(root, { recursive: true, force: true })
  }
  let stage = 'bridge-ready'
  try {
    // An ordinary read-only 404 waits for private MySQL, not a synthetic authority bootstrap.
    await call({ action: 'request', method: 'GET', url: origin + '/__component_ready', headers: {}, body: null }, 120000)
    const nativeRoot = randomBytes(32)
    let provider: Awaited<ReturnType<typeof IdentityProvider.initialize>>
    try { provider = await IdentityProvider.initialize({ stateRoot: root, rootKeyKind: 'injected', keyId: 'registered-protocol-component', rootKey: nativeRoot }) }
    finally { nativeRoot.fill(0) }
    const startHost = async (policy?: ProtocolUsePolicy) => {
      const host = new Context()
      context = host
      const entries: Array<{ options: { name: string }; disabled: boolean; fiber: Context['fiber'] }> = []
      host.provide('loader', { *entries() { yield* entries } })
      await host.plugin(AnpIdentityService, { stateRoot: root, allowConsumers: [consumer, '@fixture/registered-creator'], userConsumers: policy ? [consumer] : ['@fixture/registered-creator'], protocolPolicies: policy ? [policy] : [] })
      const service = host.anpIdentity as AnpIdentityService
      const unregisterProvider = (service as unknown as NativeProviderRegistry).registerProvider({ protocol: 'anp-identity-node-provider/1', provider })
      await service.health()
      const install = async (name: string) => {
        let installed!: Context
        await host.plugin(Object.assign((value: Context) => { installed = value }, { inject: ['anpIdentity'] }))
        entries.push({ options: { name }, disabled: false, fiber: installed.fiber }); return installed
      }
      return { host, install, unregisterProvider }
    }
    stage = 'management-approval'
    const initial = await startHost()
    const managerContext = await initial.install('@agent-network-protocol/dsh-anp-identity/management-remote')
    const creatorContext = await initial.install('@fixture/registered-creator')
    const managerService = managerContext.anpIdentity as AnpIdentityService
    const manager = managerService.acquireManagement(managerContext)
    const creator = (creatorContext.anpIdentity as AnpIdentityService).bindUserConsumer(creatorContext)
    const run = randomUUID().replaceAll('-', '')
    const requested = await creator.requestCreateIdentity({ requestId: 'create-registered-protocol', purpose: 'Create a registered machine protocol identity',
      parameters: { profile, usage: 'protocol', label: 'Registered machine component', domain: 'identity.example', path: '/awiki/' + (profile === 'web' ? 'web/' : 'user/') + run } })
    const approved = await manager.decide({ requestId: requested.id, expectedVersion: requested.version, decision: 'approve' }) as CreateAuthorizationRequest
    if (!approved.result) throw new Error('registered_protocol_creation_not_approved')
    const reference = structuredClone(approved.result.reference)
    stage = 'real-registration'
    const credentials = new EncryptedManagementCredentialBroker(join(root, 'management'), async () => Buffer.from(encryptionKey))
    await managerService.registerLocalIdentity(managerContext, { reference, origin, credentials, fetch: transport, managementAudience: 'awiki-user-service', handleDomain: 'identity.example',
      registration: { handle: 'dsh-cimd-' + run, email: 'dsh-cimd-' + run + '@example.invalid', ...(profile === 'web' ? { registration_operation_id: randomUUID() } : {}) } })
    const backend = await managerService.configureManagedPublicationBackend(managerContext, 'registered-machine', { reference, origin, credentials, fetch: transport })
    closeBackend = backend.dispose
    stage = 'real-publication'
    let published = await manager.publishIdentity({ reference, config: { backend: 'registered-machine', documentId: backend.documentId, clientName: 'Registered machine component', redirectUris: [], activeKid: reference.did + '#oauth', capabilities: { mcpMachine: true, papSession: false, papAccount: false } } })
    if (published.state !== 'published' || !published.clientId || !published.jwksUri || published.algorithm !== 'ES256') throw new Error('registered_protocol_not_published')
    stage = 'raw-b-readback'
    const readBytes = async (url: string) => {
      const response = await transport(new Request(url, { redirect: 'manual' }))
      if (response.status !== 200 || response.redirected || !(response.headers.get('content-type') ?? '').startsWith('application/json')) throw new Error('registered_protocol_public_readback_failed')
      return await response.text()
    }
    const readMaterials = async (current: OAuthClientIdentity) => {
      if (current.state !== 'published' || !current.clientId || !current.jwksUri || current.algorithm !== 'ES256'
        || !Number.isSafeInteger(current.version) || !current.version || !current.keyId) throw new Error('registered_protocol_not_published')
      const [metadata, jwks] = await Promise.all([readBytes(current.clientId), readBytes(current.jwksUri)])
      const publicMetadata = JSON.parse(metadata)
      const publicJwks = JSON.parse(jwks)
      if (publicMetadata.client_id !== current.clientId || new URL(publicMetadata.client_id).origin !== origin
        || publicMetadata.jwks_uri !== current.jwksUri || JSON.stringify(publicMetadata.grant_types) !== '["client_credentials"]'
        || JSON.stringify(publicMetadata.response_types) !== '[]' || JSON.stringify(publicMetadata.redirect_uris) !== '[]'
        || publicMetadata.token_endpoint_auth_method !== 'private_key_jwt' || publicMetadata.token_endpoint_auth_signing_alg !== 'ES256'
        || publicJwks.keys?.length !== 1 || publicJwks.keys[0]?.kid !== current.keyId) throw new Error('registered_protocol_public_material_mismatch')
      return { metadata, jwks }
    }
    let { metadata, jwks } = await readMaterials(published)
    const sha = (value: string) => createHash('sha256').update(value).digest('hex')
    const readNativeDocument = async (current: OAuthClientIdentity, metadataBytes: string): Promise<JsonValue> => {
      if (disposed) throw new Error('registered_protocol_fixture_disposed')
      const lease = provider.acquireLease({ consumer: 'registered-public-read', capabilities: ['IDENTITY_READ'], ttlSeconds: 60 })
      try {
        const document = (await lease.publicIdentity(reference)).document
        const services = (document as { service?: Array<Record<string, unknown>> }).service?.filter(value => value.type === 'ANPCIMD') ?? []
        if (services.length !== 1 || services[0]!.serviceEndpoint !== current.clientId || services[0]!.anp_metadata_sha256 !== sha(metadataBytes)) throw new Error('registered_protocol_public_binding_mismatch')
        return structuredClone(document)
      } finally { lease.dispose() }
    }
    const publicDocument = () => readNativeDocument(published, metadata)
    await publicDocument()
    stage = 'explicit-policy-reopen'
    stage = 'dispose-initial-backend'
    closeBackend(); closeBackend = undefined
    stage = 'dispose-initial-host'
    await initial.host.fiber.dispose()
    const policyRef = 'registered-machine-policy'
    const policy: ProtocolUsePolicy = { id: policyRef, version: 1, consumer, owner: '@agent-network-protocol/dsh-anp-identity', identity: reference, profiles: ['mcp_machine'], issuers, resources, publicTargets: false, scopes, expiresAt: Date.now() + 3600000 }
    stage = 'reopen-host-policy'
    const reopened = await startHost(policy)
    stage = 'install-protocol-consumer'
    const consumerContext = await reopened.install(consumer)
    stage = 'bind-protocol-client'
    const client = (consumerContext.anpIdentity as AnpIdentityService).bindProtocolConsumer(consumerContext)
    const snapshot = (): PublicationSnapshot => ({ version: published.version!, keyId: published.keyId!, metadataSha256: sha(metadata), jwksSha256: sha(jwks) })
    let rotationCount = 0
    let rotating = false
    let pendingRotation: { keyId: string; previous: PublicationSnapshot } | undefined
    let rotationManagement: { service: AnpIdentityService; context: Context; backend: string; documentId: string } | undefined
    const rotateOAuthKey = async (): Promise<RotationResult> => {
      if (disposed || rotating) throw new Error('registered_protocol_rotation_unavailable')
      rotating = true
      try {
        if (!rotationManagement) {
          const managementContext = await reopened.install('@agent-network-protocol/dsh-anp-identity/management-remote')
          const service = managementContext.anpIdentity as AnpIdentityService
          const configured = await service.configureManagedPublicationBackend(managementContext, 'registered-rotation', { reference, origin, credentials, fetch: transport })
          if (configured.documentId !== backend.documentId) { configured.dispose(); throw new Error('registered_protocol_document_changed') }
          closeBackend = configured.dispose
          rotationManagement = { service, context: managementContext, backend: 'registered-rotation', documentId: configured.documentId }
        }
        pendingRotation ??= { keyId: reference.did + '#oauth-rotation-' + (rotationCount + 1), previous: snapshot() }
        const pending = pendingRotation
        const next = await rotationManagement.service.acquireManagement(rotationManagement.context).publishIdentity({ reference, config: {
          backend: rotationManagement.backend, documentId: rotationManagement.documentId, clientName: 'Registered machine component',
          redirectUris: [], activeKid: pending.keyId, capabilities: { mcpMachine: true, papSession: false, papAccount: false },
        } })
        if (next.clientId !== published.clientId || !next.version || next.version <= pending.previous.version || next.keyId !== pending.keyId) throw new Error('registered_protocol_rotation_mismatch')
        const latest = await readMaterials(next)
        await readNativeDocument(next, latest.metadata)
        // Replace only after real activation and raw readback. Existing caller snapshots remain unchanged.
        published = next; metadata = latest.metadata; jwks = latest.jwks
        rotationCount += 1; pendingRotation = undefined
        return { ...snapshot(), previous: { ...pending.previous } }
      } catch (error) {
        const rawCode = (error as { code?: unknown } | null)?.code
        const code = typeof rawCode === 'string' && /^[a-zA-Z0-9_:-]{1,64}$/u.test(rawCode) ? rawCode : 'unclassified'
        throw new Error('registered_protocol_rotation_failed:' + code)
      } finally { rotating = false }
    }
    const closeRegisteredProvider = async () => {
      if (disposed || rotating) throw new Error('registered_protocol_close_unavailable')
      await reopened.unregisterProvider()
      return { closed: 'c-native-provider-registration' as const, storeLocked: false as const }
    }
    return { context: consumerContext, client, reference, policyRef,
      get publicMaterials() { return { metadata, jwks } }, publicDocument, rotateOAuthKey, closeRegisteredProvider,
      get provenance() { return { publisher: 'user-service' as const, registration: 'production-command' as const, publication: 'prepare-bind-activate-readback' as const, machineOnly: true as const, metadataSha256: sha(metadata), jwksSha256: sha(jwks) } }, dispose }
  } catch (error) {
    const rawCode = (error as { code?: unknown } | null)?.code
    const code = typeof rawCode === 'string' && /^[a-zA-Z0-9_:-]{1,64}$/u.test(rawCode) ? rawCode : 'unclassified'
    await dispose()
    throw new Error('registered_protocol_fixture_failed:' + stage + ':' + code)
  }
}
