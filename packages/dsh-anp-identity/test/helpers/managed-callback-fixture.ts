/** Actual C/A/B callback fixture. Only synthetic external email delivery and the local Store master are substituted. */
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { Context } from '@deepseek-ai/cordis'
import type { IdentityReference, JsonValue } from '@agent-network-protocol/anp-identity'
import { IdentityProvider } from '../../../../bindings/node/provider.js'
import AnpIdentityService from '../../src/index.js'
import type { NativeProviderRegistry } from '../../src/provider-api.js'
import type { CreateAuthorizationRequest } from '../../src/authorization-types.js'
import { EncryptedManagementCredentialBroker } from '../../src/management-credentials.js'
import type { PapCallbackManagementOperations } from '../../src/pap-callback.js'
import type { ProtocolIdentityClient, ProtocolUsePolicy } from '../../src/protocol-client.js'
import { exactHttps } from '../../src/publication-http.js'

interface CallbackFixtureOptions {
  source: string
  python: string
  profile?: 'e1' | 'web'
  publicationOrigin?: string
}
interface CallbackProtocolPolicy {
  consumer: string
  profiles: Array<'pap_session' | 'pap_account'>
  issuers: string[]
  resources: string[]
  scopes: string[]
}
interface CallbackFixture {
  callbackManagement: PapCallbackManagementOperations
  clientId: string
  origin: string
  fetch: typeof fetch
  reference: IdentityReference
  readonly publicMaterials: { metadata: string; jwks: string }
  publicDocument(): Promise<JsonValue>
  dispose(): Promise<void>
}
interface CallbackProtocolFixture extends CallbackFixture {
  context: Context
  client: ProtocolIdentityClient
  policyRef: string
}

function callbackOrigin(value: string): string {
  if (value === 'https://identity.example' || value === 'https://agent.test:29443') return value
  const port = /^https:\/\/localhost:([1-9][0-9]{0,4})$/u.exec(value)?.[1]
  if (!port || Number(port) > 65535) throw new Error('callback_fixture_origin_not_allowed')
  return value
}

/** Start actual registration/management/PAP publication and optionally install one explicit same-identity PAP consumer policy.
 * @param options - Owning B source, local identity method, allowed public origin and a complete optional Host policy.
 * @returns Restricted callback operations, original B public bytes and optional Context-bound PAP client; no provider, native lease or credential is returned.
 */
export function createManagedCallbackFixture(options: CallbackFixtureOptions & CallbackProtocolPolicy): Promise<CallbackProtocolFixture>
export function createManagedCallbackFixture(options: CallbackFixtureOptions): Promise<CallbackFixture>
export async function createManagedCallbackFixture(options: CallbackFixtureOptions & Partial<CallbackProtocolPolicy>): Promise<CallbackFixture | CallbackProtocolFixture> {
  const origin = callbackOrigin(options.publicationOrigin ?? 'https://identity.example')
  const policyRequested = ['consumer', 'profiles', 'issuers', 'resources', 'scopes'].some(key => Object.hasOwn(options, key))
  if (policyRequested && (!options.consumer || !options.profiles?.length || !options.issuers?.length || !options.resources?.length || !options.scopes?.length
    || new Set(options.profiles).size !== options.profiles.length || options.profiles.some(profile => profile !== 'pap_session' && profile !== 'pap_account')
    || new Set(options.scopes).size !== options.scopes.length || options.scopes.some(scope => !scope || /[\s\u0000-\u001f\u007f]/u.test(scope)))) throw new Error('callback_fixture_complete_pap_policy_required')
  options.issuers?.forEach(value => exactHttps(value)); options.resources?.forEach(value => exactHttps(value))
  const child = spawn(options.python, [join(options.source, 'tests/app/cimd/management_bridge.py')], { cwd: options.source,
    env: { ...process.env, CIMD_TEST_REAL_MANAGEMENT_BRIDGE: '1', CIMD_TEST_PUBLICATION_ORIGIN: origin, PYTHONPATH: join(options.source, 'src') }, stdio: ['pipe', 'pipe', 'pipe'] })
  type Reply = { status: number; headers: Record<string, string>; body: string }
  const queue: Array<{ resolve(value: Reply): void; reject(error: Error): void; timer: ReturnType<typeof setTimeout> }> = []
  let stopped = false
  const fail = () => { while (queue.length) { const pending = queue.shift()!; clearTimeout(pending.timer); pending.reject(new Error('callback_bridge_unavailable')) } }
  child.stderr.resume()
  child.stdin.on('error', fail)
  const exited = new Promise<void>((resolve, reject) => {
    child.once('error', () => { stopped = true; fail(); reject(new Error('callback_bridge_unavailable')) })
    child.once('exit', code => { stopped = true; fail(); code === 0 ? resolve() : reject(new Error('callback_bridge_unavailable')) })
  })
  void exited.catch(() => {})
  createInterface({ input: child.stdout }).on('line', line => {
    const pending = queue.shift()
    if (!pending) return
    clearTimeout(pending.timer)
    try { const reply = JSON.parse(line); if (reply.error) pending.reject(new Error('callback_bridge_unavailable')); else pending.resolve(reply) }
    catch { pending.reject(new Error('callback_bridge_unavailable')) }
  })
  const call = (value: unknown, timeoutMs = 15000) => new Promise<Reply>((resolve, reject) => {
    if (stopped) { reject(new Error('callback_bridge_unavailable')); return }
    const timer = setTimeout(() => { stopped = true; fail(); child.stdin.end(); child.kill('SIGTERM') }, timeoutMs)
    queue.push({ resolve, reject, timer })
    child.stdin.write(JSON.stringify(value) + '\n', error => { if (error) fail() })
  })
  const transport: typeof fetch = async (input, init) => {
    const request = new Request(input, init)
    if (new URL(request.url).origin !== origin) throw new Error('callback_fixture_origin_mismatch')
    const response = await call({ action: 'request', method: request.method, url: request.url,
      headers: Object.fromEntries(request.headers), body: request.body ? await request.text() : null })
    return new Response(response.body, { status: response.status, headers: response.headers })
  }
  const root = await mkdtemp(join(tmpdir(), 'c-b-callback-'))
  const encryptionKey = randomBytes(32)
  let context: Context | undefined
  let closeDriver: (() => void) | undefined
  let disposed = false
  const dispose = async () => {
    if (disposed) return
    disposed = true
    closeDriver?.(); closeDriver = undefined
    await context?.fiber.dispose().catch(() => {})
    if (!stopped) await call({ action: 'close' }, 30000).catch(() => {})
    child.stdin.end()
    let timer: ReturnType<typeof setTimeout> | undefined
    await Promise.race([exited.catch(() => {}), new Promise<void>(resolve => { timer = setTimeout(resolve, 30000) })])
    if (timer !== undefined) clearTimeout(timer)
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM')
    await exited.catch(() => {}); encryptionKey.fill(0)
    await rm(root, { recursive: true, force: true })
  }
  let stage = 'bridge-ready'
  try {
    // Readiness is an ordinary no-write 404, not a synthetic identity or owner bootstrap.
    await call({ action: 'request', method: 'GET', url: origin + '/__component_ready', headers: {}, body: null }, 120000)
    const nativeRoot = randomBytes(32)
    let provider: Awaited<ReturnType<typeof IdentityProvider.initialize>>
    try { provider = await IdentityProvider.initialize({ stateRoot: root, rootKeyKind: 'injected', keyId: 'callback-component', rootKey: nativeRoot }) }
    finally { nativeRoot.fill(0) }
    const startHost = async (policy?: ProtocolUsePolicy) => {
      const host = new Context()
      context = host
      const entries: Array<{ options: { name: string }; disabled: boolean; fiber: Context['fiber'] }> = []
      host.provide('loader', { *entries() { yield* entries } })
      await host.plugin(AnpIdentityService, { stateRoot: root, allowConsumers: ['@fixture/callback-creator', ...(policy ? [policy.consumer] : [])], userConsumers: policy ? [policy.consumer] : ['@fixture/callback-creator'], protocolPolicies: policy ? [policy] : [] })
      const service = host.anpIdentity as AnpIdentityService
      ;(service as unknown as NativeProviderRegistry).registerProvider({ protocol: 'anp-identity-node-provider/1', provider })
      await service.health()
      const installed = async (name: string) => {
        let installedContext!: Context
        await host.plugin(Object.assign((value: Context) => { installedContext = value }, { inject: ['anpIdentity'] }))
        entries.push({ options: { name }, disabled: false, fiber: installedContext.fiber }); return installedContext
      }
      return { host, installed }
    }
    stage = 'create-approved-identity'
    const initial = await startHost()
    const managementContext = await initial.installed('@agent-network-protocol/dsh-anp-identity/management-remote')
    const creatorContext = await initial.installed('@fixture/callback-creator')
    const managerService = managementContext.anpIdentity as AnpIdentityService
    const manager = managerService.acquireManagement(managementContext)
    const creator = (creatorContext.anpIdentity as AnpIdentityService).bindUserConsumer(creatorContext)
    const run = randomUUID().replaceAll('-', '')
    const profile = options.profile ?? 'web'
    const request = await creator.requestCreateIdentity({ requestId: 'create-callback', purpose: 'Create a registered PAP callback identity',
      parameters: { profile, usage: 'protocol', label: 'PAP callback', domain: 'identity.example', path: '/awiki/' + (profile === 'web' ? 'web/' : 'user/') + run } })
    const approved = await manager.decide({ requestId: request.id, expectedVersion: request.version, decision: 'approve' }) as CreateAuthorizationRequest
    if (!approved.result) throw new Error('callback_fixture_creation_failed')
    const reference = structuredClone(approved.result.reference)
    const credentials = new EncryptedManagementCredentialBroker(join(root, 'management'), async () => Buffer.from(encryptionKey))
    stage = 'real-registration'
    await managerService.registerLocalIdentity(managementContext, { reference, origin, credentials, fetch: transport, managementAudience: 'awiki-user-service', handleDomain: 'identity.example',
      registration: { handle: 'dsh-cimd-' + run, email: 'dsh-cimd-' + run + '@example.invalid', ...(profile === 'web' ? { registration_operation_id: randomUUID() } : {}) } })
    let driver = await managerService.configureManagedPublicationBackend(managementContext, 'callback', { reference, origin, credentials, fetch: transport })
    closeDriver = driver.dispose
    stage = 'real-pap-publication'
    const published = await manager.publishIdentity({ reference, config: { backend: 'callback', documentId: driver.documentId, clientName: 'PAP callback component',
      redirectUris: [origin + '/user-service/v1/pap-callback'], activeKid: reference.did + '#oauth', capabilities: { mcpMachine: false, papSession: true, papAccount: true } } })
    if (published.state !== 'published' || !published.clientId || !published.jwksUri) throw new Error('callback_fixture_publication_failed')
    const readBytes = async (url: string) => {
      const response = await transport(new Request(url, { redirect: 'manual' }))
      if (response.status !== 200 || response.redirected || !(response.headers.get('content-type') ?? '').startsWith('application/json')) throw new Error('callback_fixture_public_readback_failed')
      return await response.text()
    }
    stage = 'raw-b-readback'
    const [metadata, jwks] = await Promise.all([readBytes(published.clientId), readBytes(published.jwksUri)])
    const material = JSON.parse(metadata)
    if (material.client_id !== published.clientId || material.jwks_uri !== published.jwksUri || material.token_endpoint_auth_method !== 'private_key_jwt'
      || material.token_endpoint_auth_signing_alg !== 'ES256' || JSON.stringify(material.grant_types) !== '["authorization_code","refresh_token"]'
      || JSON.stringify(material.response_types) !== '["code"]' || JSON.stringify(material.redirect_uris) !== JSON.stringify([origin + '/user-service/v1/pap-callback'])) throw new Error('callback_fixture_public_material_mismatch')
    const publicDocument = async (): Promise<JsonValue> => {
      if (disposed) throw new Error('callback_fixture_disposed')
      const native = provider.acquireLease({ consumer: 'callback-public-read', capabilities: ['IDENTITY_READ'], ttlSeconds: 60 })
      try {
        const document = (await native.publicIdentity(reference)).document
        const services = (document as { service?: Array<Record<string, unknown>> }).service?.filter(service => service.type === 'ANPCIMD') ?? []
        if (services.length !== 1 || services[0]!.serviceEndpoint !== published.clientId || services[0]!.anp_metadata_sha256 !== createHash('sha256').update(metadata).digest('hex')) throw new Error('callback_fixture_public_binding_mismatch')
        return structuredClone(document)
      } finally { native.dispose() }
    }
    await publicDocument()
    let protocol: { context: Context; client: ProtocolIdentityClient; policyRef: string } | undefined
    if (policyRequested) {
      stage = 'dispose-initial-management'
      closeDriver(); closeDriver = undefined
      await initial.host.fiber.dispose()
      const policyRef = 'registered-pap-callback-policy'
      const policy: ProtocolUsePolicy = { id: policyRef, version: 1, owner: '@agent-network-protocol/dsh-anp-identity', identity: reference,
        consumer: options.consumer!, profiles: [...options.profiles!], issuers: [...options.issuers!], resources: [...options.resources!], publicTargets: false, scopes: [...options.scopes!], expiresAt: Date.now() + 3600000 }
      stage = 'reopen-explicit-pap-policy'
      const reopened = await startHost(policy)
      const consumerContext = await reopened.installed(policy.consumer)
      const client = (consumerContext.anpIdentity as AnpIdentityService).bindProtocolConsumer(consumerContext)
      const managerContext = await reopened.installed('@agent-network-protocol/dsh-anp-identity/management-remote')
      const service = managerContext.anpIdentity as AnpIdentityService
      stage = 'rebuild-callback-driver'
      const replacement = await service.configureManagedPublicationBackend(managerContext, 'callback-reopened', { reference, origin, credentials, fetch: transport })
      if (replacement.documentId !== driver.documentId) { replacement.dispose(); throw new Error('callback_fixture_document_changed') }
      driver = replacement; closeDriver = replacement.dispose
      protocol = { context: consumerContext, client, policyRef }
    }
    const result: CallbackFixture = { callbackManagement: driver.callbackManagement, clientId: published.clientId, origin, fetch: transport, reference,
      get publicMaterials() { return { metadata, jwks } }, publicDocument, dispose }
    return protocol ? { ...result, ...protocol } : result
  } catch (error) {
    const rawCode = (error as { code?: unknown } | null)?.code
    const code = typeof rawCode === 'string' && /^[a-zA-Z0-9_:-]{1,64}$/u.test(rawCode) ? rawCode : 'unclassified'
    await dispose()
    throw new Error('callback_fixture_failed:' + stage + ':' + code)
  }
}
