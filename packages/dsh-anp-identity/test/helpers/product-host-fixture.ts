/** Actual Loader product Host. Only B's external SMTP/Siteverify and module resolution are fixtures. */
import { Context } from '@deepseek-ai/cordis'
import Loader, { type EntryOptions } from '@deepseek-ai/cordis-plugin-loader'
import TypertRegistry from '@deepseek-ai/dsh-typert-registry'
import CredentialsLocal from '@deepseek-ai/dsh-credentials-local'
import type { IdentityReference, JsonValue } from '@agent-network-protocol/anp-identity'
import { createHash, randomUUID } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout } from 'node:timers/promises'
import AnpIdentityService from '../../src/index.js'
import * as NativeProvider from '../../src/provider.js'
import * as ProtocolBootstrap from '../../src/protocol-bootstrap.js'
import ManagerRemote from '../../src/management-remote.js'
import type { ProtocolUsePolicy } from '../../src/protocol-client.js'
import type { PublicationCapabilities } from '../../src/publication-types.js'
import type { RegistrationBootstrapStatus } from '../../src/registration-bootstrap.js'
import { strictBootstrapBridge } from './strict-bootstrap-bridge.js'

const MANAGER = '@agent-network-protocol/dsh-anp-identity/management-remote'
const PROVIDER = '@agent-network-protocol/dsh-anp-identity/provider'
const SERVICE = '@agent-network-protocol/dsh-anp-identity'
const CREDENTIALS = '@deepseek-ai/dsh-credentials-local'
type Entries = Array<Omit<EntryOptions, 'id'>>
export interface ProductHostFixtureOptions {
  source: string
  python: string
  /** Exact B fixture publisher origin; defaults to identity.example. */
  publicationOrigin?: string
  /** Actual native identity method; Web remains rootless. */
  profile?: 'e1' | 'web'
  /** Keep creation approval and independent user confirmation under the test's control. */
  manual?: boolean
  publicationCapabilities?: PublicationCapabilities
  redirectUris?: string[]
}
interface ReopenOptions {
  protocolPolicies?: ProtocolUsePolicy[]
  /** Actual module exports, resolved by the real Loader; protected C modules cannot be replaced. */
  modules?: Record<string, unknown>
  entries?: Entries
}
interface Gate {
  readonly entered: Promise<void>
  release(): void
}

async function until<T>(read: () => Promise<T> | T, accepts: (value: T) => boolean, timeout = 30000): Promise<T> {
  const deadline = Date.now() + timeout
  while (Date.now() < deadline) {
    const value = await read()
    if (accepts(value)) return value
    await setTimeout(50)
  }
  throw new Error('product_host_fixture_wait_timed_out')
}

/**
 * Create through actual C consent, B factor verification and publication. The
 * returned controller belongs to the test operator. Plugins receive only their
 * real installed Context and non-secret Loader config, never this controller,
 * a native lease, DeviceAccess, broker, mailbox or user-control handle.
 */
export async function createProductHostFixture(options: ProductHostFixtureOptions) {
  if (process.platform !== 'linux') throw new Error('product_host_fixture_requires_linux')
  const bridge = await strictBootstrapBridge(options.source, options.python,
    options.publicationOrigin === undefined ? {} : { publicationOrigin: options.publicationOrigin })
  let root: string
  try { root = await mkdtemp(join(tmpdir(), 'c-product-host-')) }
  catch (error) { await bridge.dispose(); throw error }
  const run = randomUUID().replaceAll('-', '')
  const handle = 'dsh-cimd-' + run
  const email = handle + '@example.com'
  const config = { id: 'fresh-email', requestId: 'fresh-protocol-' + run, stateRoot: join(root, 'bootstrap'),
    origin: bridge.origin, email, clientName: 'Actual product Host protocol identity', pollIntervalMs: 100,
    ...(options.publicationCapabilities ? { capabilities: options.publicationCapabilities } : {}),
    ...(options.redirectUris ? { redirectUris: options.redirectUris } : {}) }
  const profile = options.profile ?? 'e1'
  const creation = { requestId: config.requestId, label: 'Actual product protocol identity', profile, domain: 'identity.example',
    path: (profile === 'web' ? '/awiki/web/' : '/awiki/user/') + run, handle: handle + '.identity.example' }
  let context: Context | undefined
  let managerContext: Context | undefined
  let remote: ManagerRemote | undefined
  let reference: IdentityReference | undefined
  let materials: { metadata: string; jwks: string } | undefined
  let policyRefs: string[] = []
  let disposed = false
  let disposal: Promise<void> | undefined
  let held: { kind: 'email-status' | 'register-result'; gate: Gate; enter(): void; released: Promise<void>; used: boolean } | undefined
  const originalFetch = globalThis.fetch
  const transport: typeof fetch = async (input, init) => {
    const request = new Request(input, init)
    if (new URL(request.url).origin !== bridge.origin) return originalFetch(request)
    const reply = await bridge.fetch(request)
    const current = held
    if (!current || current.used) return reply
    const path = new URL(request.url).pathname
    const match = current.kind === 'email-status' ? request.method === 'GET' && path.endsWith('/auth/email-status')
      : request.method === 'POST' && path.endsWith('/did-auth/rpc') && bridge.facts.at(-1)?.rpc === 'register'
    if (!match) return reply
    current.used = true
    // Only HTTP delivery is deferred. B has already executed its real handler;
    // the caller has not received even the first response-body byte.
    const bytes = new Uint8Array(await reply.arrayBuffer())
    return new Response(new ReadableStream<Uint8Array>({ async start(controller) {
      current.enter()
      await current.released
      controller.enqueue(bytes); controller.close()
    } }), { status: reply.status, headers: reply.headers })
  }
  globalThis.fetch = transport

  const status = (): RegistrationBootstrapStatus => {
    if (!remote) throw new Error('product_host_fixture_manager_unavailable')
    const view = remote.registrationBootstrapStatus()[0]
    if (!view) throw new Error('product_host_fixture_bootstrap_unavailable')
    return view
  }
  const manager = () => {
    if (!managerContext) throw new Error('product_host_fixture_manager_unavailable')
    return (managerContext.get('anpIdentity') as AnpIdentityService).acquireManagement(managerContext)
  }
  const waitForPhase = (phase: RegistrationBootstrapStatus['phase']) => until(status, view => view.phase === phase)
  const start = async (reopen: ReopenOptions = {}, deniedRequest?: string) => {
    if (disposed) throw new Error('product_host_fixture_disposed')
    const current = context = new Context()
    await current.plugin(TypertRegistry)
    await current.plugin(Loader)
    const modules: Record<string, unknown> = {
      [SERVICE]: AnpIdentityService, [CREDENTIALS]: CredentialsLocal, [PROVIDER]: NativeProvider,
      [MANAGER]: ManagerRemote, [ProtocolBootstrap.PROTOCOL_BOOTSTRAP_CONSUMER]: ProtocolBootstrap,
    }
    for (const [name, module] of Object.entries(reopen.modules ?? {})) {
      if (Object.hasOwn(modules, name)) throw new Error('product_host_fixture_protected_module')
      modules[name] = module
    }
    // Module-resolution seam only. Entry/Fiber creation, injection, lifecycle,
    // current installation identity and all plugin execution remain real.
    current.loader.import = (specifier: string) => {
      if (!Object.hasOwn(modules, specifier)) throw new Error('product_host_fixture_unknown_module')
      return modules[specifier]
    }
    const policies = structuredClone(reopen.protocolPolicies ?? [])
    for (const policy of policies) {
      if (!reference || policy.identity.storeId !== reference.storeId || policy.identity.identityId !== reference.identityId
        || policy.identity.did !== reference.did) throw new Error('product_host_fixture_policy_identity_mismatch')
    }
    policyRefs = policies.map(policy => policy.id)
    const consumers = [...new Set([ProtocolBootstrap.PROTOCOL_BOOTSTRAP_CONSUMER, ...policies.map(policy => policy.consumer)])]
    await current.loader.create({ name: CREDENTIALS, config: { path: join(root, '.credentials.yaml'), watch: false } })
    await current.loader.create({ name: SERVICE, config: { stateRoot: join(root, 'identity'), allowConsumers: consumers, userConsumers: consumers, protocolPolicies: policies } })
    // Explicit A local-file custody inside the owned test root, not an OS
    // keyring claim or a fallback for management-broker credential records.
    await current.loader.create({ name: PROVIDER, config: { stateRoot: join(root, 'identity'), rootKeyProvider: 'local-file' } })
    await current.loader.await()
    await until(async () => (await (current.get('anpIdentity') as AnpIdentityService).health()).status, value => value === 'ready')
    await current.loader.create({ name: MANAGER, config: { registrationBootstrap: deniedRequest ? { ...config, id: 'denied-email', requestId: deniedRequest } : config } })
    await current.loader.create({ name: ProtocolBootstrap.PROTOCOL_BOOTSTRAP_CONSUMER,
      config: deniedRequest ? { ...creation, requestId: deniedRequest, path: creation.path + '-denied', handle: 'dsh-cimd-denied-' + run.slice(0, 20) + '.identity.example' } : creation })
    await current.loader.await()
    managerContext = [...current.loader.entries()].find(entry => entry.options.name === MANAGER)?.fiber?.ctx
    remote = current.get('anpIdentityManager') as ManagerRemote
    if (!managerContext || !remote) throw new Error('product_host_fixture_manager_missing')
  }
  const readPublished = async () => {
    const view = await waitForPhase('published')
    if (!view.reference || !view.clientId) throw new Error('product_host_fixture_publication_missing')
    reference = structuredClone(view.reference)
    const response = await bridge.fetch(view.clientId)
    if (response.status !== 200) throw new Error('product_host_fixture_metadata_unavailable')
    const metadata = await response.text()
    const parsed = JSON.parse(metadata) as { client_id?: string; jwks_uri?: string }
    if (parsed.client_id !== view.clientId || !parsed.jwks_uri) throw new Error('product_host_fixture_metadata_mismatch')
    const jwksResponse = await bridge.fetch(parsed.jwks_uri)
    if (jwksResponse.status !== 200) throw new Error('product_host_fixture_jwks_unavailable')
    materials = { metadata, jwks: await jwksResponse.text() }
    const document = await manager().publicDocument(reference) as { service?: Array<Record<string, unknown>> }
    const services = document.service?.filter(service => service.type === 'ANPCIMD')
    const digest = createHash('sha256').update(metadata).digest('hex')
    if (services?.length !== 1 || services[0]!.serviceEndpoint !== view.clientId || services[0]!.anp_metadata_sha256 !== digest) throw new Error('product_host_fixture_public_binding_mismatch')
  }
  const closeHost = async () => {
    held?.gate.release()
    const old = context; context = undefined; managerContext = undefined; remote = undefined
    await old?.fiber.dispose()
  }
  const dispose = () => disposal ??= (async () => {
    disposed = true
    try { await closeHost() }
    finally {
      if (globalThis.fetch === transport) globalThis.fetch = originalFetch
      try { await bridge.dispose() }
      finally { await rm(root, { recursive: true, force: true }) }
    }
  })()
  const userControl = {
    email,
    fullHandle: creation.handle,
    async review() { return await manager().getRequest(config.requestId) },
    async decide(decision: 'approve' | 'deny') {
      const review = await manager().getRequest(config.requestId)
      return await manager().decide({ requestId: review.request.id, expectedVersion: review.request.version, decision })
    },
    async confirmEmail(mode: 'valid' | 'invalid-email-token' = 'valid') { return await bridge.confirmEmail(email, mode) },
  }
  const approveAndConfirm = async () => {
    const review = await userControl.review()
    if (review.request.status === 'pending') await userControl.decide('approve')
    await waitForPhase('awaiting_email_verification')
    await until(() => bridge.facts.some(fact => fact.path.endsWith('/auth/email-send')), Boolean)
    if (!await userControl.confirmEmail()) throw new Error('product_host_fixture_user_confirmation_failed')
    await readPublished()
  }
  try {
    await start()
    const result = {
      root,
      origin: bridge.origin,
      get ctx(): Context { if (!context) throw new Error('product_host_fixture_disposed'); return context },
      get publicRef(): IdentityReference { if (!reference) throw new Error('product_host_fixture_not_published'); return structuredClone(reference) },
      get reference(): IdentityReference { if (!reference) throw new Error('product_host_fixture_not_published'); return structuredClone(reference) },
      get policyRef(): string { if (policyRefs.length !== 1) throw new Error('product_host_fixture_policy_not_selected'); return policyRefs[0]! },
      get publicMaterials() { if (!materials) throw new Error('product_host_fixture_not_published'); return { ...materials } },
      async publicDocument(): Promise<JsonValue> { if (!reference) throw new Error('product_host_fixture_not_published'); return await manager().publicDocument(reference) as JsonValue },
      status, waitForPhase, readPublished, approveAndConfirm, userControl,
      evidence: { facts: bridge.facts, observations: bridge.observations, cleanup: bridge.cleanup, excludesInternalCredentials: bridge.excludesInternalCredentials },
      requestForTest: bridge.fetch,
      async reopen(reopen: ReopenOptions = {}) {
        if (!reference) throw new Error('product_host_fixture_not_published')
        await closeHost(); await start(reopen); await readPublished()
        for (const entry of reopen.entries ?? []) await context!.loader.create(entry)
        await context!.loader.await()
        return context!
      },
      async denyFreshRequest() {
        if (!reference) throw new Error('product_host_fixture_not_published')
        await closeHost()
        const id = 'denied-protocol-' + run
        await start({}, id)
        const review = await manager().getRequest(id)
        await manager().decide({ requestId: id, expectedVersion: review.request.version, decision: 'deny' })
        return await waitForPhase('blocked')
      },
      holdNextResponse(kind: 'email-status' | 'register-result'): Gate {
        if (held && !held.used) throw new Error('product_host_fixture_gate_already_pending')
        let enter!: () => void; let release!: () => void
        const entered = new Promise<void>(resolve => { enter = resolve })
        const released = new Promise<void>(resolve => { release = resolve })
        const gate = { entered, release }
        held = { kind, gate, enter, released, used: false }
        return gate
      },
      async disableProvider() {
        const entry = [...context!.loader.entries()].find(value => value.options.name === PROVIDER)
        if (!entry) throw new Error('product_host_fixture_provider_entry_missing')
        await context!.loader.update(entry.id, { disabled: true })
      },
      dispose,
    }
    if (!options.manual) await approveAndConfirm()
    return result
  } catch (error) { await dispose(); throw error }
}
