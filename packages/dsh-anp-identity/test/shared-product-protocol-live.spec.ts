/** One current Host/reference: actual F NoAS first, F disposal, then actual Agent MCP and real expiry. */
import type { Context } from '@deepseek-ai/cordis'
import type { RequestListener } from 'node:http'
import type { Server } from 'node:https'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { setTimeout } from 'node:timers/promises'
import { expect, it, vi } from 'vitest'
import type { ProtocolUsePolicy } from '../src/protocol-client.js'
import { createProductHostFixture } from './helpers/product-host-fixture.js'

const network = vi.hoisted(() => ({ send: undefined as typeof fetch | undefined }))
vi.mock('../../../../deepseek-harness/packages/mcp/mcp-client/src/machine-http.ts', async original => {
  const actual = await original<Record<string, unknown>>()
  return { ...actual, machineFetch: (input: string | URL | Request, init?: RequestInit) => {
    if (!network.send) throw new Error('shared_product_transport_not_ready')
    return network.send(input, init)
  } }
})

const bSource = process.env.DSH_IDENTITY_USER_SERVICE_SOURCE
const python = process.env.DSH_IDENTITY_PYTHON
const hSource = process.env.DSH_MCP_PRODUCT_HARNESS_SOURCE
const eSource = process.env.DSH_MCP_PRODUCT_AS_SOURCE
const fSource = process.env.DSH_SHARED_PRODUCT_F_SOURCE
const MCP = '@deepseek-ai/dsh-mcp-client'
const F_PLUGIN = '@agentconnect/dsh-pap/plugin', F_MANAGER = '@agentconnect/dsh-pap/management-remote', F_TOOLS = '@agentconnect/dsh-pap/tools'
const load = (root: string, file: string): Promise<unknown> => import(/* @vite-ignore */ pathToFileURL(join(root, file)).href)
const hash = async (file: string) => createHash('sha256').update(await readFile(file)).digest('hex')
interface Pool { query(sql: string): Promise<{ rows: Array<Record<string, unknown>> }>; end(): Promise<void> }
interface Store { configureRequestLimits(value: object): Promise<unknown>; configurePolicy(value: object): Promise<unknown>; provisionResourceServer(id: string, secret: string, resources: string[]): Promise<unknown> }
interface Tls { cert: string; fetcher(): unknown; start(handler: RequestListener, host?: string): Promise<{ origin: string; server: Server }>; close(): Promise<void> }
interface Agent { ctx: Context }
interface AgentHandle { agent: Agent; dispose(): Promise<void> }
interface ToolRuntime { schemas(agent?: Agent): Array<{ name: string }>; execute(value: object): Promise<{ isError: boolean; value?: unknown; content: Array<{ type: string; text?: string }> }> }
interface Runtime extends Context { agents: { create(value: { sessionId: string; setup(context: Context): Promise<void> }): Promise<AgentHandle> }; tools: ToolRuntime }
interface PublicResult { ok: boolean; value?: unknown }
interface FManager { status(): Promise<PublicResult>; manage(value: object): Promise<PublicResult>; operations(): Promise<PublicResult> }
interface RawTarget { assertActive(): Promise<void> }
interface PapInternals { stop(): void; client?: { options: { identityHost: { rawLeases: Set<RawTarget> } } } }
interface Sidecar { binDirectory: string; stop(): Promise<unknown> }
interface NoAsVerifier { handler: RequestListener; observations: { requests: number; publicRequests: number; publicUnauthenticated: boolean }; uniqueRequestProofs(): number }

async function sourceHashes(): Promise<Record<string, string>> {
  const paths: Array<[string, string]> = []
  for (const [label, root, folder] of [['D', hSource!, 'packages/mcp/mcp-client/src'], ['F', fSource!, 'src']] as const) {
    for (const file of (await readdir(join(root, folder), { recursive: true })).filter(name => name.endsWith('.ts') && !name.startsWith('client/')).sort()) paths.push([label + '/' + file, join(root, folder, file)])
  }
  for (const name of ['index.ts', 'registration-bootstrap.ts', 'management-driver.ts', 'protocol-bootstrap.ts', 'target-policy.ts', 'provider.ts', 'installed-consumer.ts', 'host-management-secret.ts']) paths.push(['C/' + name, new URL('../src/' + name, import.meta.url).pathname])
  for (const name of ['helpers/product-host-fixture.ts', 'helpers/strict-bootstrap-bridge.ts', 'shared-product-protocol-live.spec.ts']) paths.push(['fixture/' + name, new URL(name, import.meta.url).pathname])
  for (const name of ['scripts/helpers/no-as-product-verifier.ts', 'scripts/helpers/secret-service-sidecar.ts']) paths.push(['F-fixture/' + name, join(fSource!, name)])
  for (const name of ['packages/oauth-as/app.ts', 'packages/oauth-core/client.ts', 'packages/oauth-rs/index.ts', 'packages/store-postgres/store.ts', 'examples/minimal-mcp-server/app.ts', 'tests/helpers.ts']) paths.push(['E/' + name, join(eSource!, name)])
  paths.push(['native', new URL('../../../bindings/node/anp-identity.linux-x64-gnu.node', import.meta.url).pathname])
  return Object.fromEntries(await Promise.all(paths.map(async ([name, path]) => [name, await hash(path)])))
}

it.skipIf(process.platform !== 'linux' || !bSource || !python || !hSource || !eSource || !fSource || !process.env.DATABASE_URL)(
  'P01/P28 current Host closes actual F before first MCP client and obtains a new CC after real expiry', async () => {
    expect(process.env.NODE_ENV).toBe('test')
    const database = new URL(process.env.DATABASE_URL!)
    const pgSocket = database.searchParams.get('host')
    expect(database.hostname).toBe(''); expect(database.pathname).toBe('/cimd_component')
    expect(pgSocket).toMatch(/^\/tmp\/cimd-pg\.[^/]+\/socket$/u)
    const before = await sourceHashes()
    expect(before.native).toBe('ffb6c3a6ee7bcd5592184db57c865d0a90748a6379636ca203a5ad42012718b9')
    const pg = await load(eSource!, 'node_modules/pg/lib/index.js') as { default: { Pool: new (value: object) => Pool } }
    const pool = new pg.default.Pool({ connectionString: process.env.DATABASE_URL, max: 8 })
    const { tlsFixture } = await load(eSource!, 'tests/helpers.ts') as { tlsFixture(): Promise<Tls> }
    const { PostgresStore } = await load(eSource!, 'packages/store-postgres/store.ts') as { PostgresStore: new (pool: Pool, issuer: string) => Store }
    const { ClientAuthenticator } = await load(eSource!, 'packages/oauth-core/client.ts') as { ClientAuthenticator: new (fetcher: unknown, issuer: string) => unknown }
    const { createAuthorizationServer } = await load(eSource!, 'packages/oauth-as/app.ts') as { createAuthorizationServer(store: Store, authenticator: unknown, scopes: string[]): RequestListener }
    const { TokenVerifier } = await load(eSource!, 'packages/oauth-rs/index.ts') as { TokenVerifier: new (fetcher: unknown, config: object) => unknown }
    const { createMcpApp } = await load(eSource!, 'examples/minimal-mcp-server/app.ts') as { createMcpApp(verifier: unknown): RequestListener }
    const FPlugin = await load(fSource!, 'src/plugin.ts')
    const { default: FManagerModule } = await load(fSource!, 'src/management-remote.ts') as { default: unknown }
    const FTools = await load(fSource!, 'src/tools.ts')
    const { SafeHttpsTransport } = await load(fSource!, 'src/network.ts') as { SafeHttpsTransport: new (options: object) => unknown }
    const { KeyringSecretStore } = await load(fSource!, 'src/keyring.ts') as { KeyringSecretStore: new (service: string, root: string) => { getEncryptionKey(namespace: string): Promise<Buffer | undefined> } }
    const { createSecretServiceSidecar } = await load(fSource!, 'scripts/helpers/secret-service-sidecar.ts') as { createSecretServiceSidecar(): Promise<Sidecar> }
    const { createNoAsProductVerifier } = await load(fSource!, 'scripts/helpers/no-as-product-verifier.ts') as { createNoAsProductVerifier(options: object): NoAsVerifier }
    const Mcp = await load(hSource!, 'packages/mcp/mcp-client/src/index.ts')
    const { default: Management } = await load(hSource!, 'packages/mcp/mcp-client/src/management.ts') as { default: unknown }
    const { default: ManagementRemote } = await load(hSource!, 'packages/mcp/mcp-client/src/management-remote.ts') as { default: unknown }
    const { createTestMachineFetch } = await load(hSource!, 'packages/mcp/mcp-client/src/machine-http.ts') as { createTestMachineFetch(options: { origin: string; ca: string }): typeof fetch }
    const { mountPreset } = await load(hSource!, 'packages/preset/agent-presets/src/mount.ts') as { mountPreset(ctx: Context, preset: { id: string; trust: 'system'; path: string }): Promise<void> }
    const kit = await load(hSource!, 'packages/test-support/agent-loop-testkit/src/index.ts') as { mountAgentLoopTestDependencies(ctx: Context): Promise<void>; mountAgentLoopTestHarness(ctx: Context): Promise<unknown> }
    const tls = await tlsFixture()
    const originalPath = process.env.PATH
    let sidecar: Sidecar | undefined, sidecarCleanup: unknown
    let fixture: Awaited<ReturnType<typeof createProductHostFixture>> | undefined
    let asHandler: RequestListener | undefined, rsHandler: RequestListener | undefined, noAs: NoAsVerifier | undefined
    let noAsClosed = false
    let rawTargetsDisposed = 0
    let expiryObserved = false
    const counts = { tokenPosts: 0, resourceRequests: 0, materialReads: 0, forbiddenRoutes: 0 }
    const grantTypes: Array<string | null> = []
    const order: string[] = []
    try {
      sidecar = await createSecretServiceSidecar()
      process.env.PATH = sidecar.binDirectory + ':' + originalPath
      const publisher = await tls.start((request, response) => {
        if (!fixture) { response.writeHead(503).end(); return }
        const material = fixture.publicMaterials, meta = JSON.parse(material.metadata) as { client_id: string; jwks_uri: string }
        response.setHeader('content-type', 'application/json')
        if (request.method === 'GET' && request.url === new URL(meta.client_id).pathname) { counts.materialReads++; response.end(material.metadata) }
        else if (request.method === 'GET' && request.url === new URL(meta.jwks_uri).pathname) { counts.materialReads++; response.end(material.jwks) }
        else response.writeHead(404).end()
      }, 'localhost')
      const company = await tls.start((request, response) => {
        if (noAsClosed) { response.writeHead(503).end(); return }
        if (!noAs) { response.writeHead(503).end(); return }
        noAs.handler(request, response)
      }, 'other.test')
      const as = await tls.start((request, response) => {
        if (request.method === 'POST' && request.url === '/oauth/token') {
          counts.tokenPosts++
          const chunks: Buffer[] = []
          request.on('data', chunk => chunks.push(Buffer.from(chunk)))
          request.on('end', () => {
            grantTypes.push(new URLSearchParams(Buffer.concat(chunks).toString()).get('grant_type'))
            for (const chunk of chunks) chunk.fill(0)
            chunks.length = 0
          })
        }
        if (/authorize|callback|refresh/u.test(request.url ?? '')) counts.forbiddenRoutes++
        if (!asHandler) { response.writeHead(503).end(); return }
        asHandler(request, response)
      }, 'localhost')
      const rs = await tls.start((request, response) => {
        if (request.url === '/mcp') counts.resourceRequests++
        if (!rsHandler) { response.writeHead(503).end(); return }
        rsHandler(request, response)
      }, 'localhost')
      const resource = rs.origin + '/mcp', scopes = ['agent.self.read', 'catalog.read']
      const store = new PostgresStore(pool, as.origin)
      await store.configureRequestLimits({ globalMinute: 240, originMinute: 120, clientMinute: 60, sourceMinute: 120 })
      await store.configurePolicy({ resource, scopes, ttl: 8, maxNewClientsHour: 10, maxRequestsClientMinute: 30, maxRequestsMinute: 120,
        custodyCondition: 'One current actual C/B/A Host, F closed before MCP', enabled: true })
      const rsId = 'shared-product-rs', rsSecret = randomBytes(32).toString('base64url')
      await store.provisionResourceServer(rsId, rsSecret, [resource])
      asHandler = createAuthorizationServer(store, new ClientAuthenticator(tls.fetcher(), as.origin), scopes)
      rsHandler = createMcpApp(new TokenVerifier(tls.fetcher(), { issuer: as.origin, introspectionEndpoint: as.origin + '/oauth/introspect', resource,
        rsId, rsSecret, allowedScopes: scopes }))
      const dispatch = new Map([as.origin, rs.origin].map(origin => [origin, createTestMachineFetch({ origin, ca: tls.cert })]))
      network.send = (input, init) => {
        const send = dispatch.get(new URL(input instanceof Request ? input.url : String(input)).origin)
        if (!send) throw new Error('shared_product_unapproved_transport_origin')
        return send(input, init)
      }
      fixture = await createProductHostFixture({ source: bSource!, python: python!, publicationOrigin: publisher.origin,
        publicationCapabilities: { mcpMachine: true, papSession: true, papAccount: false } })
      const reference = fixture.publicRef, material = fixture.publicMaterials
      const metadata = JSON.parse(material.metadata) as { client_id: string }
      noAs = createNoAsProductVerifier({ clientId: metadata.client_id, jwks: JSON.parse(material.jwks), companyOrigin: company.origin })
      const owner = '@agent-network-protocol/dsh-anp-identity'
      const common = { version: 1, owner, identity: reference, publicTargets: false, expiresAt: Date.now() + 600000 }
      const policies: ProtocolUsePolicy[] = [
        { ...common, id: 'shared-F', consumer: F_PLUGIN, profiles: ['pap_session'], issuers: [company.origin], resources: [company.origin, company.origin + '/api'], scopes: ['pap.read'] },
        { ...common, id: 'shared-MCP', consumer: MCP, profiles: ['mcp_machine'], issuers: [as.origin], resources: [resource], scopes },
      ]
      const networkName = '@fixture/shared-F-network'
      const fTransport = new SafeHttpsTransport({ ca: tls.cert, privateOrigins: [company.origin], lookup: async () => [{ address: '127.0.0.1', family: 4 }] })
      const modules = { [F_PLUGIN]: FPlugin, [F_MANAGER]: FManagerModule, [F_TOOLS]: FTools, [MCP]: Mcp,
        [MCP + '/management']: Management, [MCP + '/management-remote']: ManagementRemote,
        [networkName]: { apply(context: Context) { context.provide('papHost', { transport: fTransport }) } } }
      const ctx = await fixture.reopen({ protocolPolicies: policies, modules }) as Runtime
      const hostContext = fixture.ctx
      const provider = [...ctx.loader.entries()].find(entry => entry.options.name === owner + '/provider')!.fiber!.ctx.fiber
      await kit.mountAgentLoopTestDependencies(ctx)
      await kit.mountAgentLoopTestHarness(ctx)
      // F tools require a real Agent execution. This Agent has no MCP preset
      // and constructs no MCP client; it is closed before the MCP phase.
      const fActor = await ctx.agents.create({ sessionId: 'shared-F-agent-' + randomUUID(), setup: async () => {} })
      const papRoot = join(fixture.root, 'F-state')
      for (const entry of [
        { name: networkName },
        { name: F_PLUGIN, config: { enabled: true, stateRoot: papRoot, policyRef: 'shared-F' } },
        { name: F_MANAGER }, { name: F_TOOLS },
        { name: MCP + '/management', config: { managerConsumers: [MCP + '/management-remote'] } },
        { name: MCP + '/management-remote' },
      ]) await ctx.loader.create(entry)
      await ctx.loader.await()
      const manager = ctx.get('papManager') as FManager
      const unwrap = (result: PublicResult): Record<string, unknown> => { expect(result.ok).toBe(true); return result.value as Record<string, unknown> }
      unwrap(await manager.manage({ action: 'identity/select', reference }))
      const discovered = unwrap(await manager.manage({ action: 'company/discover', domain: new URL(company.origin).host }))
      const session = unwrap(await manager.manage({ action: 'session/connect', companyRef: discovered.companyRef }))
      const operations = (await manager.operations()).value as Array<{ operationRef: string }>
      expect(operations).toHaveLength(1)
      unwrap(await manager.manage({ action: 'operation/enable', operationRef: operations[0]!.operationRef, sessionRef: session.sessionRef }))
      const response = await ctx.tools.execute({ agent: fActor.agent, callId: randomUUID(), name: 'pap_request', arguments: { operationRef: operations[0]!.operationRef }, signal: new AbortController().signal })
      expect(response).toMatchObject({ isError: false, value: { ok: true, value: { status: 200 } } })
      expect(noAs.observations.requests).toBe(1); expect(noAs.uniqueRequestProofs()).toBe(1)
      expect(counts.tokenPosts).toBe(0)
      expect(Number((await pool.query('SELECT count(*)::integer AS n FROM clients')).rows[0]!.n)).toBe(0)
      expect([...ctx.loader.entries()].some(entry => entry.options.name === MCP)).toBe(false)
      const sha256 = (text: string) => createHash('sha256').update(text).digest('base64url')
      const binding = { identityRef: { storeId: reference.storeId, identityId: reference.identityId, did: reference.did }, ownerRef: owner, clientId: metadata.client_id }
      const namespace = 'dsh-pap/profile/' + sha256(papRoot) + '/pap/' + sha256(JSON.stringify(binding))
      const secret = await new KeyringSecretStore('org.agentconnect.dsh-pap', join(fixture.root, 'F-key-check')).getEncryptionKey(namespace)
      expect(secret?.length).toBe(32); secret?.fill(0)
      order.push('actual_F_NoAS_signed_request_Token0_no_MCP_client')
      // Read-only access to opaque test capabilities proves the real stop path
      // disposes raw targets while the actual F Context is still installed.
      const pap = ctx.get('pap') as PapInternals
      const raw = [...pap.client!.options.identityHost.rawLeases]
      expect(raw.length).toBeGreaterThan(0)
      await Promise.all(raw.map(target => target.assertActive()))
      pap.stop()
      expect(pap.client!.options.identityHost.rawLeases.size).toBe(0)
      for (const target of raw) { await expect(target.assertActive()).rejects.toBeDefined(); rawTargetsDisposed++ }
      for (const name of [F_TOOLS, F_MANAGER, F_PLUGIN, networkName]) {
        const entry = [...ctx.loader.entries()].find(value => value.options.name === name)
        expect(entry).toBeDefined(); await ctx.loader.remove(entry!.id)
      }
      noAsClosed = true
      company.server.closeAllConnections()
      await new Promise<void>((resolve, reject) => company.server.close(error => error ? reject(error) : resolve()))
      sidecarCleanup = await sidecar.stop(); sidecar = undefined
      await fActor.dispose()
      expect(fixture.ctx).toBe(hostContext)
      expect([...ctx.loader.entries()].find(entry => entry.options.name === owner + '/provider')!.fiber!.ctx.fiber).toBe(provider)
      expect(fixture.publicRef).toEqual(reference); expect(fixture.publicMaterials).toEqual(material)
      expect(counts.tokenPosts).toBe(0)
      order.push('F_engine_raw_targets_rows_NoAS_and_default_SecretService_closed_same_C_Host')
      const credential = ctx.get('credentials') as { set(ref: string, value: string): Promise<void> }
      const keyRef = 'SHARED_MCP_' + randomUUID().replaceAll('-', '').toUpperCase()
      await credential.set(keyRef, randomBytes(32).toString('base64url'))
      ctx.baseUrl = pathToFileURL(hSource! + '/').href
      ctx.loader.internal = { version: 'v2', import: async (name: string) => {
        if (!Object.hasOwn(modules, name)) throw new Error('shared_product_unknown_module')
        return modules[name as keyof typeof modules]
      } } as unknown as NonNullable<typeof ctx.loader.internal>
      const file = join(fixture.root, 'mcp.cordis.yml')
      await writeFile(file, `- id: actual-machine\n  name: '${MCP}'\n  inject: [mcpConnections, anpIdentity, credentials]\n  config:\n    serverName: shared\n    transport: streamable-http\n    url: ${resource}\n    failOnStartupError: true\n    reconnect: { enabled: false }\n    authentication:\n      mode: cimd-client-credentials\n      connectionId: shared-${randomUUID()}\n      identityRef: ${JSON.stringify(reference)}\n      policyRef: shared-MCP\n      requestedScopes: [agent.self.read, catalog.read]\n      stateRoot: ${JSON.stringify(join(fixture.root, 'MCP-state'))}\n      encryptionKeyRef: ${keyRef}\n`)
      order.push('first_MCP_Agent_Preset_constructed_after_F_shutdown')
      const handle = await ctx.agents.create({ sessionId: 'shared-agent-' + randomUUID(), setup: context => mountPreset(context, { id: 'shared-product', trust: 'system', path: file }) })
      const callTools = async () => {
        for (const name of ['mcp__shared__identity_get', 'mcp__shared__catalog_list']) {
          const result = await ctx.tools.execute({ agent: handle.agent, name, arguments: {}, callId: randomUUID(), signal: new AbortController().signal })
          expect(result.isError).toBe(false)
          const text = result.content.find(item => item.type === 'text')?.text
          expect(text).toBeTypeOf('string')
          if (name.endsWith('identity_get')) expect(JSON.parse(text!)).toMatchObject({ client_id: metadata.client_id, resource })
          else expect(JSON.parse(text!).items).toBeInstanceOf(Array)
        }
      }
      await callTools(); expect(counts.tokenPosts).toBe(1)
      order.push('MCP_first_CC_and_two_tools')
      await setTimeout(8500)
      expiryObserved = Number((await pool.query('SELECT count(*)::integer AS n FROM access_tokens WHERE expires_at<=clock_timestamp()')).rows[0]!.n) === 1
      expect(expiryObserved).toBe(true)
      await callTools(); expect(counts.tokenPosts).toBe(2)
      expect(grantTypes).toEqual(['client_credentials', 'client_credentials'])
      expect(counts.forbiddenRoutes).toBe(0)
      expect(fixture.ctx).toBe(hostContext); expect(fixture.publicRef).toEqual(reference); expect(fixture.publicMaterials).toEqual(material)
      order.push('actual_8_5_seconds_expiry_new_CC_and_two_tools_same_CIMD')
      await handle.dispose()
      expect(await sourceHashes()).toEqual(before)
    } finally {
      try { await fixture?.dispose() }
      finally {
        network.send = undefined; process.env.PATH = originalPath
        try { if (sidecar) sidecarCleanup = await sidecar.stop() }
        finally { try { await tls.close() } finally { await pool.end() } }
      }
    }
    expect(fixture!.evidence.cleanup.complete).toBe(true)
    await expect(stat(fixture!.root)).rejects.toMatchObject({ code: 'ENOENT' })
    const result = { passed: true, lane: 'current-one-C-Host-actual-F-closed-before-first-MCP', sourceSha256: before, counts, grantTypes, order,
      sameHostContextProviderReferenceAndCimd: true, papRequests: noAs!.observations.requests, papStageTokenRequests: 0, rawFTargetsDisposed: rawTargetsDisposed,
      ttlSeconds: 8, actualExpiryObserved: expiryObserved, waitMilliseconds: 8500,
      boundaries: { liveLLM: false, systemTest: false, productE2E: false, productionDefaultNetwork: 'not-claimed',
        OSLockCachedToken: 'separate-E-owner-not-this-case', B: 'logical-HTTPS-ASGI-external-SMTP-Siteverify-fixture', Company: 'independent-Node-crypto-actual-TLS',
        MCP: 'actual-Agent-Preset-SDK-E-AS-RS-PG-TLS' },
      cleanup: { B: fixture!.evidence.cleanup, CRootRemoved: fixture!.root, TLSClosed: true, pgPoolClosed: true, SecretService: sidecarCleanup,
        pgOwnerRoot: dirname(pgSocket!), pgCluster: 'owner-EXIT-trap-after-spec' } }
    if (process.env.DSH_SHARED_PRODUCT_RESULT) {
      await mkdir(dirname(process.env.DSH_SHARED_PRODUCT_RESULT), { recursive: true, mode: 0o700 })
      await writeFile(process.env.DSH_SHARED_PRODUCT_RESULT, JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' })
    }
  }, 180000)
