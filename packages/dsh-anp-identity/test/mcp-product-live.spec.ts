/** Opt-in source component: real fresh C/B, actual Agent/Preset/MCP and E PG/TLS. No model run. */
import type { Context } from '@deepseek-ai/cordis'
import type { RequestListener } from 'node:http'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { setTimeout } from 'node:timers/promises'
import { expect, it, vi } from 'vitest'
import type { ProtocolUsePolicy } from '../src/protocol-client.js'
import { createProductHostFixture } from './helpers/product-host-fixture.js'

const wire = vi.hoisted(() => ({ send: undefined as typeof fetch | undefined }))
// The one network seam changes only exact-origin selection. Every request is
// still sent by the production pinned HTTPS implementation over real TLS.
vi.mock('../../../../deepseek-harness/packages/mcp/mcp-client/src/machine-http.ts', async original => {
  const actual = await original<Record<string, unknown>>()
  return { ...actual, machineFetch: (input: string | URL | Request, init?: RequestInit) => {
    if (!wire.send) throw new Error('mcp_product_transport_not_ready')
    return wire.send(input, init)
  } }
})

const bSource = process.env.DSH_IDENTITY_USER_SERVICE_SOURCE
const python = process.env.DSH_IDENTITY_PYTHON
const harnessSource = process.env.DSH_MCP_PRODUCT_HARNESS_SOURCE
const asSource = process.env.DSH_MCP_PRODUCT_AS_SOURCE
const MCP = '@deepseek-ai/dsh-mcp-client'
const MANAGEMENT = MCP + '/management'
const REMOTE = MCP + '/management-remote'
const scopes = ['agent.self.read', 'catalog.read']
type Agent = { ctx: Context }
type AgentHandle = { agent: Agent; dispose(): Promise<void> }
interface Runtime extends Context {
  agents: { create(input: { sessionId: string; setup(ctx: Context): Promise<void> }): Promise<AgentHandle> }
  tools: {
    schemas(agent?: Agent): Array<{ name: string }>
    get(name: string, agent?: Agent): unknown
    execute(input: { agent: Agent; name: string; arguments: object; callId: string; signal: AbortSignal }): Promise<unknown>
  }
}
interface PublicStatus { state: string; authentication: string; generation: number; remoteRevocation: string }
interface Manager { status(id: string): Promise<PublicStatus>; disconnect(id: string): Promise<PublicStatus>; enable(id: string): Promise<PublicStatus> }
interface Pool { query(sql: string, values?: unknown[]): Promise<{ rows: Array<Record<string, unknown>> }>; end(): Promise<void> }
interface Store {
  configureRequestLimits(value: Record<string, number>): Promise<unknown>
  configurePolicy(value: Record<string, unknown>): Promise<unknown>
  provisionResourceServer(id: string, secret: string, resources: string[]): Promise<unknown>
}
interface Tls {
  start(handler: RequestListener, hostname?: string): Promise<{ origin: string }>
  fetcher(): unknown
  cert: string
  close(): Promise<void>
}
const load = (base: string, path: string): Promise<unknown> => import(/* @vite-ignore */ pathToFileURL(join(base, path)).href)
const sha = async (path: string) => createHash('sha256').update(await readFile(path)).digest('hex')
async function sourceHashes(): Promise<Record<string, string>> {
  const d = join(harnessSource!, 'packages/mcp/mcp-client/src')
  const paths: Array<[string, string]> = [
    ...((await readdir(d)).filter(name => name.endsWith('.ts')).map(name => ['D/' + name, join(d, name)] as [string, string])),
    ...['index.ts', 'registration-bootstrap.ts', 'protocol-bootstrap.ts', 'host-management-secret.ts', 'target-policy.ts', 'provider.ts', 'installed-consumer.ts'].map(name => ['C/' + name, new URL('../src/' + name, import.meta.url).pathname] as [string, string]),
    ...['test/helpers/product-host-fixture.ts', 'test/helpers/strict-bootstrap-bridge.ts', 'test/mcp-product-live.spec.ts'].map(name => ['fixture/' + name, new URL('../' + name, import.meta.url).pathname] as [string, string]),
    ...['packages/oauth-as/app.ts', 'packages/oauth-core/client.ts', 'packages/store-postgres/store.ts', 'packages/oauth-rs/index.ts', 'examples/minimal-mcp-server/app.ts', 'tests/helpers.ts'].map(name => ['E/' + name, join(asSource!, name)] as [string, string]),
    ['native', new URL('../../../bindings/node/anp-identity.linux-x64-gnu.node', import.meta.url).pathname],
  ]
  return Object.fromEntries(await Promise.all(paths.map(async ([name, path]) => [name, await sha(path)])))
}

it.skipIf(process.platform !== 'linux' || !bSource || !python || !harnessSource || !asSource || !process.env.DATABASE_URL)(
  'fresh C identity authorizes actual Agent Preset MCP, whose explicit disconnect remains disabled until new C permission and enable', async () => {
    expect(process.env.NODE_ENV).toBe('test')
    const database = new URL(process.env.DATABASE_URL!)
    const socket = database.searchParams.get('host')
    expect(database.hostname).toBe('')
    expect(database.pathname).toBe('/cimd_component')
    expect(socket).toMatch(/^\/tmp\/cimd-pg\.[^/]+\/socket$/u)
    const before = await sourceHashes()
    expect(before.native).toBe('ffb6c3a6ee7bcd5592184db57c865d0a90748a6379636ca203a5ad42012718b9')
    const pg = await load(asSource!, 'node_modules/pg/lib/index.js') as { default: { Pool: new (config: object) => Pool } }
    const pool = new pg.default.Pool({ connectionString: process.env.DATABASE_URL, max: 8 })
    const { tlsFixture } = await load(asSource!, 'tests/helpers.ts') as { tlsFixture(): Promise<Tls> }
    const { PostgresStore } = await load(asSource!, 'packages/store-postgres/store.ts') as { PostgresStore: new (pool: Pool, issuer: string) => Store }
    const { ClientAuthenticator } = await load(asSource!, 'packages/oauth-core/client.ts') as { ClientAuthenticator: new (fetcher: unknown, issuer: string) => unknown }
    const { createAuthorizationServer } = await load(asSource!, 'packages/oauth-as/app.ts') as { createAuthorizationServer(store: Store, authenticator: unknown, scopes: string[]): RequestListener }
    const { TokenVerifier } = await load(asSource!, 'packages/oauth-rs/index.ts') as { TokenVerifier: new (fetcher: unknown, config: object) => unknown }
    const { createMcpApp } = await load(asSource!, 'examples/minimal-mcp-server/app.ts') as { createMcpApp(verifier: unknown): RequestListener }
    const McpClient = await load(harnessSource!, 'packages/mcp/mcp-client/src/index.ts')
    const { default: Management } = await load(harnessSource!, 'packages/mcp/mcp-client/src/management.ts') as { default: unknown }
    const { default: ManagementRemote } = await load(harnessSource!, 'packages/mcp/mcp-client/src/management-remote.ts') as { default: unknown }
    const { createTestMachineFetch } = await load(harnessSource!, 'packages/mcp/mcp-client/src/machine-http.ts') as { createTestMachineFetch(options: { origin: string; ca: string }): typeof fetch }
    const { mountPreset } = await load(harnessSource!, 'packages/preset/agent-presets/src/mount.ts') as { mountPreset(ctx: Context, preset: { id: string; trust: 'system'; path: string }): Promise<void> }
    const kit = await load(harnessSource!, 'packages/test-support/agent-loop-testkit/src/index.ts') as {
      mountAgentLoopTestDependencies(ctx: Context): Promise<void>; mountAgentLoopTestHarness(ctx: Context): Promise<unknown>
    }
    const tls = await tlsFixture()
    let fixture: Awaited<ReturnType<typeof createProductHostFixture>> | undefined
    let agent: AgentHandle | undefined
    let asHandler: RequestListener | undefined, rsHandler: RequestListener | undefined
    const counts = { tokenPosts: 0, revokePosts: 0, resourceRequests: 0, publicMaterialReads: 0, forbiddenOAuthRoutes: 0 }
    const order: string[] = []
    let finalRemoteRevocation = 'not_requested'
    try {
      const publisher = await tls.start((request, response) => {
        const material = fixture?.publicMaterials
        if (!material) { response.writeHead(503).end(); return }
        const metadata = JSON.parse(material.metadata) as { client_id: string; jwks_uri: string }
        if (request.method !== 'GET') { response.writeHead(404).end(); return }
        response.setHeader('content-type', 'application/json')
        if (request.url === new URL(metadata.client_id).pathname) { counts.publicMaterialReads++; response.end(material.metadata) }
        else if (request.url === new URL(metadata.jwks_uri).pathname) { counts.publicMaterialReads++; response.end(material.jwks) }
        else response.writeHead(404).end()
      }, 'identity.example')
      const as = await tls.start((request, response) => {
        if (request.method === 'POST' && request.url === '/oauth/token') counts.tokenPosts++
        if (request.method === 'POST' && request.url === '/oauth/revoke') counts.revokePosts++
        if (/authorize|callback|refresh/u.test(request.url ?? '')) counts.forbiddenOAuthRoutes++
        if (!asHandler) { response.writeHead(503).end(); return }
        asHandler(request, response)
      }, 'localhost')
      const rs = await tls.start((request, response) => {
        if (request.url === '/mcp') {
          counts.resourceRequests++
          expect(request.headers['poppy-session']).toBeUndefined()
          expect(request.headers.dpop).toBeUndefined()
        }
        if (!rsHandler) { response.writeHead(503).end(); return }
        rsHandler(request, response)
      }, 'localhost')
      const resource = rs.origin + '/mcp'
      const store = new PostgresStore(pool, as.origin)
      await store.configureRequestLimits({ globalMinute: 240, originMinute: 120, clientMinute: 60, sourceMinute: 120 })
      await store.configurePolicy({ resource, scopes, ttl: 300, maxNewClientsHour: 10, maxRequestsClientMinute: 30,
        maxRequestsMinute: 120, custodyCondition: 'Actual approved C / A native / B published component identity', enabled: true })
      const rsId = 'mcp-product-rs', rsSecret = randomBytes(32).toString('base64url')
      await store.provisionResourceServer(rsId, rsSecret, [resource])
      asHandler = createAuthorizationServer(store, new ClientAuthenticator(tls.fetcher(), as.origin), scopes)
      rsHandler = createMcpApp(new TokenVerifier(tls.fetcher(), { issuer: as.origin, introspectionEndpoint: as.origin + '/oauth/introspect',
        resource, rsId, rsSecret, allowedScopes: scopes }))
      const transports = new Map([as.origin, rs.origin].map(origin => [origin, createTestMachineFetch({ origin, ca: tls.cert })]))
      wire.send = (input, init) => {
        const url = input instanceof Request ? input.url : String(input)
        const send = transports.get(new URL(url).origin)
        if (!send) throw new Error('mcp_product_unapproved_transport_origin')
        return send(input, init)
      }
      fixture = await createProductHostFixture({ source: bSource!, python: python!, publicationOrigin: publisher.origin })
      const published = JSON.parse(fixture.publicMaterials.metadata) as { client_id: string }
      expect(new URL(published.client_id).origin).toBe(publisher.origin)
      expect(Number((await pool.query('SELECT count(*)::integer AS n FROM clients')).rows[0]!.n)).toBe(0)
      order.push('actual_C_B_published_before_MCP')
      const connectionId = 'mcp-product-' + randomUUID()
      const keyRef = 'MCP_PRODUCT_' + randomUUID().replaceAll('-', '').toUpperCase()
      const stateRoot = join(fixture.root, 'machine-state')
      const policy = (version: number): ProtocolUsePolicy => ({ id: 'actual-product-mcp', version, owner: '@agent-network-protocol/dsh-anp-identity',
        consumer: MCP, identity: fixture!.publicRef, profiles: ['mcp_machine'], issuers: [as.origin], resources: [resource],
        publicTargets: false, scopes, expiresAt: Date.now() + 600000 })
      const modules = { [MCP]: McpClient, [MANAGEMENT]: Management, [REMOTE]: ManagementRemote }
      const hostEntries = [{ name: MANAGEMENT, config: { managerConsumers: [REMOTE] } }, { name: REMOTE }]
      const credential = () => fixture!.ctx.get('credentials') as { set(ref: string, value: string): Promise<void>; resolve(ref: string): Promise<{ value: string; source?: string } | undefined> }
      let presetPath = ''
      const reopen = async (policies: ProtocolUsePolicy[]) => {
        await fixture!.reopen({ protocolPolicies: policies, modules, entries: hostEntries })
        const ctx = fixture!.ctx as Runtime
        ctx.baseUrl = pathToFileURL(harnessSource! + '/').href
        // PresetTree has its own import method; share this exact Host module
        // resolver rather than attaching a fabricated Entry or caller Context.
        ctx.loader.internal = { version: 'v2', import: async (name: string) => {
          if (!Object.hasOwn(modules, name)) throw new Error('mcp_product_unknown_module')
          return modules[name as keyof typeof modules]
        } } as unknown as NonNullable<typeof ctx.loader.internal>
        if (!await credential().resolve(keyRef)) await credential().set(keyRef, randomBytes(32).toString('base64url'))
        expect((await credential().resolve(keyRef))?.source).toBe('file')
        await kit.mountAgentLoopTestDependencies(ctx)
        await kit.mountAgentLoopTestHarness(ctx)
        presetPath = join(fixture!.root, 'agent.cordis.yml')
        await writeFile(presetPath, `- id: actual-machine\n  name: '${MCP}'\n  inject: [mcpConnections, anpIdentity, credentials]\n  config:\n    serverName: product\n    transport: streamable-http\n    url: ${resource}\n    failOnStartupError: true\n    reconnect: { enabled: false }\n    authentication:\n      mode: cimd-client-credentials\n      connectionId: ${connectionId}\n      identityRef: ${JSON.stringify(fixture!.publicRef)}\n      policyRef: actual-product-mcp\n      requestedScopes: [agent.self.read, catalog.read]\n      issuer: ${as.origin}\n      stateRoot: ${JSON.stringify(stateRoot)}\n      encryptionKeyRef: ${keyRef}\n`)
        return ctx
      }
      const mount = async (ctx: Runtime) => ctx.agents.create({ sessionId: 'mcp-product-agent-' + randomUUID(),
        setup: context => mountPreset(context, { id: 'mcp-product', trust: 'system', path: presetPath }) })
      const remote = () => fixture!.ctx.get('mcpConnectionManager') as Manager
      const toolNames = ['mcp__product__identity_get', 'mcp__product__catalog_list']
      const tools = async (ctx: Runtime, handle: AgentHandle) => {
        expect(ctx.tools.schemas(handle.agent).map(schema => schema.name).sort()).toEqual(toolNames.slice().sort())
        expect(ctx.tools.schemas().map(schema => schema.name)).not.toContain(toolNames[0])
        for (const name of toolNames) {
          const result = await ctx.tools.execute({ agent: handle.agent, name, arguments: {}, callId: randomUUID(), signal: new AbortController().signal })
          const text = (result as { content?: Array<{ type: string; text?: string }> }).content?.find(item => item.type === 'text')?.text
          expect(text).toBeTypeOf('string')
          const value = JSON.parse(text!) as Record<string, unknown>
          if (name.endsWith('identity_get')) expect(value).toMatchObject({ client_id: published.client_id, resource })
          else expect(value.items).toBeInstanceOf(Array)
        }
      }
      let ctx = await reopen([])
      await expect(mount(ctx)).rejects.toThrow()
      expect(counts.tokenPosts).toBe(0)
      expect(Number((await pool.query('SELECT count(*)::integer AS n FROM clients')).rows[0]!.n)).toBe(0)
      order.push('missing_C_policy_refused_before_Token')
      ctx = await reopen([policy(1)])
      agent = await mount(ctx)
      expect([...ctx.loader.entries()].some(entry => entry.options.name === MCP)).toBe(false)
      await tools(ctx, agent)
      expect(counts.tokenPosts).toBe(1)
      expect(await remote().status(connectionId)).toMatchObject({ state: 'ready', authentication: 'token_ready' })
      order.push('real_Preset_MCP_two_tools')
      const previousAgent = agent.agent
      await agent.dispose(); agent = undefined
      const stoppedRequests = counts.resourceRequests
      expect(ctx.tools.get(toolNames[0]!, previousAgent)).toBeUndefined()
      await ctx.tools.execute({ agent: previousAgent, name: toolNames[0]!, arguments: {}, callId: randomUUID(), signal: new AbortController().signal }).catch(() => {})
      await setTimeout(50)
      expect(counts.resourceRequests).toBe(stoppedRequests)
      expect(counts.revokePosts).toBe(0)
      order.push('ordinary_agent_exit_quiesced')
      agent = await mount(ctx)
      await tools(ctx, agent)
      await remote().disconnect(connectionId)
      expect(await remote().status(connectionId)).toMatchObject({ state: 'disconnected', authentication: 'stopped' })
      expect(ctx.tools.get(toolNames[0]!, agent.agent)).toBeUndefined()
      const afterDisconnect = counts.tokenPosts
      expect(counts.revokePosts).toBeGreaterThan(0)
      expect(Number((await pool.query('SELECT count(*)::integer AS n FROM access_tokens WHERE revoked_at IS NOT NULL')).rows[0]!.n)).toBeGreaterThan(0)
      ctx = await reopen([]); agent = await mount(ctx)
      expect(await remote().status(connectionId)).toMatchObject({ state: 'disconnected', authentication: 'stopped' })
      expect(counts.tokenPosts).toBe(afterDisconnect)
      await expect(remote().enable(connectionId)).rejects.toThrow()
      expect(counts.tokenPosts).toBe(afterDisconnect)
      expect(ctx.tools.get(toolNames[0]!, agent.agent)).toBeUndefined()
      order.push('disconnect_restart_disabled_missing_permission_enable_refused')
      ctx = await reopen([policy(2)]); agent = await mount(ctx)
      expect(await remote().status(connectionId)).toMatchObject({ state: 'disconnected' })
      expect(counts.tokenPosts).toBe(afterDisconnect)
      await remote().enable(connectionId)
      await tools(ctx, agent)
      expect(counts.tokenPosts).toBeGreaterThan(afterDisconnect)
      order.push('new_C_policy_explicit_enable_two_tools')
      finalRemoteRevocation = (await remote().disconnect(connectionId)).remoteRevocation
      expect(['confirmed', 'remote_revocation_unconfirmed']).toContain(finalRemoteRevocation)
      expect(counts.forbiddenOAuthRoutes).toBe(0)
      expect(await sourceHashes()).toEqual(before)
    } finally {
      try { await fixture?.dispose() }
      finally {
        wire.send = undefined
        try { await tls.close() } finally { await pool.end() }
      }
    }
    expect(fixture!.evidence.cleanup.complete).toBe(true)
    await expect(stat(fixture!.root)).rejects.toMatchObject({ code: 'ENOENT' })
    const result = { passed: true, lane: 'actual-fresh-C-B-Agent-Preset-MCP-E-PG-TLS', sourceSha256: before, counts, order,
      finalRemoteRevocation, boundaries: { model: 'production-AgentLoop-test-harness-no-live-LLM', systemTest: false, productE2E: false,
        transport: 'only-machineFetch-exact-origin-dispatch-to-actual-createTestMachineFetch', producerDefaultNetwork: 'not-claimed',
        B: 'actual-fullmiddleware-ASGI-SMTP-Siteverify-external-transports-fixture', E: 'actual-AS-RS-SDK-PG-TLS' },
      cleanup: { B: fixture!.evidence.cleanup, CRootRemoved: fixture!.root, TLSClosed: true, pgPoolClosed: true,
        pgOwnerRoot: dirname(socket!), pgCluster: 'owner-runner-EXIT-trap-after-spec' } }
    if (process.env.DSH_MCP_PRODUCT_RESULT) {
      await mkdir(dirname(process.env.DSH_MCP_PRODUCT_RESULT), { recursive: true, mode: 0o700 })
      await writeFile(process.env.DSH_MCP_PRODUCT_RESULT, JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 })
    }
  }, 180000)
