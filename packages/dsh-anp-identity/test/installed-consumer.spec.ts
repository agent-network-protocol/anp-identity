/** Real rc2 source Loader/Preset/MCP and real C binding; only the stdio MCP server is a fixture.
 * The optional cross-repository lane requires DSH_INSTALLED_CONSUMER_SOURCE_ROOT and its source aliases.
 */
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { Context, type Fiber } from '@deepseek-ai/cordis'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import { afterEach, expect, it, vi } from 'vitest'
import AnpIdentityService from '../src/index.js'
import { installedConsumerEntries, resolveInstalledConsumer } from '../src/installed-consumer.js'
import { openNativeProvider } from '../src/provider.js'
import type { NativeProviderRegistry } from '../src/provider-api.js'
import { bindIdentityClient } from '../src/user-client.js'

const source = process.env.DSH_INSTALLED_CONSUMER_SOURCE_ROOT
type SourcePlugin = Parameters<Context['plugin']>[0]
let mountPreset: (ctx: Context, preset: { id: string; trust: 'system'; path: string }) => Promise<void>
let createScope: (ctx: Context, key: object) => { ctx: Context; dispose(): Promise<void> }
let Tools: SourcePlugin
let SystemPrompt: SourcePlugin
let McpClient: SourcePlugin
let dependencies: Promise<void> | undefined
async function sourceDependencies(): Promise<void> {
  if (!source) throw new Error('DSH_INSTALLED_CONSUMER_SOURCE_ROOT is required for the rc2 source fixture')
  const load = (relative: string): Promise<unknown> => import(/* @vite-ignore */ pathToFileURL(join(source, relative)).href)
  mountPreset = (await load('packages/preset/agent-presets/src/mount.ts') as { mountPreset: typeof mountPreset }).mountPreset
  createScope = (await load('packages/core/scope/src/index.ts') as { createScope: typeof createScope }).createScope
  Tools = (await load('packages/core/tools/src/index.ts') as { default: SourcePlugin }).default
  SystemPrompt = (await load('packages/core/system-prompt/src/index.ts') as { default: SourcePlugin }).default
  McpClient = await load('packages/mcp/mcp-client/src/index.ts') as SourcePlugin
}

const ROOT_CONSUMER = '@fixture/root-consumer'
const MCP_CONSUMER = '@deepseek-ai/dsh-mcp-client'
const roots: Context[] = []
const directories: string[] = []
afterEach(async () => {
  vi.restoreAllMocks()
  for (const ctx of roots.splice(0).reverse()) await ctx.fiber.dispose()
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true })
})

async function harness() {
  await (dependencies ??= sourceDependencies())
  const directory = await mkdtemp(join(tmpdir(), 'c-installed-consumer-'))
  directories.push(directory)
  const ctx = new Context()
  roots.push(ctx)
  ctx.baseUrl = pathToFileURL(directory).href + '/'
  await ctx.plugin(Loader)
  const contexts = new Map<string, Context>()
  const modules = new Map<string, unknown>([
    ['identity-host', AnpIdentityService],
    ['tools', Tools],
    ['system-prompt', SystemPrompt],
    [MCP_CONSUMER, McpClient],
    ['native-provider', { inject: ['anpIdentity'], async apply(providerContext: Context) {
      const registration = await openNativeProvider({ stateRoot: directory, rootKeyProvider: 'injected', rootKeyProviderId: 'installed-consumer-test', injectedRootKey: Buffer.alloc(32, 93) })
      const dispose = (providerContext.anpIdentity as unknown as NativeProviderRegistry).registerProvider(registration)
      providerContext.effect(() => dispose, 'installed consumer fixture native provider')
    } }],
    [ROOT_CONSUMER, { inject: ['anpIdentity'], apply(caller: Context) { contexts.set(ROOT_CONSUMER, caller) } }],
    ['@fixture/spoofed-plugin-export', { name: MCP_CONSUMER, inject: ['anpIdentity'], apply(caller: Context) { contexts.set('spoof', caller) } }],
  ])
  ctx.loader.internal = { version: 'v2', import: async (name: string) => {
    if (!modules.has(name)) throw new Error('unexpected_fixture_module')
    return modules.get(name)
  } } as unknown as NonNullable<typeof ctx.loader.internal>
  await ctx.loader.create({ name: 'identity-host', config: { stateRoot: directory, allowConsumers: [ROOT_CONSUMER, MCP_CONSUMER], userConsumers: [ROOT_CONSUMER, MCP_CONSUMER],
    // Binding admission needs a Host policy, but does not publish/use a target or issue a Token.
    protocolPolicies: [{ id: 'installed-mcp', version: 1, owner: '@agent-network-protocol/dsh-anp-identity', consumer: MCP_CONSUMER,
      identity: { storeId: 'fixture', identityId: 'binding-only', did: 'did:web:identity.example:binding-only' }, profiles: ['mcp_machine'],
      issuers: ['https://issuer.example'], resources: ['https://resource.example/mcp'], publicTargets: false, scopes: ['agent.self.read'], expiresAt: Date.now() + 60000 }] } })
  await ctx.loader.create({ name: 'native-provider' })
  await ctx.loader.create({ name: 'system-prompt', config: { personaPrefix: '' } })
  await ctx.loader.create({ name: 'tools' })
  await ctx.loader.create({ name: ROOT_CONSUMER })
  await ctx.loader.create({ name: '@fixture/spoofed-plugin-export' })
  await ctx.loader.await()
  const host = ctx.anpIdentity as AnpIdentityService
  await expect(host.health()).resolves.toMatchObject({ status: 'ready' })
  return { ctx, directory, contexts, modules }
}

it.skipIf(!source)('binds root and actual MCP preset rows while the old root-only walk cannot see the preset', async () => {
  const f = await harness()
  const root = f.contexts.get(ROOT_CONSUMER)!
  expect(resolveInstalledConsumer(f.ctx, root)?.options.name).toBe(ROOT_CONSUMER)
  const rootClient = bindIdentityClient(root)
  await expect(rootClient.requestCreateIdentity({ requestId: 'root-installed', purpose: 'Verify real root admission', parameters: { label: 'Root', domain: 'identity.example', path: '/root' } })).resolves.toMatchObject({ caller: { consumer: ROOT_CONSUMER }, status: 'pending' })

  const scope = createScope(f.ctx, {})
  const file = join(f.directory, 'agent.cordis.yml')
  const server = join(f.directory, 'mcp-fixture.cjs')
  await writeFile(server, `require('node:readline').createInterface({ input: process.stdin }).on('line', line => {
    const body = JSON.parse(line)
    if (body.id === undefined) return
    const result = body.method === 'initialize'
      ? { protocolVersion: '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'installed-consumer-fixture', version: '1' } }
      : { tools: [] }
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }) + '\\n')
  })`)
  await writeFile(file, `- id: scoped-mcp\n  name: '${MCP_CONSUMER}'\n  config:\n    transport: stdio\n    serverName: scoped\n    command: ${JSON.stringify(process.execPath)}\n    args: [${JSON.stringify(server)}]\n    failOnStartupError: true\n    reconnect: { enabled: false }\n`)
  await mountPreset(scope.ctx, { id: 'installed-consumer', trust: 'system', path: file })
  // PresetTree intentionally severs the root Entry.subtree walk.
  expect([...f.ctx.loader.entries()].some(entry => entry.options.name === MCP_CONSUMER)).toBe(false)
  const installed = installedConsumerEntries(f.ctx).find(entry => entry.options.name === MCP_CONSUMER)!
  expect(installed).toBeDefined()
  const caller = installed.fiber!.ctx!
  expect(resolveInstalledConsumer(f.ctx, caller)).toBe(installed)
  // This is the actual C facade, actual Loader fiber and actual MCP entry.
  // Before index.ts consumes the new resolver this rejects consumer_forbidden.
  const identity = caller.get('anpIdentity') as AnpIdentityService
  const client = identity.bindUserConsumer(caller)
  expect(typeof identity.bindProtocolConsumer(caller).registerValidatedTarget).toBe('function')
  await expect(client.requestCreateIdentity({ requestId: 'preset-installed', purpose: 'Verify actual preset caller', parameters: { label: 'Preset', domain: 'identity.example', path: '/preset' } })).resolves.toMatchObject({ caller: { consumer: MCP_CONSUMER }, status: 'pending' })
  await scope.dispose()
  expect(resolveInstalledConsumer(f.ctx, caller)).toBeUndefined()
  expect(() => identity.bindProtocolConsumer(caller)).toThrowError(expect.objectContaining({ code: 'consumer_forbidden' }))
  await expect(client.getCreateRequest('preset-installed')).rejects.toMatchObject({ code: 'consumer_forbidden' })
})

it.skipIf(!source)('rejects other roots, export-name spoofing and direct plugins, including children inheriting a Loader entry', async () => {
  const f = await harness()
  const other = await harness()
  const otherCaller = other.contexts.get(ROOT_CONSUMER)!
  expect(resolveInstalledConsumer(f.ctx, otherCaller)).toBeUndefined()
  expect(() => (f.ctx.anpIdentity as AnpIdentityService).bindUserConsumer(otherCaller))
    .toThrowError(expect.objectContaining({ code: 'consumer_forbidden' }))
  const spoof = f.contexts.get('spoof')!
  expect(resolveInstalledConsumer(f.ctx, spoof)?.options.name).toBe('@fixture/spoofed-plugin-export')
  expect(() => bindIdentityClient(spoof)).toThrowError(expect.objectContaining({ code: 'consumer_forbidden' }))
  let direct!: Context
  await f.ctx.plugin({ name: MCP_CONSUMER, inject: ['anpIdentity'], apply(ctx: Context) { direct = ctx } })
  expect(resolveInstalledConsumer(f.ctx, direct)).toBeUndefined()
  expect(() => bindIdentityClient(direct)).toThrowError(expect.objectContaining({ code: 'consumer_forbidden' }))
  const forged = { options: { id: 'forged', name: ROOT_CONSUMER }, fiber: direct.fiber,
    loader: { store: f.ctx.loader.store }, parent: { tree: { ctx: direct, store: {} as Record<string, unknown> } } }
  forged.parent.tree.store.forged = forged
  const untrusted = direct.fiber as unknown as { entry?: unknown }
  untrusted.entry = forged
  expect(resolveInstalledConsumer(f.ctx, direct)).toBeUndefined()
  expect(() => bindIdentityClient(direct)).toThrowError(expect.objectContaining({ code: 'consumer_forbidden' }))
  delete untrusted.entry
  let child!: Context
  await f.contexts.get(ROOT_CONSUMER)!.plugin({ name: ROOT_CONSUMER, inject: ['anpIdentity'], apply(ctx: Context) { child = ctx } })
  expect((child.fiber as Fiber & { entry?: unknown }).entry).toBeDefined()
  expect(resolveInstalledConsumer(f.ctx, child)).toBeUndefined()
  expect(() => bindIdentityClient(child)).toThrowError(expect.objectContaining({ code: 'consumer_forbidden' }))
})

it.skipIf(!source)('revokes old HMR fibers and disabled/removed entries without borrowing another live entry with the same name', async () => {
  const f = await harness()
  const old = f.contexts.get(ROOT_CONSUMER)!
  const oldClient = bindIdentityClient(old)
  const entry = [...f.ctx.loader.entries()].find(candidate => candidate.options.name === ROOT_CONSUMER)!
  await entry.update({ name: '@fixture/spoofed-plugin-export' })
  expect(resolveInstalledConsumer(f.ctx, old)).toBeUndefined()
  await expect(oldClient.requestCreateIdentity({ requestId: 'stale-hmr', purpose: 'Must reject stale fiber', parameters: { label: 'Stale', domain: 'identity.example', path: '/stale' } })).rejects.toMatchObject({ code: 'consumer_forbidden' })
  await entry.update({ name: ROOT_CONSUMER })
  const current = f.contexts.get(ROOT_CONSUMER)!
  expect(current.fiber).not.toBe(old.fiber)
  expect(resolveInstalledConsumer(f.ctx, old)).toBeUndefined()
  const currentClient = bindIdentityClient(current)
  await f.ctx.loader.update(entry.id, { disabled: true })
  expect(resolveInstalledConsumer(f.ctx, current)).toBeUndefined()
  await expect(currentClient.getCreateRequest('absent')).rejects.toMatchObject({ code: 'consumer_forbidden' })
  await f.ctx.loader.update(entry.id, { disabled: false })
  const reenabled = f.contexts.get(ROOT_CONSUMER)!
  const reenabledClient = bindIdentityClient(reenabled)
  await f.ctx.loader.remove(entry.id)
  expect(resolveInstalledConsumer(f.ctx, reenabled)).toBeUndefined()
  await expect(reenabledClient.getCreateRequest('absent')).rejects.toMatchObject({ code: 'consumer_forbidden' })
})
