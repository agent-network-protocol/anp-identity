/** Actual C/A/B callback fixture. Only synthetic external email delivery is substituted by B's owning bridge. */
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes, randomUUID } from 'node:crypto'
import { Context } from '@deepseek-ai/cordis'
import { IdentityProvider } from '../../../../bindings/node/provider.js'
import AnpIdentityService from '../../src/index.js'
import type { NativeProviderRegistry } from '../../src/provider-api.js'
import type { CreateAuthorizationRequest } from '../../src/authorization-types.js'
import { EncryptedManagementCredentialBroker } from '../../src/management-credentials.js'

/** Start production registration, Registry, device management and PAP publication in an isolated SQL environment.
 * @param options - Owning B source/environment and local identity method.
 * @returns A restricted callback capability and fixed-origin public callback transport; no native lease or credential is returned.
 */
export async function createManagedCallbackFixture(options: { source: string; python: string; profile?: 'e1' | 'web' }) {
  const origin = 'https://identity.example'
  const child = spawn(options.python, [join(options.source, 'tests/app/cimd/management_bridge.py')], { cwd: options.source,
    env: { ...process.env, CIMD_TEST_REAL_MANAGEMENT_BRIDGE: '1', PYTHONPATH: join(options.source, 'src') }, stdio: ['pipe', 'pipe', 'pipe'] })
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
    const timer = setTimeout(() => { stopped = true; fail(); child.kill('SIGTERM') }, timeoutMs)
    queue.push({ resolve, reject, timer })
    child.stdin.write(JSON.stringify(value) + '\n', error => { if (error) fail() })
  })
  const transport: typeof fetch = async input => {
    const request = input instanceof Request ? input : new Request(input)
    if (new URL(request.url).origin !== origin) throw new Error('callback_fixture_origin_mismatch')
    const response = await call({ action: 'request', method: request.method, url: request.url,
      headers: Object.fromEntries(request.headers), body: request.body ? await request.text() : null })
    return new Response(response.body, { status: response.status, headers: response.headers })
  }
  const root = await mkdtemp(join(tmpdir(), 'c-b-callback-'))
  const ctx = new Context()
  const encryptionKey = randomBytes(32)
  let closeDriver: (() => void) | undefined
  const dispose = async () => {
    closeDriver?.(); closeDriver = undefined
    if (!stopped) await call({ action: 'close' }).catch(() => {})
    if (child.exitCode === null) { child.stdin.end(); child.kill('SIGTERM') }
    await exited.catch(() => {}); await ctx.fiber.dispose(); encryptionKey.fill(0)
    await rm(root, { recursive: true, force: true })
  }
  try {
    // Readiness is an ordinary no-write 404, allowing the private MySQL bridge its bounded startup window.
    await call({ action: 'request', method: 'GET', url: origin + '/__component_ready', headers: {}, body: null }, 120000)
    const nativeRoot = randomBytes(32)
    const provider = await IdentityProvider.initialize({ stateRoot: root, rootKeyKind: 'injected', keyId: 'callback-component', rootKey: nativeRoot })
    nativeRoot.fill(0)
    const entries: Array<{ options: { name: string }; disabled: boolean; fiber: Context['fiber'] }> = []
    ctx.provide('loader', { *entries() { yield* entries } })
    await ctx.plugin(AnpIdentityService, { stateRoot: root, allowConsumers: ['@fixture/callback-creator'], userConsumers: ['@fixture/callback-creator'] })
    const service = ctx.anpIdentity as AnpIdentityService
    ;(service as unknown as NativeProviderRegistry).registerProvider({ protocol: 'anp-identity-node-provider/1', provider })
    await service.health()
    const installed = async (name: string) => {
      let context!: Context
      await ctx.plugin(Object.assign((value: Context) => { context = value }, { inject: ['anpIdentity'] }))
      entries.push({ options: { name }, disabled: false, fiber: context.fiber }); return context
    }
    const managementContext = await installed('@agent-network-protocol/dsh-anp-identity/management-remote')
    const creatorContext = await installed('@fixture/callback-creator')
    const managerService = managementContext.anpIdentity as AnpIdentityService
    const manager = managerService.acquireManagement(managementContext)
    const creator = (creatorContext.anpIdentity as AnpIdentityService).bindUserConsumer(creatorContext)
    const run = randomUUID().replaceAll('-', '')
    const profile = options.profile ?? 'web'
    const request = await creator.requestCreateIdentity({ requestId: 'create-callback', purpose: 'Create a registered PAP callback identity',
      parameters: { profile, usage: 'protocol', label: 'PAP callback', domain: 'identity.example', path: '/awiki/' + (profile === 'web' ? 'web/' : 'user/') + run } })
    const approved = await manager.decide({ requestId: request.id, expectedVersion: request.version, decision: 'approve' }) as CreateAuthorizationRequest
    if (!approved.result) throw new Error('callback_fixture_creation_failed')
    const reference = approved.result.reference
    const credentials = new EncryptedManagementCredentialBroker(join(root, 'management'), async () => Buffer.from(encryptionKey))
    await managerService.registerLocalIdentity(managementContext, { reference, origin, credentials, fetch: transport, managementAudience: 'awiki-user-service',
      registration: { handle: 'dsh-cimd-' + run, email: 'dsh-cimd-' + run + '@example.invalid', ...(profile === 'web' ? { registration_operation_id: randomUUID() } : {}) } })
    const driver = await managerService.configureManagedPublicationBackend(managementContext, 'callback', { reference, origin, credentials, fetch: transport })
    closeDriver = driver.dispose
    const published = await manager.publishIdentity({ reference, config: { backend: 'callback', documentId: driver.documentId, clientName: 'PAP callback component',
      redirectUris: [origin + '/user-service/v1/pap-callback'], activeKid: reference.did + '#oauth', capabilities: { mcpMachine: false, papSession: true, papAccount: true } } })
    if (published.state !== 'published' || !published.clientId) throw new Error('callback_fixture_publication_failed')
    return { callbackManagement: driver.callbackManagement, clientId: published.clientId, origin, fetch: transport, dispose }
  } catch (error) { await dispose(); throw error }
}
