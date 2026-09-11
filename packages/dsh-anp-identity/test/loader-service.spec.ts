import { Context } from '@deepseek-ai/cordis'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, expect, it, vi } from 'vitest'
import AnpIdentityService from '../src/index.js'
import { openNativeProvider } from '../src/provider.js'
import type { NativeProviderRegistry } from '../src/provider-api.js'
import { bindIdentityClient } from '../src/user-client.js'

afterEach(() => vi.restoreAllMocks())

it('authenticates a real Loader-installed ordinary consumer against its actual fiber', async () => {
  const root = await mkdtemp(join(tmpdir(), 'anp-real-loader-'))
  const ctx = new Context()
  let consumerContext: Context | undefined
  let deniedContext: Context | undefined
  try {
    await ctx.plugin(Loader)
    const loader = ctx.loader
    const modules: Record<string, unknown> = {
      'identity-host': AnpIdentityService,
      'native-provider': {
        inject: ['anpIdentity'],
        async apply(providerContext: Context) {
          const registration = await openNativeProvider({
            stateRoot: root, rootKeyProvider: 'injected', rootKeyProviderId: 'actual-loader-test', injectedRootKey: Buffer.alloc(32, 91),
          })
          const dispose = (providerContext.anpIdentity as unknown as NativeProviderRegistry).registerProvider(registration)
          providerContext.effect(() => dispose, 'actual loader test: native Provider')
        },
      },
      'user-one': { inject: ['anpIdentity'], apply(context: Context) { consumerContext = context } },
      'denied-one': { inject: ['anpIdentity'], apply(context: Context) { deniedContext = context } },
    }
    // Only resolve local test modules here. Entry creation, isolation, services,
    // lifecycle and installed metadata are owned by the actual Cordis Loader.
    vi.spyOn(loader, 'import').mockImplementation((specifier: string) => {
      const module = modules[specifier]
      if (!module) throw new Error('Unexpected test module specifier')
      return module
    })
    await loader.create({ name: 'identity-host', config: {
      stateRoot: root, allowConsumers: ['user-one', 'trusted-host'], userConsumers: ['user-one'], allowProviderConsumers: ['trusted-host'],
      httpAllowedOrigins: { 'user-one': ['https://api.example.com'] },
    } })
    await loader.create({ name: 'native-provider' })
    await loader.create({ name: 'user-one' })
    await loader.create({ name: 'denied-one' })
    await loader.await()
    if (!consumerContext) throw new Error('The real Loader did not apply the consumer')
    const installed = [...loader.entries()].find(entry => entry.options.name === 'user-one')!
    expect(installed.fiber === consumerContext.fiber).toBe(false)
    expect(installed.fiber!.uid).toBe(consumerContext.fiber.uid)
    // registry.plugin() returns Object.create(realFiber) with a then method.
    // Loader retains that wrapper, while the plugin receives realFiber.ctx.
    expect(installed.fiber!.ctx.fiber === consumerContext.fiber).toBe(true)
    expect(installed.disabled).toBe(false)
    expect([1, 2]).toContain(installed.fiber!.state)
    const host = ctx.anpIdentity as AnpIdentityService
    await expect(host.health()).resolves.toMatchObject({ status: 'ready' })
    const ordinary = bindIdentityClient(consumerContext)
    if (!deniedContext) throw new Error('The real Loader did not apply the denied consumer')
    expect(() => bindIdentityClient(deniedContext!)).toThrowError(expect.objectContaining({ code: 'consumer_forbidden' }))
    const proxy = consumerContext.anpIdentity as AnpIdentityService
    await expect(proxy.acquireClient({ consumer: 'trusted-host', capabilities: ['identity:read', 'identity:create'] }))
      .rejects.toMatchObject({ code: 'consumer_forbidden' })
    expect(() => proxy.acquireProvider({ consumer: 'trusted-host', capabilities: ['IDENTITY_READ', 'IDENTITY_CREATE'] }))
      .toThrowError(expect.objectContaining({ code: 'consumer_forbidden' }))
    const request = await ordinary.requestCreateIdentity({
      requestId: 'real-loader-create', purpose: 'Verify the actual Loader ordinary plugin boundary',
      parameters: { label: 'Actual Loader identity', domain: 'example.com', path: '/actual-loader' },
    })
    expect(request).toMatchObject({ caller: { consumer: 'user-one' }, status: 'pending' })
    expect(await host.acquireManagement().listIdentities()).toEqual([])
    expect(() => (consumerContext!.anpIdentity as AnpIdentityService).acquireManagement()).toThrow()
    await host.acquireManagement().decide({ requestId: request.id, expectedVersion: request.version, decision: 'approve' })
    const identities = await host.acquireManagement().listIdentities()
    expect(identities).toHaveLength(1)
    const access = await ordinary.requestAccess({ requestId: 'real-loader-access', purpose: 'Disable cancels a real installed consumer request',
      identity: identities[0]!.reference, operation: { action: 'read' } })
    await loader.update(installed.id, { disabled: true })
    await expect.poll(async () => (await host.acquireManagement().getRequest(access.id)).request.status, { timeout: 2000 }).toBe('cancelled')
    expect(await host.acquireManagement().grants(identities[0]!.reference)).toEqual([])
  } finally {
    await ctx.fiber.dispose()
    await rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 20 })
  }
})
