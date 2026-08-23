import { Context } from '@deepseek-ai/cordis'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import type { CreateIdentityRequest as NativeCreateIdentityRequest } from '@agent-network-protocol/anp-identity'
import { IdentityProvider } from '@agent-network-protocol/anp-identity/provider'
import AnpIdentityService from '../src/index.js'
import { CatalogStore, CREATE_INTENT_SCHEMA, findEntry } from '../src/catalog.js'
import {
  ANP_IDENTITY_NATIVE_PROVIDER_PROTOCOL,
  type NativeIdentityProvider,
  type NativeProviderRegistry,
} from '../src/provider-api.js'
import { openNativeProvider } from '../src/provider.js'

const ALL_CLIENT_CAPABILITIES = [
  'identity:read',
  'identity:create',
  'identity:sign',
  'identity:document-update',
  'identity:http-auth',
  'identity:delete',
  'identity:recover',
  'identity:handle',
] as const

describe('DSH ANP Identity service', () => {
  it('creates multiple DIDs, signs through a purpose, dispatches HTTP, and survives restart', async () => {
    await using fixture = await serviceFixture(['third-party-demo'])
    const client = await fixture.ctx.anpIdentity.acquireClient({
      consumer: 'third-party-demo',
      capabilities: [...ALL_CLIENT_CAPABILITIES],
      httpOrigins: ['https://api.example.com'],
    })
    const alice = await client.create({
      identity: identitySpec('alice'),
      label: 'Alice',
      handle: 'alice.demo',
    })
    await client.create({ identity: identitySpec('bob'), handle: 'bob.demo' })
    const publicIdentity = await alice.publicIdentity()
    expect((await client.list()).map(value => value.handle)).toEqual(['alice.demo', 'bob.demo'])

    const payload = Buffer.from('third-party payload')
    const signature = await alice.sign({
      purpose: 'authentication',
      kid: `${publicIdentity.reference.did}#request`,
      payload,
    })
    await expect(alice.verify({
      purpose: 'authentication',
      kid: signature.kid,
      payload,
      signature: signature.bytes,
    })).resolves.toBe('valid')

    let transported: Request | undefined
    const response = await alice.authenticatedHttp.dispatch(
      new Request('https://api.example.com/messages', { method: 'POST', body: 'hello' }),
      async (request) => {
        transported = request
        return new Response('accepted', { status: 202 })
      },
    )
    expect(transported?.redirect).toBe('manual')
    expect(transported?.headers.has('signature-input')).toBe(true)
    expect(transported?.headers.has('signature')).toBe(true)
    await expect(response.text()).resolves.toBe('accepted')
    expect('prepareHttpSignature' in alice).toBe(false)
    let rejectedTransportCalled = false
    const rejectedTransport = async () => {
      rejectedTransportCalled = true
      return new Response()
    }
    await expect(alice.authenticatedHttp.dispatch(
      new Request('https://api.example.com/messages', {
        headers: { Authorization: 'Bearer caller-owned' },
      }),
      rejectedTransport,
    )).rejects.toMatchObject({ code: 'invalid_request' })
    await expect(alice.authenticatedHttp.dispatch(
      new Request('https://other.example.com/messages'),
      rejectedTransport,
    )).rejects.toMatchObject({ code: 'http_origin_forbidden' })
    await expect(alice.authenticatedHttp.dispatch(
      new Request('https://api.example.com/messages', {
        method: 'POST',
        body: new Uint8Array(4 * 1024 * 1024 + 1),
      }),
      rejectedTransport,
    )).rejects.toMatchObject({ code: 'http_body_too_large' })
    expect(rejectedTransportCalled).toBe(false)
    await client.dispose()

    const reference = publicIdentity.reference
    await fixture.restart()
    const reopened = await fixture.ctx.anpIdentity.acquireClient({
      consumer: 'third-party-demo',
      capabilities: ['identity:read', 'identity:sign'],
    })
    const reopenedAlice = await reopened.get({ handle: 'alice.demo' })
    const reopenedSignature = await reopenedAlice.sign({
      purpose: 'authentication',
      kid: `${reference.did}#request`,
      payload: Buffer.from('after restart'),
    })
    expect(reopenedSignature.bytes).toHaveLength(64)
    expect((await reopened.list())).toHaveLength(2)
  })

  it('fails closed for missing, duplicate, incompatible, and unauthorized Providers', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-anp-identity-provider-test-'))
    const ctx = new Context()
    try {
      await ctx.plugin(AnpIdentityService, {
        stateRoot: root,
        allowConsumers: ['allowed'],
        allowProviderConsumers: [],
      })
      await expect(ctx.anpIdentity.health()).resolves.toMatchObject({ status: 'unavailable' })
      await expect(ctx.anpIdentity.acquireClient({
        consumer: 'allowed',
        capabilities: ['identity:read'],
      })).rejects.toMatchObject({ code: 'provider_unavailable' })
      await expect(ctx.anpIdentity.acquireClient({
        consumer: 'denied',
        capabilities: ['identity:read'],
      })).rejects.toMatchObject({ code: 'consumer_forbidden' })
      expect(() => ctx.anpIdentity.acquireProvider({
        consumer: 'allowed',
        capabilities: ['IDENTITY_READ'],
      })).toThrowError(expect.objectContaining({ code: 'consumer_forbidden' }))

      const registry = ctx.anpIdentity as unknown as NativeProviderRegistry
      const dispose = registry.registerProvider(Promise.resolve({
        protocol: 'wrong/1',
        provider: {},
      } as never))
      expect(() => registry.registerProvider(Promise.resolve({} as never)))
        .toThrowError(expect.objectContaining({ code: 'provider_unavailable' }))
      await expect(ctx.anpIdentity.acquireClient({
        consumer: 'allowed',
        capabilities: ['identity:read'],
      })).rejects.toMatchObject({ code: 'provider_unavailable' })
      await dispose()
    } finally {
      await ctx.fiber.dispose()
      await rm(root, { recursive: true, force: true })
    }
  })

  it('enforces catalog grants, handle uniqueness, tombstones, and Provider disposal', async () => {
    await using fixture = await serviceFixture(['owner', 'consumer-two'])
    const owner = await fixture.ctx.anpIdentity.acquireClient({
      consumer: 'owner',
      capabilities: ['identity:read', 'identity:create', 'identity:delete', 'identity:handle'],
    })
    const identity = await owner.create({ identity: identitySpec('grants'), handle: 'shared.identity' })
    const reference = (await identity.publicIdentity()).reference
    const host = fixture.ctx.anpIdentity.acquireProvider({
      consumer: 'owner',
      capabilities: ['IDENTITY_READ'],
    })
    await host.grantConsumer(reference, 'consumer-two')
    await expect(owner.delete(reference)).rejects.toMatchObject({ code: 'identity_in_use' })
    await expect(owner.setHandle(reference, 'shared.identity')).resolves.toBeUndefined()
    const second = await fixture.ctx.anpIdentity.acquireClient({
      consumer: 'consumer-two',
      capabilities: ['identity:read'],
    })
    const secondIdentity = await second.get({ handle: 'shared.identity' })
    await expect(secondIdentity.sign({
      purpose: 'authentication',
      payload: Buffer.from('not authorized'),
    })).rejects.toMatchObject({ code: 'capability_forbidden' })
    await host.revokeConsumer(reference, 'consumer-two')
    await expect(owner.delete(reference)).resolves.toBeUndefined()
    await expect(second.get(reference)).rejects.toMatchObject({ code: 'identity_not_found' })

    const beforeDispose = await owner.create({ identity: identitySpec('disposed') })
    await fixture.disposeProvider()
    await expect(beforeDispose.publicIdentity()).rejects.toMatchObject({ code: 'provider_disposed' })
  })

  it('renews a long-lived Host Provider lease before its native token expires', async () => {
    await using fixture = await serviceFixture(['owner'])
    const host = fixture.ctx.anpIdentity.acquireProvider({
      consumer: 'owner',
      capabilities: ['IDENTITY_READ'],
      ttlSeconds: 3,
    })

    await new Promise(resolve => setTimeout(resolve, 3_200))
    await expect(host.list()).resolves.toEqual([])
    host.dispose()
  })

  it('removes a create intent when native creation definitively created nothing', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-anp-identity-create-retry-'))
    const ctx = await createContext(root, ['owner'])
    const registration = await openNativeProvider({
      stateRoot: root,
      rootKeyProvider: 'injected',
      rootKeyProviderId: 'dsh-test-root',
      injectedRootKey: Buffer.alloc(32, 17),
    })
    let rejectCreate = true
    const provider: NativeIdentityProvider = {
      acquireLease(request) {
        const lease = registration.provider.acquireLease(request)
        return new Proxy(lease, {
          get(target, property) {
            if (property === 'create') {
              return async (input: NativeCreateIdentityRequest) => {
                if (rejectCreate) {
                  rejectCreate = false
                  throw Object.assign(new Error('injected create failure'), {
                    code: 'provider_unavailable',
                    retryable: true,
                  })
                }
                return target.create(input)
              }
            }
            const value = Reflect.get(target, property, target)
            return typeof value === 'function' ? value.bind(target) : value
          },
        })
      },
    }
    const registry = ctx.anpIdentity as unknown as NativeProviderRegistry
    const dispose = registry.registerProvider({
      protocol: ANP_IDENTITY_NATIVE_PROVIDER_PROTOCOL,
      provider,
    })
    try {
      await waitForReady(ctx)
      const owner = await ctx.anpIdentity.acquireClient({
        consumer: 'owner',
        capabilities: ['identity:read', 'identity:create'],
      })
      const create = {
        identity: identitySpec('retry'),
        handle: 'retry.identity',
        requestId: 'retry-create',
      }
      await expect(owner.create(create)).rejects.toMatchObject({ code: 'provider_unavailable' })
      await expect(new CatalogStore(root).listIntents()).resolves.toEqual([])
      await expect(owner.create(create)).resolves.toBeDefined()
    } finally {
      await dispose()
      await ctx.fiber.dispose()
      await rm(root, { recursive: true, force: true })
    }
  })

  it('rebuilds a corrupt catalog as unclaimed without inventing grants', async () => {
    await using fixture = await serviceFixture(['owner'])
    const owner = await fixture.ctx.anpIdentity.acquireClient({
      consumer: 'owner',
      capabilities: ['identity:read', 'identity:create', 'identity:recover'],
    })
    await owner.create({ identity: identitySpec('corrupt'), handle: 'lost.handle' })
    await owner.dispose()
    await fixture.disposeProvider()
    await writeFile(join(fixture.root, 'catalog-v1.json'), '{corrupt', 'utf8')
    await fixture.registerProvider()
    await expect(fixture.ctx.anpIdentity.health()).resolves.toMatchObject({
      status: 'degraded',
      catalog: 'corrupt',
    })
    const recovery = await fixture.ctx.anpIdentity.acquireClient({
      consumer: 'owner',
      capabilities: ['identity:read', 'identity:recover'],
    })
    await expect(recovery.list()).rejects.toMatchObject({ code: 'catalog_corrupt' })
    await expect(recovery.recover()).resolves.toMatchObject({
      catalogRebuilt: true,
      unclaimedIdentityCount: 1,
    })
    await expect(recovery.list()).resolves.toEqual([])
    const raw = JSON.parse(await readFile(join(fixture.root, 'catalog-v1.json'), 'utf8'))
    expect(raw.entries).toMatchObject([{ state: 'unclaimed', grantedConsumers: [] }])
  })

  it('rolls create intents forward and completes deletion tombstones after restart', async () => {
    await using fixture = await serviceFixture(['owner'])
    await fixture.disposeProvider()
    const registration = await openNativeProvider({
      stateRoot: fixture.root,
      rootKeyProvider: 'injected',
      rootKeyProviderId: 'dsh-test-root',
      injectedRootKey: Buffer.alloc(32, 17),
    })
    const native = registration.provider.acquireLease({
      consumer: 'recovery-fixture',
      capabilities: ['IDENTITY_READ', 'IDENTITY_CREATE', 'IDENTITY_DELETE'],
      ttlSeconds: 300,
    })
    const baseline = await native.list()
    const catalog = new CatalogStore(fixture.root)
    await catalog.reserveIntent({
      schema: CREATE_INTENT_SCHEMA,
      requestId: 'crash-before-reference',
      consumer: 'owner',
      label: 'Recovered metadata',
      handle: 'recovered.intent',
      createdAt: '2026-08-23T00:00:00.000Z',
      baselineIdentityIds: baseline.map(value => value.reference.identityId),
    })
    const created = await native.create(identitySpec('intent-recovery'))
    native.dispose()

    await fixture.registerProvider()
    const owner = await fixture.ctx.anpIdentity.acquireClient({
      consumer: 'owner',
      capabilities: ['identity:read'],
    })
    await expect(owner.get({ handle: 'recovered.intent' })).resolves.toBeDefined()
    expect(await catalog.listIntents()).toEqual([])
    await owner.dispose()
    await fixture.disposeProvider()

    await catalog.mutate((current) => {
      const entry = findEntry(current, created.reference)
      if (entry === undefined) throw new Error('recovered catalog entry is missing')
      return {
        ...current,
        entries: current.entries.map(value => value.identityId === entry.identityId
          ? { ...value, state: 'deleting' as const }
          : value),
      }
    })
    await fixture.registerProvider()
    const host = fixture.ctx.anpIdentity.acquireProvider({
      consumer: 'owner',
      capabilities: ['IDENTITY_READ'],
    })
    expect((await host.list()).some(value => value.reference.identityId === created.reference.identityId))
      .toBe(false)
  })
})

async function serviceFixture(consumers: string[]) {
  const root = await mkdtemp(join(tmpdir(), 'dsh-anp-identity-service-'))
  let ctx = await createContext(root, consumers)
  let dispose = await register(ctx, root)
  return {
    root,
    get ctx() { return ctx },
    async disposeProvider() {
      await dispose()
    },
    async registerProvider() {
      dispose = await register(ctx, root)
    },
    async restart() {
      await ctx.fiber.dispose()
      ctx = await createContext(root, consumers)
      dispose = await register(ctx, root)
    },
    async [Symbol.asyncDispose]() {
      await ctx.fiber.dispose()
      await rm(root, { recursive: true, force: true })
    },
  }
}

async function createContext(root: string, consumers: string[]): Promise<Context> {
  const ctx = new Context()
  await ctx.plugin(AnpIdentityService, {
    stateRoot: root,
    allowConsumers: consumers,
    allowProviderConsumers: consumers,
    httpAllowedOrigins: Object.fromEntries(consumers.map(value => [value, ['https://api.example.com']])),
  })
  return ctx
}

async function register(ctx: Context, root: string): Promise<() => Promise<void>> {
  const registration = await openNativeProvider({
    stateRoot: root,
    rootKeyProvider: 'injected',
    rootKeyProviderId: 'dsh-test-root',
    injectedRootKey: Buffer.alloc(32, 17),
  })
  const registry = ctx.anpIdentity as unknown as NativeProviderRegistry
  const dispose = registry.registerProvider(registration)
  await waitForReady(ctx)
  return dispose
}

async function waitForReady(ctx: Context): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const health = await ctx.anpIdentity.health()
    if (health.status !== 'unavailable') return
    await new Promise<void>(resolve => setTimeout(resolve, 10))
  }
  throw new Error('ANP Identity Provider did not become ready')
}

function identitySpec(name: string): NativeCreateIdentityRequest {
  return {
    profile: 'e1',
    domain: 'example.com',
    pathSegments: ['dsh', name],
    capabilities: { didWba: true },
    managedKeys: [
      { fragment: 'root', role: 'root_control' },
      { fragment: 'request', role: 'request_signing' },
      { fragment: 'device', role: 'device_signing' },
      { fragment: 'application', role: 'e2ee_signing' },
      { fragment: 'agreement', role: 'e2ee_agreement' },
    ],
    extensions: [{
      type: 'device_manifest',
      value: {
        devices: [{
          deviceId: `${name}-device`,
          signingKeyId: '#device',
          e2eeKeyId: '#agreement',
          profiles: ['anp.core.binding.v1'],
        }],
      },
    }],
  }
}
