/** Host-only ANP Identity service for DeepSeek Harness. */

import { randomUUID } from 'node:crypto'
import { homedir } from 'node:os'
import { isAbsolute, join } from 'node:path'
import { Service, type Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type {
  CreateIdentityRequest as NativeCreateIdentityRequest,
  IdentityDescriptor as NativeIdentityDescriptor,
  IdentityReference,
  PublicIdentity,
} from '@agent-network-protocol/anp-identity'
import type * as NativeProvider from '@agent-network-protocol/anp-identity/provider'
import {
  CatalogStore,
  CATALOG_SCHEMA,
  CREATE_INTENT_SCHEMA,
  emptyCatalog,
  entryReference,
  findEntry,
  normalizeHandle,
  type CatalogEntry,
  type IdentityCatalog,
} from './catalog.js'
import { pluginError, AnpIdentityPluginError } from './errors.js'
import { createAuthenticatedHttp } from './http-auth.js'
import {
  ANP_IDENTITY_NATIVE_PROVIDER_PROTOCOL,
  ANP_IDENTITY_PROVIDER_PROTOCOL,
  ANP_IDENTITY_SERVICE_PROTOCOL,
  type AnpIdentityService as AnpIdentityServiceContract,
  type HostProviderLease,
  type NativeIdentityProvider,
  type NativeProviderRegistration,
  type ProviderRequest,
} from './provider-api.js'
import type {
  AnpIdentityHealth,
  ClientCapability,
  ClientRequest,
  CreateIdentityRequest,
  DeleteIdentityRequest,
  DocumentChangeSessionClient,
  IdentityClientLease,
  IdentityDescriptor,
  IdentityRef,
  ListIdentitiesInput,
  ManagedIdentityClient,
  RecoveryReport,
} from './types.js'

export type * from './types.js'
export { AnpIdentityPluginError } from './errors.js'
export type { AnpIdentityPluginErrorCode } from './errors.js'
export {
  ANP_IDENTITY_HTTP_MAX_BODY_BYTES,
} from './http-auth.js'
export {
  ANP_IDENTITY_PROVIDER_PROTOCOL,
  ANP_IDENTITY_SERVICE_PROTOCOL,
} from './provider-api.js'
export type {
  AnpIdentityService as AnpIdentityServiceContract,
  HostProviderLease,
  ProviderRequest,
} from './provider-api.js'

declare module '@deepseek-ai/cordis' {
  interface Context {
    anpIdentity: AnpIdentityServiceContract
  }
}

export interface Config {
  /** Absolute ANP Identity Store root. Defaults below DSH_HOME. */
  readonly stateRoot?: string
  /** Exact same-process consumer names permitted to acquire leases. */
  readonly allowConsumers?: string[]
  /** Narrow Host-only consumers permitted to acquire Provider leases. */
  readonly allowProviderConsumers?: string[]
  /** Exact HTTPS origins permitted per consumer for authenticated HTTP. */
  readonly httpAllowedOrigins?: Record<string, string[]>
  /** Run native Store recovery when a Provider opens. */
  readonly recoveryOnOpen?: boolean
}

export const Config: z<Config> = z.object({
  stateRoot: z.string(),
  allowConsumers: z.array(z.string()).default([]),
  allowProviderConsumers: z.array(z.string()).default([]),
  httpAllowedOrigins: z.dict(z.array(z.string())).default({}),
  recoveryOnOpen: z.boolean().default(true),
})

interface ResolvedConfig {
  readonly stateRoot: string
  readonly allowConsumers: ReadonlySet<string>
  readonly allowProviderConsumers: ReadonlySet<string>
  readonly httpAllowedOrigins: ReadonlyMap<string, ReadonlySet<string>>
  readonly recoveryOnOpen: boolean
}

interface ProviderSlot {
  readonly id: symbol
  readonly leases: Set<DisposableLease>
  readonly ready: Promise<NativeIdentityProvider>
  provider?: NativeIdentityProvider
  disposed: boolean
  initialized: boolean
  catalog: 'ready' | 'corrupt' | 'unavailable'
}

interface DisposableLease {
  dispose(): void | Promise<void>
}

interface InternalService {
  listForClient(lease: ClientLease, input: ListIdentitiesInput | undefined): Promise<IdentityDescriptor[]>
  createForClient(lease: ClientLease, input: CreateIdentityRequest): Promise<ManagedIdentityClient>
  getForClient(lease: ClientLease, reference: IdentityRef): Promise<ManagedIdentityClient>
  deleteForClient(lease: ClientLease, reference: IdentityRef, input?: DeleteIdentityRequest): Promise<void>
  recoverForClient(lease: ClientLease): Promise<RecoveryReport>
  setHandleForClient(lease: ClientLease, reference: IdentityRef, handle: string | null): Promise<void>
  assertManagedAccess(lease: ClientLease, reference: IdentityReference): Promise<void>
  grantConsumer(slot: ProviderSlot, reference: IdentityReference, consumer: string): Promise<void>
  revokeConsumer(slot: ProviderSlot, reference: IdentityReference, consumer: string): Promise<void>
  createForHost(
    slot: ProviderSlot,
    native: NativeProvider.ProviderLease,
    consumer: string,
    request: NativeCreateIdentityRequest,
  ): Promise<PublicIdentity>
  deleteForHost(
    slot: ProviderSlot,
    native: NativeProvider.ProviderLease,
    consumer: string,
    reference: IdentityReference,
  ): Promise<void>
  removeLease(slot: ProviderSlot, lease: DisposableLease): void
}

const CLIENT_CAPABILITIES = new Set<ClientCapability>([
  'identity:read',
  'identity:create',
  'identity:sign',
  'identity:document-update',
  'identity:http-auth',
  'identity:delete',
  'identity:recover',
  'identity:handle',
])

const ALL_PROVIDER_CAPABILITIES: NativeProvider.ProviderCapability[] = [
  'IDENTITY_READ',
  'IDENTITY_CREATE',
  'IDENTITY_IMPORT',
  'IDENTITY_SIGN',
  'IDENTITY_ECDH_SEALED',
  'IDENTITY_DOCUMENT_UPDATE',
  'IDENTITY_KEY_LIFECYCLE',
  'IDENTITY_DELETE',
  'IDENTITY_HTTP_SIGNATURE',
  'AWIKI_LEGACY_ROOT_TRANSFER_V1',
]

const HOST_LEASE_RENEWAL_SKEW_MS = 60_000

/** One multi-DID ANP Identity service with a replaceable native Provider. */
export class AnpIdentityService extends Service implements AnpIdentityServiceContract {
  static Config = Config

  private readonly resolvedConfig: ResolvedConfig
  private readonly catalogStore: CatalogStore
  private providerSlot: ProviderSlot | undefined

  public constructor(ctx: Context, config: Config) {
    super(ctx, 'anpIdentity')
    this.resolvedConfig = resolveConfig(config)
    this.catalogStore = new CatalogStore(this.resolvedConfig.stateRoot)
    ctx.effect(() => async () => {
      const slot = this.providerSlot
      if (slot !== undefined) await this.disposeSlot(slot)
    }, 'anp-identity: dispose native provider')
  }

  async health(): Promise<AnpIdentityHealth> {
    const slot = this.providerSlot
    if (slot === undefined || slot.disposed) {
      return {
        status: 'unavailable',
        protocol: ANP_IDENTITY_SERVICE_PROTOCOL,
        catalog: 'unavailable',
      }
    }
    try {
      await slot.ready
    } catch {
      return {
        status: 'unavailable',
        protocol: ANP_IDENTITY_SERVICE_PROTOCOL,
        catalog: slot.catalog,
      }
    }
    return {
      status: slot.catalog === 'ready' ? 'ready' : 'degraded',
      protocol: ANP_IDENTITY_SERVICE_PROTOCOL,
      providerProtocol: ANP_IDENTITY_PROVIDER_PROTOCOL,
      catalog: slot.catalog,
    }
  }

  private registerProvider(
    registration: Promise<NativeProviderRegistration> | NativeProviderRegistration,
  ): () => Promise<void> {
    if (this.providerSlot !== undefined) throw pluginError('provider_unavailable')
    const slot: ProviderSlot = {
      id: Symbol('anp-identity-provider'),
      leases: new Set(),
      disposed: false,
      initialized: false,
      catalog: 'unavailable',
      ready: Promise.resolve(registration).then(async (value) => {
        if (slot.disposed) throw pluginError('provider_disposed')
        const provider = validateRegistration(value)
        slot.provider = provider
        await this.initializeSlot(slot, provider)
        if (slot.disposed) throw pluginError('provider_disposed')
        slot.initialized = true
        return provider
      }),
    }
    this.providerSlot = slot
    void slot.ready.catch(() => {})
    return () => this.disposeSlot(slot)
  }

  async acquireClient(input: ClientRequest): Promise<IdentityClientLease> {
    const request = validateClientRequest(input, this.resolvedConfig)
    const slot = this.requireSlot()
    const provider = await this.awaitProvider(slot)
    const capabilities = nativeClientCapabilities(request.capabilities)
    let native: NativeProvider.ProviderLease
    try {
      native = provider.acquireLease({
        consumer: request.consumer,
        capabilities,
        ttlSeconds: request.ttlSeconds,
      })
    } catch (error) {
      throw mapNativeError(error)
    }
    const lease = new ClientLease(
      this as unknown as InternalService,
      slot,
      native,
      request.consumer,
      request.capabilities,
      request.httpOrigins,
      Date.now() + request.ttlSeconds * 1_000,
    )
    slot.leases.add(lease)
    return lease
  }

  acquireProvider(input: ProviderRequest): HostProviderLease {
    const request = validateProviderRequest(input, this.resolvedConfig)
    const slot = this.requireSlot()
    const provider = slot.provider
    if (provider === undefined || !slot.initialized) throw pluginError('provider_unavailable')
    let native: NativeProvider.ProviderLease
    try {
      native = provider.acquireLease({
        consumer: request.consumer,
        capabilities: [...request.capabilities],
        ttlSeconds: request.ttlSeconds,
      })
    } catch (error) {
      throw mapNativeError(error)
    }
    const lease = new HostLease(
      this as unknown as InternalService,
      slot,
      provider,
      native,
      request.consumer,
      request.capabilities,
      request.ttlSeconds,
    )
    slot.leases.add(lease)
    return lease
  }

  private async listForClient(
    lease: ClientLease,
    input: ListIdentitiesInput | undefined,
  ): Promise<IdentityDescriptor[]> {
    lease.assertCapability('identity:read')
    const catalog = await this.loadCatalog(lease.slot)
    const native = await nativeCall(() => lease.native.list())
    const byId = new Map(native.map(value => [value.reference.identityId, value]))
    const output: IdentityDescriptor[] = []
    for (const entry of catalog.entries) {
      if (entry.state !== 'active' || !entry.grantedConsumers.includes(lease.consumer)) continue
      const descriptor = byId.get(entry.identityId)
      if (descriptor === undefined || (input?.state !== undefined && descriptor.state !== input.state)) continue
      output.push({
        ...descriptor,
        ...(entry.label === undefined ? {} : { label: entry.label }),
        ...(entry.handle === undefined ? {} : { handle: entry.handle }),
        catalogState: entry.state,
      })
    }
    return output.sort((left, right) => left.reference.did.localeCompare(right.reference.did))
  }

  private async createForClient(
    lease: ClientLease,
    input: CreateIdentityRequest,
  ): Promise<ManagedIdentityClient> {
    lease.assertCapability('identity:create')
    validateCreateInput(input)
    const requestId = input.requestId ?? randomUUID()
    const createdAt = new Date().toISOString()
    await this.catalogStore.reserveIntent({
      schema: CREATE_INTENT_SCHEMA,
      requestId,
      consumer: lease.consumer,
      ...(input.label === undefined ? {} : { label: input.label }),
      ...(input.handle === undefined ? {} : { handle: normalizeHandle(input.handle) }),
      createdAt,
      baselineIdentityIds: [],
    })
    let identity: PublicIdentity
    try {
      identity = await this.catalogStore.withNativeCreateLock(async () => {
        lease.assertCapability('identity:create')
        const baseline = await nativeCall(() => lease.native.list())
        await this.catalogStore.updateIntent(requestId, current => ({
          ...current,
          baselineIdentityIds: baseline.map(value => value.reference.identityId).sort(),
        }))
        const created = await nativeCall(() => lease.native.create(input.identity))
        await this.catalogStore.updateIntent(requestId, current => ({
          ...current,
          reference: created.reference,
        }))
        return created
      })
      await this.catalogStore.commitIntent(requestId)
      await this.catalogStore.deleteIntent(requestId)
    } catch (error) {
      throw mapOperationError(error)
    }
    return new ManagedClient(this as unknown as InternalService, lease, identity.reference, identity)
  }

  private async getForClient(lease: ClientLease, reference: IdentityRef): Promise<ManagedIdentityClient> {
    lease.assertCapability('identity:read')
    const resolved = await this.resolveAuthorized(lease, reference)
    return new ManagedClient(this as unknown as InternalService, lease, resolved)
  }

  private async deleteForClient(
    lease: ClientLease,
    reference: IdentityRef,
    _input?: DeleteIdentityRequest,
  ): Promise<void> {
    lease.assertCapability('identity:delete')
    const resolved = await this.resolveAuthorized(lease, reference)
    await this.catalogStore.mutate((catalog) => {
      const entry = findEntry(catalog, resolved)
      if (entry === undefined) throw pluginError('identity_not_found')
      if (entry.state !== 'active') throw pluginError('identity_deleting')
      if (entry.grantedConsumers.some(consumer => consumer !== lease.consumer)) {
        throw pluginError('identity_in_use')
      }
      return replaceEntry(catalog, entry, { ...entry, state: 'deleting' })
    })
    await nativeCall(() => lease.native.delete(resolved))
    await this.catalogStore.mutate(catalog => ({
      ...catalog,
      entries: catalog.entries.filter(entry => entry.identityId !== resolved.identityId),
    }))
  }

  private async recoverForClient(lease: ClientLease): Promise<RecoveryReport> {
    lease.assertCapability('identity:recover')
    const native = await nativeCall(() => lease.native.recover())
    const report = await this.reconcile(lease.slot, lease.native, true, false)
    return { ...native, ...report }
  }

  private async setHandleForClient(
    lease: ClientLease,
    reference: IdentityRef,
    handle: string | null,
  ): Promise<void> {
    lease.assertCapability('identity:handle')
    const resolved = await this.resolveAuthorized(lease, reference)
    const normalized = handle === null ? undefined : normalizeHandle(handle)
    await this.catalogStore.mutate((catalog) => {
      const entry = findEntry(catalog, resolved)
      assertGrantedEntry(entry, lease.consumer)
      if (normalized !== undefined
        && catalog.entries.some(candidate => candidate.identityId !== entry.identityId
          && candidate.handle === normalized)) {
        throw pluginError('handle_conflict')
      }
      const { handle: _currentHandle, ...withoutHandle } = entry
      return replaceEntry(catalog, entry, {
        ...withoutHandle,
        ...(normalized === undefined ? {} : { handle: normalized }),
      })
    })
  }

  private async assertManagedAccess(lease: ClientLease, reference: IdentityReference): Promise<void> {
    lease.assertActive()
    const catalog = await this.loadCatalog(lease.slot)
    assertGrantedEntry(findEntry(catalog, reference), lease.consumer)
  }

  private async grantConsumer(
    slot: ProviderSlot,
    reference: IdentityReference,
    consumer: string,
  ): Promise<void> {
    this.assertAllowedConsumer(consumer)
    this.assertSlot(slot)
    await this.catalogStore.mutate((catalog) => {
      const entry = findEntry(catalog, reference)
      if (entry === undefined) throw pluginError('identity_not_found')
      if (entry.state === 'deleting') throw pluginError('identity_deleting')
      return replaceEntry(catalog, entry, {
        ...entry,
        state: 'active',
        grantedConsumers: [...new Set([...entry.grantedConsumers, consumer])].sort(),
      })
    })
  }

  private async revokeConsumer(
    slot: ProviderSlot,
    reference: IdentityReference,
    consumer: string,
  ): Promise<void> {
    this.assertSlot(slot)
    await this.catalogStore.mutate((catalog) => {
      const entry = findEntry(catalog, reference)
      if (entry === undefined) throw pluginError('identity_not_found')
      if (entry.state !== 'active') throw pluginError('identity_deleting')
      const grantedConsumers = entry.grantedConsumers.filter(value => value !== consumer)
      return replaceEntry(catalog, entry, {
        ...entry,
        grantedConsumers,
        state: grantedConsumers.length === 0 ? 'unclaimed' : 'active',
      })
    })
  }

  private async createForHost(
    slot: ProviderSlot,
    native: NativeProvider.ProviderLease,
    consumer: string,
    request: NativeCreateIdentityRequest,
  ): Promise<PublicIdentity> {
    this.assertSlot(slot)
    const requestId = randomUUID()
    const createdAt = new Date().toISOString()
    await this.catalogStore.reserveIntent({
      schema: CREATE_INTENT_SCHEMA,
      requestId,
      consumer,
      createdAt,
      baselineIdentityIds: [],
    })
    try {
      const identity = await this.catalogStore.withNativeCreateLock(async () => {
        this.assertSlot(slot)
        const baseline = await nativeCall(() => native.list())
        await this.catalogStore.updateIntent(requestId, current => ({
          ...current,
          baselineIdentityIds: baseline.map(value => value.reference.identityId).sort(),
        }))
        const created = await nativeCall(() => native.create(request))
        await this.catalogStore.updateIntent(requestId, current => ({
          ...current,
          reference: created.reference,
        }))
        return created
      })
      await this.catalogStore.commitIntent(requestId)
      await this.catalogStore.deleteIntent(requestId)
      return identity
    } catch (error) {
      throw mapOperationError(error)
    }
  }

  private async deleteForHost(
    slot: ProviderSlot,
    native: NativeProvider.ProviderLease,
    consumer: string,
    reference: IdentityReference,
  ): Promise<void> {
    this.assertSlot(slot)
    let catalogEntry: CatalogEntry | undefined
    try {
      const catalog = await this.loadCatalog(slot)
      catalogEntry = findEntry(catalog, reference)
    } catch (error) {
      if (!isPluginCode(error, 'catalog_corrupt')) throw error
      throw pluginError('catalog_corrupt')
    }
    if (catalogEntry !== undefined) {
      if (catalogEntry.state === 'deleting') throw pluginError('identity_deleting')
      if (catalogEntry.grantedConsumers.some(value => value !== consumer)) {
        throw pluginError('identity_in_use')
      }
      await this.catalogStore.mutate(catalog => {
        const entry = findEntry(catalog, reference)
        if (entry === undefined) throw pluginError('identity_not_found')
        return replaceEntry(catalog, entry, { ...entry, state: 'deleting' })
      })
    }
    await nativeCall(() => native.delete(reference))
    if (catalogEntry !== undefined) {
      await this.catalogStore.mutate(catalog => ({
        ...catalog,
        entries: catalog.entries.filter(entry => entry.identityId !== reference.identityId),
      }))
    }
  }

  private removeLease(slot: ProviderSlot, lease: DisposableLease): void {
    slot.leases.delete(lease)
  }

  private async initializeSlot(slot: ProviderSlot, provider: NativeIdentityProvider): Promise<void> {
    try {
      await this.catalogStore.initialize()
      slot.catalog = 'ready'
    } catch (error) {
      if (isPluginCode(error, 'catalog_corrupt')) slot.catalog = 'corrupt'
      else throw error
    }
    const native = provider.acquireLease({
      consumer: '@agent-network-protocol/dsh-anp-identity',
      capabilities: ALL_PROVIDER_CAPABILITIES,
      ttlSeconds: 3_600,
    })
    try {
      if (this.resolvedConfig.recoveryOnOpen) await nativeCall(() => native.recover())
      await this.reconcile(slot, native, false, false)
    } finally {
      native.dispose()
    }
  }

  private async reconcile(
    slot: ProviderSlot,
    native: NativeProvider.ProviderLease,
    rebuildCorrupt: boolean,
    runNativeRecovery: boolean,
  ): Promise<Pick<RecoveryReport, 'catalogRebuilt' | 'unclaimedIdentityCount'>> {
    if (runNativeRecovery) await nativeCall(() => native.recover())
    const descriptors = await nativeCall(() => native.list())
    const storeById = new Map(descriptors.map(value => [value.reference.identityId, value.reference]))
    let catalog: IdentityCatalog
    try {
      catalog = await this.catalogStore.load()
      slot.catalog = 'ready'
    } catch (error) {
      if (!isPluginCode(error, 'catalog_corrupt')) throw error
      slot.catalog = 'corrupt'
      if (!rebuildCorrupt) {
        return { catalogRebuilt: false, unclaimedIdentityCount: descriptors.length }
      }
      catalog = await this.catalogStore.replace({
        ...emptyCatalog(),
        entries: descriptors.map(value => unclaimedEntry(value.reference)),
      })
      slot.catalog = 'ready'
      return { catalogRebuilt: true, unclaimedIdentityCount: catalog.entries.length }
    }

    for (const intent of await this.catalogStore.listIntents()) {
      let reference = intent.reference
      if (reference === undefined) {
        const baseline = new Set(intent.baselineIdentityIds)
        const known = new Set(catalog.entries.map(value => value.identityId))
        const candidates = descriptors
          .map(value => value.reference)
          .filter(value => !baseline.has(value.identityId) && !known.has(value.identityId))
        if (candidates.length === 1) {
          const recovered = candidates[0]!
          reference = recovered
          await this.catalogStore.updateIntent(intent.requestId, current => ({
            ...current,
            reference: recovered,
          }))
        } else if (candidates.length === 0) {
          await this.catalogStore.deleteIntent(intent.requestId)
          continue
        } else {
          for (const candidate of candidates) {
            catalog = await addUnclaimed(this.catalogStore, catalog, candidate)
          }
          await this.catalogStore.deleteIntent(intent.requestId)
          continue
        }
      }
      const storedReference = storeById.get(reference.identityId)
      if (storedReference === undefined || !sameReference(storedReference, reference)) {
        await this.catalogStore.deleteIntent(intent.requestId)
        continue
      }
      await this.catalogStore.commitIntent(intent.requestId)
      await this.catalogStore.deleteIntent(intent.requestId)
      catalog = await this.catalogStore.load()
    }

    catalog = await this.catalogStore.load()
    for (const entry of catalog.entries.filter(value => value.state === 'deleting')) {
      const reference = storeById.get(entry.identityId)
      if (reference !== undefined) {
        await nativeCall(() => native.delete(reference))
        storeById.delete(entry.identityId)
      }
    }
    catalog = await this.catalogStore.mutate(current => ({
      ...current,
      entries: current.entries.filter(entry =>
        entry.state !== 'deleting'
        && sameReference(storeById.get(entry.identityId), entryReference(entry))),
    }))
    const known = new Set(catalog.entries.map(value => value.identityId))
    for (const reference of storeById.values()) {
      if (!known.has(reference.identityId)) {
        catalog = await addUnclaimed(this.catalogStore, catalog, reference)
        known.add(reference.identityId)
      }
    }
    return {
      catalogRebuilt: false,
      unclaimedIdentityCount: catalog.entries.filter(value => value.state === 'unclaimed').length,
    }
  }

  private async resolveAuthorized(
    lease: ClientLease,
    reference: IdentityRef,
  ): Promise<IdentityReference> {
    lease.assertActive()
    const catalog = await this.loadCatalog(lease.slot)
    const entry = 'handle' in reference
      ? catalog.entries.find(value => value.handle === normalizeHandle(reference.handle))
      : findEntry(catalog, reference)
    assertGrantedEntry(entry, lease.consumer)
    return entryReference(entry)
  }

  private async loadCatalog(slot: ProviderSlot): Promise<IdentityCatalog> {
    this.assertSlot(slot)
    if (slot.catalog === 'corrupt') throw pluginError('catalog_corrupt')
    try {
      return await this.catalogStore.load()
    } catch (error) {
      if (isPluginCode(error, 'catalog_corrupt')) slot.catalog = 'corrupt'
      throw error
    }
  }

  private assertAllowedConsumer(consumer: string): void {
    validateConsumer(consumer)
    if (!this.resolvedConfig.allowConsumers.has(consumer)) throw pluginError('consumer_forbidden')
  }

  private requireSlot(): ProviderSlot {
    const slot = this.providerSlot
    if (slot === undefined || slot.disposed) throw pluginError('provider_unavailable')
    return slot
  }

  private assertSlot(slot: ProviderSlot): void {
    if (slot.disposed || this.providerSlot?.id !== slot.id) throw pluginError('provider_disposed')
  }

  private async awaitProvider(slot: ProviderSlot): Promise<NativeIdentityProvider> {
    this.assertSlot(slot)
    try {
      const provider = await slot.ready
      this.assertSlot(slot)
      return provider
    } catch (error) {
      if (isPluginCode(error, 'provider_disposed')) throw error
      throw pluginError('provider_unavailable')
    }
  }

  private async disposeSlot(slot: ProviderSlot): Promise<void> {
    if (slot.disposed) return
    slot.disposed = true
    if (this.providerSlot?.id === slot.id) this.providerSlot = undefined
    for (const lease of [...slot.leases]) await lease.dispose()
    slot.leases.clear()
  }
}

class ClientLease implements IdentityClientLease, DisposableLease {
  readonly capabilities: readonly ClientCapability[]
  readonly httpOrigins: ReadonlySet<string>
  #disposed = false

  constructor(
    readonly service: InternalService,
    readonly slot: ProviderSlot,
    readonly native: NativeProvider.ProviderLease,
    readonly consumer: string,
    capabilities: readonly ClientCapability[],
    httpOrigins: ReadonlySet<string>,
    readonly expiresAt: number,
  ) {
    this.capabilities = Object.freeze([...capabilities])
    this.httpOrigins = httpOrigins
  }

  list(input?: ListIdentitiesInput): Promise<IdentityDescriptor[]> {
    return this.service.listForClient(this, input)
  }

  create(input: CreateIdentityRequest): Promise<ManagedIdentityClient> {
    return this.service.createForClient(this, input)
  }

  get(reference: IdentityRef): Promise<ManagedIdentityClient> {
    return this.service.getForClient(this, reference)
  }

  delete(reference: IdentityRef, input?: DeleteIdentityRequest): Promise<void> {
    return this.service.deleteForClient(this, reference, input)
  }

  recover(): Promise<RecoveryReport> {
    return this.service.recoverForClient(this)
  }

  setHandle(reference: IdentityRef, handle: string | null): Promise<void> {
    return this.service.setHandleForClient(this, reference, handle)
  }

  async dispose(): Promise<void> {
    if (this.#disposed) return
    this.#disposed = true
    this.native.dispose()
    this.service.removeLease(this.slot, this)
  }

  assertActive(): void {
    if (this.#disposed || this.slot.disposed || Date.now() >= this.expiresAt) {
      throw pluginError('provider_disposed')
    }
  }

  assertCapability(capability: ClientCapability): void {
    this.assertActive()
    if (!this.capabilities.includes(capability)) throw pluginError('capability_forbidden')
  }
}

class ManagedClient implements ManagedIdentityClient {
  readonly authenticatedHttp
  private cachedIdentity: PublicIdentity | undefined

  constructor(
    readonly service: InternalService,
    readonly lease: ClientLease,
    readonly reference: IdentityReference,
    identity?: PublicIdentity,
  ) {
    this.cachedIdentity = identity
    this.authenticatedHttp = createAuthenticatedHttp(
      reference,
      lease.native,
      lease.httpOrigins,
      async () => {
        lease.assertCapability('identity:http-auth')
        await service.assertManagedAccess(lease, reference)
      },
      () => this.requestSigningKid(),
    )
  }

  async publicIdentity() {
    this.lease.assertCapability('identity:read')
    await this.service.assertManagedAccess(this.lease, this.reference)
    const identity = await nativeCall(() => this.lease.native.publicIdentity(this.reference))
    this.cachedIdentity = identity
    return identity
  }

  async sign(request: import('./types.js').SignRequest) {
    this.lease.assertCapability('identity:sign')
    await this.service.assertManagedAccess(this.lease, this.reference)
    return nativeCall(() => this.lease.native.sign(this.reference, request))
  }

  async signOriginProof(request: import('./types.js').OriginProofRequest) {
    this.lease.assertCapability('identity:sign')
    await this.service.assertManagedAccess(this.lease, this.reference)
    return nativeCall(() => this.lease.native.signOriginProof(this.reference, request))
  }

  async verify(request: import('./types.js').VerifyRequest) {
    this.lease.assertCapability('identity:read')
    await this.service.assertManagedAccess(this.lease, this.reference)
    return nativeCall(() => this.lease.native.verify(this.reference, request))
  }

  async prepareDocumentChange(request: import('./types.js').DocumentChangeRequest) {
    this.lease.assertCapability('identity:document-update')
    await this.service.assertManagedAccess(this.lease, this.reference)
    const session = await nativeCall(() => this.lease.native.prepareDocumentChange(this.reference, request))
    return new DocumentChangeClient(
      this.service,
      this.lease,
      this.reference,
      session,
      identity => { this.cachedIdentity = identity },
    )
  }

  async resumeDocumentChange() {
    this.lease.assertCapability('identity:document-update')
    await this.service.assertManagedAccess(this.lease, this.reference)
    const session = await nativeCall(() => this.lease.native.resumeDocumentChange(this.reference))
    return session === undefined
      ? undefined
      : new DocumentChangeClient(
          this.service,
          this.lease,
          this.reference,
          session,
          identity => { this.cachedIdentity = identity },
        )
  }

  private async requestSigningKid(): Promise<string> {
    const identity = this.cachedIdentity ?? await this.publicIdentity()
    const candidates = identity.activeKeys.filter(key =>
      key.algorithm === 'ed25519'
      && key.purposes.includes('authentication')
      && key.purposes.includes('application_assertion'))
    if (candidates.length !== 1) throw pluginError('provider_incompatible')
    return candidates[0]!.kid
  }
}

class DocumentChangeClient implements DocumentChangeSessionClient {
  constructor(
    readonly service: InternalService,
    readonly lease: ClientLease,
    readonly reference: IdentityReference,
    readonly native: NativeProvider.ProviderDocumentChangeSession,
    readonly updateIdentity: (identity: PublicIdentity) => void,
  ) {}

  async candidate() {
    await this.assertActive()
    return nativeCall(() => this.native.candidate())
  }

  async beginPublication() {
    await this.assertActive()
    return nativeCall(() => this.native.beginPublication())
  }

  async complete(
    attempt: import('./types.js').PublicationAttempt,
    result: import('./types.js').PublicationResult,
  ) {
    await this.assertActive()
    const outcome = await nativeCall(() => this.native.complete(attempt, result))
    if (outcome.outcome === 'committed') this.updateIdentity(outcome.identity)
    return outcome
  }

  async reconcile(observation: import('./types.js').VerifiedRemoteDocument) {
    await this.assertActive()
    const outcome = await nativeCall(() => this.native.reconcile(observation))
    if (outcome.outcome === 'committed') this.updateIdentity(outcome.identity)
    return outcome
  }

  private async assertActive(): Promise<void> {
    this.lease.assertCapability('identity:document-update')
    await this.service.assertManagedAccess(this.lease, this.reference)
  }
}

class HostLease implements HostProviderLease, DisposableLease {
  readonly protocol = ANP_IDENTITY_PROVIDER_PROTOCOL
  readonly capabilities: readonly NativeProvider.ProviderCapability[]
  #disposed = false
  #native: NativeProvider.ProviderLease
  #expiresAt: number
  #renewAt: number
  readonly #retired = new Map<NativeProvider.ProviderLease, ReturnType<typeof setTimeout>>()

  constructor(
    readonly service: InternalService,
    readonly slot: ProviderSlot,
    readonly provider: NativeIdentityProvider,
    native: NativeProvider.ProviderLease,
    readonly consumer: string,
    capabilities: readonly NativeProvider.ProviderCapability[],
    readonly ttlSeconds: number,
  ) {
    this.capabilities = Object.freeze([...capabilities])
    this.#native = native
    const now = Date.now()
    this.#expiresAt = now + ttlSeconds * 1_000
    this.#renewAt = renewalAt(now, ttlSeconds)
  }

  dispose(): void {
    if (this.#disposed) return
    this.#disposed = true
    this.#native.dispose()
    for (const [native, timer] of this.#retired) {
      clearTimeout(timer)
      native.dispose()
    }
    this.#retired.clear()
    this.service.removeLease(this.slot, this)
  }

  info = () => this.call('IDENTITY_READ', () => this.native.info())
  recover = () => this.call('IDENTITY_READ', () => this.native.recover())
  list = () => this.call('IDENTITY_READ', () => this.native.list())
  publicIdentity = (reference: IdentityReference) =>
    this.call('IDENTITY_READ', () => this.native.publicIdentity(reference))
  hostStatus = (reference: IdentityReference) =>
    this.call('IDENTITY_READ', () => this.native.hostStatus(reference))
  recoverIdentity = (reference: IdentityReference) =>
    this.call('IDENTITY_READ', () => this.native.recoverIdentity(reference))
  create = (request: NativeCreateIdentityRequest) =>
    this.call('IDENTITY_CREATE', () => this.service.createForHost(
      this.slot,
      this.native,
      this.consumer,
      request,
    ))
  delete = (reference: IdentityReference) =>
    this.call('IDENTITY_DELETE', () => this.service.deleteForHost(
      this.slot,
      this.native,
      this.consumer,
      reference,
    ))
  sign = (reference: IdentityReference, request: import('./types.js').SignRequest) =>
    this.call('IDENTITY_SIGN', () => this.native.sign(reference, request))
  verify = (reference: IdentityReference, request: import('./types.js').VerifyRequest) =>
    this.call('IDENTITY_READ', () => this.native.verify(reference, request))
  signOriginProof = (reference: IdentityReference, request: import('./types.js').OriginProofRequest) =>
    this.call('IDENTITY_SIGN', () => this.native.signOriginProof(reference, request))
  signObjectProof = (reference: IdentityReference, request: NativeProvider.ObjectProofRequest) =>
    this.call('IDENTITY_SIGN', () => this.native.signObjectProof(reference, request))
  signDocumentProof = (reference: IdentityReference, request: NativeProvider.DocumentProofRequest) =>
    this.call('IDENTITY_SIGN', () => this.native.signDocumentProof(reference, request))
  prepareHttpSignature = (request: NativeProvider.ExactHttpSigningRequest) =>
    this.call('IDENTITY_HTTP_SIGNATURE', () => this.native.prepareHttpSignature(request))
  prepareLegacyDidWba = (reference: IdentityReference, request: NativeProvider.LegacyDidWbaRequest) =>
    this.call('IDENTITY_HTTP_SIGNATURE', () => this.native.prepareLegacyDidWba(reference, request))
  prepareDocumentChange = (
    reference: IdentityReference,
    request: import('./types.js').DocumentChangeRequest,
  ) => this.call('IDENTITY_DOCUMENT_UPDATE', () => this.native.prepareDocumentChange(reference, request))
  resumeDocumentChange = (reference: IdentityReference) =>
    this.call('IDENTITY_DOCUMENT_UPDATE', () => this.native.resumeDocumentChange(reference))
  adoptVerifiedDocument = (
    reference: IdentityReference,
    remote: import('./types.js').VerifiedRemoteDocument,
  ) => this.call('IDENTITY_DOCUMENT_UPDATE', () => this.native.adoptVerifiedDocument(reference, remote))
  beginDeviceEnrollment = (request: NativeProvider.DeviceEnrollmentRequest) =>
    this.call('IDENTITY_CREATE', () => this.native.beginDeviceEnrollment(request))
  beginRequestSigningEnrollment = (request: NativeProvider.RequestSigningEnrollmentRequest) =>
    this.call('IDENTITY_CREATE', () => this.native.beginRequestSigningEnrollment(request))
  resumeEnrollment = (reference: IdentityReference) =>
    this.call('IDENTITY_READ', () => this.native.resumeEnrollment(reference))
  importWrappedRoot = (reference: IdentityReference, envelope: NativeProvider.WrappedRootEnvelope) =>
    this.call('AWIKI_LEGACY_ROOT_TRANSFER_V1', () => this.native.importWrappedRoot(reference, envelope))
  confirmRootPromotion = (reference: IdentityReference, request: NativeProvider.RootPromotionRequest) =>
    this.call('AWIKI_LEGACY_ROOT_TRANSFER_V1', () => this.native.confirmRootPromotion(reference, request))
  signPendingRootObjectProof = (reference: IdentityReference, request: NativeProvider.ObjectProofRequest) =>
    this.call('AWIKI_LEGACY_ROOT_TRANSFER_V1', () => this.native.signPendingRootObjectProof(reference, request))
  ecdhSealed = (request: NativeProvider.SealedKeyAgreementRequest) =>
    this.call('IDENTITY_ECDH_SEALED', () => this.native.ecdhSealed(request))
  exportRootKeySealed = (request: NativeProvider.SealedRootExportRequest) =>
    this.call('AWIKI_LEGACY_ROOT_TRANSFER_V1', () => this.native.exportRootKeySealed(request))
  prepareLegacyRootImport = (request: NativeProvider.SealedRootImportPreparation) =>
    this.call('IDENTITY_IMPORT', () => this.native.prepareLegacyRootImport(request))
  prepareIdentityMaterialImport = (request: NativeProvider.SealedIdentityImportPreparation) =>
    this.call('IDENTITY_IMPORT', () => this.native.prepareIdentityMaterialImport(request))
  prepareProviderAdoption = (request: NativeProvider.SealedProviderAdoptionPreparation) =>
    this.call('IDENTITY_IMPORT', () => this.native.prepareProviderAdoption(request))
  grantConsumer = (reference: IdentityReference, consumer: string) =>
    this.call('IDENTITY_READ', () => this.service.grantConsumer(this.slot, reference, consumer))
  revokeConsumer = (reference: IdentityReference, consumer: string) =>
    this.call('IDENTITY_READ', () => this.service.revokeConsumer(this.slot, reference, consumer))

  private call<T>(capability: NativeProvider.ProviderCapability, operation: () => Promise<T>): Promise<T> {
    if (this.#disposed || this.slot.disposed) return Promise.reject(pluginError('provider_disposed'))
    if (!this.capabilities.includes(capability)) return Promise.reject(pluginError('capability_forbidden'))
    try {
      this.renewIfNeeded()
    } catch (error) {
      return Promise.reject(mapNativeError(error))
    }
    return nativeCall(operation)
  }

  private get native(): NativeProvider.ProviderLease {
    return this.#native
  }

  private renewIfNeeded(): void {
    const now = Date.now()
    if (now < this.#renewAt) return
    let next: NativeProvider.ProviderLease
    try {
      next = this.provider.acquireLease({
        consumer: this.consumer,
        capabilities: [...this.capabilities],
        ttlSeconds: this.ttlSeconds,
      })
    } catch (error) {
      if (now >= this.#expiresAt) throw error
      return
    }

    const retired = this.#native
    const retiredExpiresAt = this.#expiresAt
    this.#native = next
    this.#expiresAt = now + this.ttlSeconds * 1_000
    this.#renewAt = renewalAt(now, this.ttlSeconds)
    this.retire(retired, retiredExpiresAt)
  }

  private retire(native: NativeProvider.ProviderLease, expiresAt: number): void {
    const timer = setTimeout(() => {
      this.#retired.delete(native)
      native.dispose()
    }, Math.max(1, expiresAt - Date.now()))
    timer.unref?.()
    this.#retired.set(native, timer)
  }
}

function renewalAt(issuedAt: number, ttlSeconds: number): number {
  const ttlMs = ttlSeconds * 1_000
  return issuedAt + ttlMs - Math.min(HOST_LEASE_RENEWAL_SKEW_MS, Math.floor(ttlMs / 5))
}

export default AnpIdentityService

function resolveConfig(config: Config): ResolvedConfig {
  const configured = config.stateRoot?.trim()
  const dshHome = process.env.DSH_HOME?.trim() || join(homedir(), '.dsh')
  const stateRoot = configured === undefined || configured.length === 0
    ? join(dshHome, 'anp-identity')
    : configured
  if (!isAbsolute(stateRoot)) throw new TypeError('anp-identity: stateRoot must be absolute')
  const allowConsumers = new Set((config.allowConsumers ?? []).map(validateConsumer))
  const allowProviderConsumers = new Set((config.allowProviderConsumers ?? []).map(validateConsumer))
  for (const consumer of allowProviderConsumers) {
    if (!allowConsumers.has(consumer)) {
      throw new TypeError('anp-identity: Host Provider consumers must also be allowed clients')
    }
  }
  const httpAllowedOrigins = new Map<string, ReadonlySet<string>>()
  for (const [consumer, origins] of Object.entries(config.httpAllowedOrigins ?? {})) {
    validateConsumer(consumer)
    if (!allowConsumers.has(consumer)) throw new TypeError('anp-identity: HTTP consumer must be allowed')
    const normalized = origins.map(normalizeHttpsOrigin)
    if (new Set(normalized).size !== normalized.length) {
      throw new TypeError('anp-identity: HTTP origins must be unique')
    }
    httpAllowedOrigins.set(consumer, new Set(normalized))
  }
  return {
    stateRoot,
    allowConsumers,
    allowProviderConsumers,
    httpAllowedOrigins,
    recoveryOnOpen: config.recoveryOnOpen ?? true,
  }
}

function validateRegistration(value: NativeProviderRegistration): NativeIdentityProvider {
  if (value?.protocol !== ANP_IDENTITY_NATIVE_PROVIDER_PROTOCOL
    || typeof value.provider?.acquireLease !== 'function') {
    throw pluginError('provider_incompatible')
  }
  return value.provider
}

function validateClientRequest(input: ClientRequest, config: ResolvedConfig) {
  const consumer = validateConsumer(input.consumer)
  if (!config.allowConsumers.has(consumer)) throw pluginError('consumer_forbidden')
  if (!Array.isArray(input.capabilities)
    || input.capabilities.length === 0
    || input.capabilities.some(value => !CLIENT_CAPABILITIES.has(value))
    || new Set(input.capabilities).size !== input.capabilities.length) {
    throw pluginError('invalid_request')
  }
  const ttlSeconds = validateTtl(input.ttlSeconds)
  const configured = config.httpAllowedOrigins.get(consumer) ?? new Set<string>()
  const requested = input.httpOrigins?.map(normalizeHttpsOrigin) ?? []
  if (requested.some(origin => !configured.has(origin))) throw pluginError('http_origin_forbidden')
  return {
    consumer,
    capabilities: [...input.capabilities],
    ttlSeconds,
    httpOrigins: new Set(requested),
  }
}

function validateProviderRequest(input: ProviderRequest, config: ResolvedConfig) {
  const consumer = validateConsumer(input.consumer)
  if (!config.allowProviderConsumers.has(consumer)) throw pluginError('consumer_forbidden')
  if (!Array.isArray(input.capabilities)
    || input.capabilities.length === 0
    || input.capabilities.some(value => !ALL_PROVIDER_CAPABILITIES.includes(value))
    || new Set(input.capabilities).size !== input.capabilities.length) {
    throw pluginError('invalid_request')
  }
  return { consumer, capabilities: [...input.capabilities], ttlSeconds: validateTtl(input.ttlSeconds) }
}

function validateTtl(value: number | undefined): number {
  const ttl = value ?? 300
  if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > 3_600) throw pluginError('invalid_request')
  return ttl
}

function validateConsumer(value: string): string {
  if (typeof value !== 'string'
    || value !== value.trim()
    || !/^[A-Za-z0-9@][A-Za-z0-9@/._-]{0,127}$/u.test(value)) {
    throw new TypeError('anp-identity: consumer must be an exact plugin identifier')
  }
  return value
}

function normalizeHttpsOrigin(value: string): string {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new TypeError('anp-identity: HTTP origins must be absolute HTTPS origins')
  }
  if (url.protocol !== 'https:' || url.origin !== value || url.pathname !== '/'
    || url.search !== '' || url.hash !== '' || url.username !== '' || url.password !== '') {
    throw new TypeError('anp-identity: HTTP origins must be exact HTTPS origins')
  }
  return url.origin
}

function nativeClientCapabilities(capabilities: readonly ClientCapability[]): NativeProvider.ProviderCapability[] {
  const output = new Set<NativeProvider.ProviderCapability>()
  for (const capability of capabilities) {
    switch (capability) {
      case 'identity:read':
      case 'identity:recover':
      case 'identity:handle':
        output.add('IDENTITY_READ')
        break
      case 'identity:create':
        output.add('IDENTITY_CREATE')
        output.add('IDENTITY_READ')
        break
      case 'identity:sign':
        output.add('IDENTITY_SIGN')
        break
      case 'identity:document-update':
        output.add('IDENTITY_DOCUMENT_UPDATE')
        break
      case 'identity:http-auth':
        output.add('IDENTITY_HTTP_SIGNATURE')
        break
      case 'identity:delete':
        output.add('IDENTITY_DELETE')
        break
    }
  }
  return [...output]
}

function validateCreateInput(input: CreateIdentityRequest): void {
  if (typeof input !== 'object' || input === null || typeof input.identity !== 'object') {
    throw pluginError('invalid_request')
  }
  if (input.requestId !== undefined && !/^[A-Za-z0-9_-]{1,128}$/u.test(input.requestId)) {
    throw pluginError('invalid_request')
  }
  if (input.label !== undefined
    && (input.label !== input.label.trim() || input.label.length < 1 || input.label.length > 256)) {
    throw pluginError('invalid_request')
  }
  if (input.handle !== undefined) normalizeHandle(input.handle)
}

function assertGrantedEntry(entry: CatalogEntry | undefined, consumer: string): asserts entry is CatalogEntry {
  if (entry === undefined) throw pluginError('identity_not_found')
  if (entry.state === 'deleting') throw pluginError('identity_deleting')
  if (entry.state === 'unclaimed' || !entry.grantedConsumers.includes(consumer)) {
    throw pluginError('identity_unclaimed')
  }
}

function replaceEntry(catalog: IdentityCatalog, previous: CatalogEntry, next: CatalogEntry): IdentityCatalog {
  return {
    schema: CATALOG_SCHEMA,
    catalogGeneration: catalog.catalogGeneration,
    entries: catalog.entries.map(entry => entry.identityId === previous.identityId ? next : entry),
  }
}

function unclaimedEntry(reference: IdentityReference): CatalogEntry {
  const now = new Date().toISOString()
  return {
    identityId: reference.identityId,
    did: reference.did,
    storeId: reference.storeId,
    grantedConsumers: [],
    createdAt: now,
    lastUsedAt: now,
    state: 'unclaimed',
  }
}

function sameReference(
  left: IdentityReference | undefined,
  right: IdentityReference,
): boolean {
  return left !== undefined
    && left.storeId === right.storeId
    && left.identityId === right.identityId
    && left.did === right.did
}

async function addUnclaimed(
  store: CatalogStore,
  catalog: IdentityCatalog,
  reference: IdentityReference,
): Promise<IdentityCatalog> {
  return store.mutate(current => current.entries.some(entry => entry.identityId === reference.identityId)
    ? current
    : { ...current, entries: [...current.entries, unclaimedEntry(reference)] })
}

async function nativeCall<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation()
  } catch (error) {
    throw mapNativeError(error)
  }
}

function mapOperationError(error: unknown): Error {
  return error instanceof AnpIdentityPluginError ? error : mapNativeError(error)
}

function mapNativeError(error: unknown): Error {
  if (error instanceof AnpIdentityPluginError) return error
  const code = readErrorCode(error)
  if (code === 'identity_not_found' || code === 'key_not_found') return pluginError('identity_not_found')
  if (code === 'invalid_request' || code === 'invalid_identity' || code === 'unsupported_profile') {
    return pluginError('invalid_request')
  }
  if (code === 'conflict') return pluginError('catalog_conflict')
  if (code === 'provider_disposed') return pluginError('provider_disposed')
  if (code === 'provider_unavailable' || code === 'store_not_found') return pluginError('provider_unavailable')
  return pluginError('provider_unavailable')
}

function readErrorCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null || !('code' in error)) return undefined
  return typeof error.code === 'string' ? error.code : undefined
}

function isPluginCode(error: unknown, code: string): boolean {
  return error instanceof AnpIdentityPluginError && error.code === code
}
