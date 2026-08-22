import { randomUUID } from 'node:crypto'
import {
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
  unlink,
  type FileHandle,
} from 'node:fs/promises'
import { dirname, join } from 'node:path'
import lockfile from 'proper-lockfile'
import type { IdentityReference } from '@agent-network-protocol/anp-identity'
import { pluginError } from './errors.js'

export const CATALOG_SCHEMA = 'anp-identity-catalog/1' as const
export const CREATE_INTENT_SCHEMA = 'anp-identity-create-intent/1' as const
const MAX_CATALOG_BYTES = 4 * 1024 * 1024
const LOCK_TIMEOUT_MS = 10_000
const LOCK_RETRY_MS = 20

export type CatalogEntryState = 'active' | 'deleting' | 'unclaimed'

export interface CatalogEntry {
  readonly identityId: string
  readonly did: string
  readonly storeId: string
  readonly label?: string
  readonly handle?: string
  readonly createdByConsumer?: string
  readonly grantedConsumers: string[]
  readonly createdAt: string
  readonly lastUsedAt: string
  readonly state: CatalogEntryState
}

export interface IdentityCatalog {
  readonly schema: typeof CATALOG_SCHEMA
  readonly catalogGeneration: number
  readonly entries: CatalogEntry[]
}

export interface CreateIntent {
  readonly schema: typeof CREATE_INTENT_SCHEMA
  readonly requestId: string
  readonly consumer: string
  readonly label?: string
  readonly handle?: string
  readonly createdAt: string
  readonly baselineIdentityIds: string[]
  readonly reference?: IdentityReference
}

export type CatalogFaultPoint =
  | 'before_catalog_temp_write'
  | 'after_catalog_temp_sync'
  | 'after_catalog_rename'
  | 'before_intent_temp_write'
  | 'after_intent_temp_sync'
  | 'after_intent_rename'

export interface CatalogOptions {
  readonly fault?: (point: CatalogFaultPoint) => void
  readonly lockTimeoutMs?: number
}

/** Non-secret DSH metadata with atomic writes and a cross-process lock. */
export class CatalogStore {
  readonly catalogPath: string
  readonly intentsRoot: string
  readonly lockPath: string
  readonly nativeCreateLockPath: string
  readonly #fault: (point: CatalogFaultPoint) => void
  readonly #lockTimeoutMs: number

  public constructor(readonly stateRoot: string, options: CatalogOptions = {}) {
    this.catalogPath = join(stateRoot, 'catalog-v1.json')
    this.intentsRoot = join(stateRoot, 'journal', 'create')
    this.lockPath = join(stateRoot, 'catalog-v1.lock')
    this.nativeCreateLockPath = join(stateRoot, 'native-create.lock')
    this.#fault = options.fault ?? (() => {})
    this.#lockTimeoutMs = options.lockTimeoutMs ?? LOCK_TIMEOUT_MS
  }

  async initialize(): Promise<void> {
    await mkdir(this.intentsRoot, { recursive: true, mode: 0o700 })
    try {
      await this.load()
    } catch (error) {
      if (!isMissing(error)) throw error
      await this.withCatalogLock(async () => {
        try {
          await this.load()
        } catch (nested) {
          if (!isMissing(nested)) throw nested
          await this.writeCatalog(emptyCatalog())
        }
      })
    }
  }

  async load(): Promise<IdentityCatalog> {
    let bytes: Buffer
    try {
      bytes = await readFile(this.catalogPath)
    } catch (error) {
      if (isMissing(error)) throw error
      throw pluginError('catalog_corrupt')
    }
    if (bytes.byteLength > MAX_CATALOG_BYTES) throw pluginError('catalog_corrupt')
    try {
      return parseCatalog(JSON.parse(bytes.toString('utf8')))
    } catch (error) {
      if (isPluginCatalogError(error)) throw error
      throw pluginError('catalog_corrupt')
    }
  }

  async mutate(
    operation: (catalog: IdentityCatalog) => IdentityCatalog,
    expectedGeneration?: number,
  ): Promise<IdentityCatalog> {
    return this.withCatalogLock(async () => {
      const current = await this.load()
      if (expectedGeneration !== undefined && current.catalogGeneration !== expectedGeneration) {
        throw pluginError('catalog_conflict')
      }
      const candidate = operation(cloneCatalog(current))
      const next = parseCatalog({
        ...candidate,
        catalogGeneration: current.catalogGeneration + 1,
      })
      await this.writeCatalog(next)
      return next
    })
  }

  async replace(catalog: IdentityCatalog): Promise<IdentityCatalog> {
    return this.withCatalogLock(async () => {
      let generation = 0
      try {
        generation = (await this.load()).catalogGeneration
      } catch (error) {
        if (!isPluginCatalogError(error) && !isMissing(error)) throw error
      }
      const next = parseCatalog({ ...catalog, catalogGeneration: generation + 1 })
      await this.writeCatalog(next)
      return next
    })
  }

  async writeIntent(intent: CreateIntent): Promise<void> {
    await this.withCatalogLock(async () => {
      await this.writeJsonAtomic(
        this.intentPath(intent.requestId),
        parseIntent(intent),
        'intent',
      )
    })
  }

  async reserveIntent(intent: CreateIntent): Promise<void> {
    await this.withCatalogLock(async () => {
      const normalized = parseIntent(intent)
      const catalog = await this.load()
      const intents = await this.listIntents()
      if (intents.some(value => value.requestId === normalized.requestId)) {
        throw pluginError('catalog_conflict')
      }
      if (normalized.handle !== undefined
        && (catalog.entries.some(value => value.handle === normalized.handle)
          || intents.some(value => value.handle === normalized.handle))) {
        throw pluginError('handle_conflict')
      }
      await this.writeJsonAtomic(this.intentPath(normalized.requestId), normalized, 'intent')
    })
  }

  async commitIntent(requestId: string): Promise<CatalogEntry> {
    return this.withCatalogLock(async () => {
      const intent = await this.readIntent(requestId)
      if (intent.reference === undefined) throw pluginError('catalog_conflict')
      const catalog = await this.load()
      const existing = findEntry(catalog, intent.reference)
      if (existing !== undefined) return existing
      if (intent.handle !== undefined && catalog.entries.some(value => value.handle === intent.handle)) {
        throw pluginError('handle_conflict')
      }
      const entry: CatalogEntry = {
        identityId: intent.reference.identityId,
        did: intent.reference.did,
        storeId: intent.reference.storeId,
        ...(intent.label === undefined ? {} : { label: intent.label }),
        ...(intent.handle === undefined ? {} : { handle: intent.handle }),
        createdByConsumer: intent.consumer,
        grantedConsumers: [intent.consumer],
        createdAt: intent.createdAt,
        lastUsedAt: intent.createdAt,
        state: 'active',
      }
      await this.writeCatalog(parseCatalog({
        ...catalog,
        catalogGeneration: catalog.catalogGeneration + 1,
        entries: [...catalog.entries, entry],
      }))
      return entry
    })
  }

  async updateIntent(
    requestId: string,
    operation: (intent: CreateIntent) => CreateIntent,
  ): Promise<CreateIntent> {
    return this.withCatalogLock(async () => {
      const current = await this.readIntent(requestId)
      const next = parseIntent(operation(current))
      if (next.requestId !== requestId) throw pluginError('invalid_request')
      await this.writeJsonAtomic(this.intentPath(requestId), next, 'intent')
      return next
    })
  }

  async readIntent(requestId: string): Promise<CreateIntent> {
    assertId(requestId)
    try {
      const bytes = await readFile(this.intentPath(requestId))
      if (bytes.byteLength > MAX_CATALOG_BYTES) throw pluginError('catalog_corrupt')
      return parseIntent(JSON.parse(bytes.toString('utf8')))
    } catch (error) {
      if (isPluginCatalogError(error) || isMissing(error)) throw error
      throw pluginError('catalog_corrupt')
    }
  }

  async listIntents(): Promise<CreateIntent[]> {
    let names: string[]
    try {
      names = await readdir(this.intentsRoot)
    } catch (error) {
      if (isMissing(error)) return []
      throw error
    }
    const output: CreateIntent[] = []
    for (const name of names.sort()) {
      if (!name.endsWith('.json')) continue
      const requestId = name.slice(0, -5)
      output.push(await this.readIntent(requestId))
    }
    return output
  }

  async deleteIntent(requestId: string): Promise<void> {
    assertId(requestId)
    await this.withCatalogLock(async () => {
      await unlink(this.intentPath(requestId)).catch((error: unknown) => {
        if (!isMissing(error)) throw error
      })
    })
  }

  async withNativeCreateLock<T>(operation: () => Promise<T>): Promise<T> {
    const release = await acquireFileLock(this.nativeCreateLockPath, this.#lockTimeoutMs)
    try {
      return await operation()
    } finally {
      await release()
    }
  }

  private async withCatalogLock<T>(operation: () => Promise<T>): Promise<T> {
    const release = await acquireFileLock(this.lockPath, this.#lockTimeoutMs)
    try {
      return await operation()
    } finally {
      await release()
    }
  }

  private intentPath(requestId: string): string {
    assertId(requestId)
    return join(this.intentsRoot, `${requestId}.json`)
  }

  private async writeCatalog(catalog: IdentityCatalog): Promise<void> {
    await this.writeJsonAtomic(this.catalogPath, catalog, 'catalog')
  }

  private async writeJsonAtomic(
    path: string,
    value: unknown,
    kind: 'catalog' | 'intent',
  ): Promise<void> {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 })
    const temp = `${path}.${process.pid}.${randomUUID()}.tmp`
    let handle: FileHandle | undefined
    try {
      this.#fault(kind === 'catalog' ? 'before_catalog_temp_write' : 'before_intent_temp_write')
      handle = await open(temp, 'wx', 0o600)
      await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, 'utf8')
      await handle.sync()
      this.#fault(kind === 'catalog' ? 'after_catalog_temp_sync' : 'after_intent_temp_sync')
      await handle.close()
      handle = undefined
      await rename(temp, path)
      this.#fault(kind === 'catalog' ? 'after_catalog_rename' : 'after_intent_rename')
      const directory = await open(dirname(path), 'r')
      try {
        await directory.sync()
      } finally {
        await directory.close()
      }
    } finally {
      await handle?.close().catch(() => {})
      await rm(temp, { force: true }).catch(() => {})
    }
  }
}

export function emptyCatalog(): IdentityCatalog {
  return { schema: CATALOG_SCHEMA, catalogGeneration: 0, entries: [] }
}

export function entryReference(entry: CatalogEntry): IdentityReference {
  return { storeId: entry.storeId, identityId: entry.identityId, did: entry.did }
}

export function findEntry(
  catalog: IdentityCatalog,
  reference: IdentityReference,
): CatalogEntry | undefined {
  return catalog.entries.find((entry) =>
    entry.storeId === reference.storeId
    && entry.identityId === reference.identityId
    && entry.did === reference.did)
}

async function acquireFileLock(path: string, timeoutMs: number): Promise<() => Promise<void>> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  try {
    return await lockfile.lock(path, {
      lockfilePath: path,
      realpath: false,
      stale: Math.max(5_000, timeoutMs * 2),
      update: Math.max(1_000, timeoutMs),
      retries: {
        retries: Math.max(1, Math.ceil(timeoutMs / LOCK_RETRY_MS)),
        factor: 1,
        minTimeout: LOCK_RETRY_MS,
        maxTimeout: LOCK_RETRY_MS,
        randomize: true,
      },
    })
  } catch {
    throw pluginError('catalog_conflict')
  }
}

function parseCatalog(value: unknown): IdentityCatalog {
  if (!isRecord(value)
    || value.schema !== CATALOG_SCHEMA
    || !isNonNegativeInteger(value.catalogGeneration)
    || !Array.isArray(value.entries)) {
    throw pluginError('catalog_corrupt')
  }
  const entries = value.entries.map(parseEntry)
  const identities = new Set<string>()
  const dids = new Set<string>()
  const handles = new Set<string>()
  for (const entry of entries) {
    if (identities.has(entry.identityId) || dids.has(entry.did)) throw pluginError('catalog_corrupt')
    identities.add(entry.identityId)
    dids.add(entry.did)
    if (entry.handle !== undefined) {
      const normalized = normalizeHandle(entry.handle)
      if (handles.has(normalized)) throw pluginError('catalog_corrupt')
      handles.add(normalized)
    }
  }
  return {
    schema: CATALOG_SCHEMA,
    catalogGeneration: value.catalogGeneration,
    entries,
  }
}

function parseEntry(value: unknown): CatalogEntry {
  if (!isRecord(value)
    || !isString(value.identityId)
    || !isString(value.did)
    || !isString(value.storeId)
    || !isOptionalString(value.label)
    || !isOptionalString(value.handle)
    || !isOptionalString(value.createdByConsumer)
    || !Array.isArray(value.grantedConsumers)
    || !value.grantedConsumers.every(isString)
    || !isString(value.createdAt)
    || !isString(value.lastUsedAt)
    || !['active', 'deleting', 'unclaimed'].includes(String(value.state))) {
    throw pluginError('catalog_corrupt')
  }
  const grantedConsumers = [...new Set(value.grantedConsumers)].sort()
  if (grantedConsumers.length !== value.grantedConsumers.length) throw pluginError('catalog_corrupt')
  if (value.state === 'unclaimed' && grantedConsumers.length !== 0) throw pluginError('catalog_corrupt')
  return {
    identityId: value.identityId,
    did: value.did,
    storeId: value.storeId,
    ...(value.label === undefined ? {} : { label: value.label }),
    ...(value.handle === undefined ? {} : { handle: normalizeHandle(value.handle) }),
    ...(value.createdByConsumer === undefined ? {} : { createdByConsumer: value.createdByConsumer }),
    grantedConsumers,
    createdAt: value.createdAt,
    lastUsedAt: value.lastUsedAt,
    state: value.state as CatalogEntryState,
  }
}

function parseIntent(value: unknown): CreateIntent {
  if (!isRecord(value)
    || value.schema !== CREATE_INTENT_SCHEMA
    || !isString(value.requestId)
    || !isString(value.consumer)
    || !isOptionalString(value.label)
    || !isOptionalString(value.handle)
    || !isString(value.createdAt)
    || !Array.isArray(value.baselineIdentityIds)
    || !value.baselineIdentityIds.every(isString)
    || !isOptionalReference(value.reference)) {
    throw pluginError('catalog_corrupt')
  }
  assertId(value.requestId)
  return {
    schema: CREATE_INTENT_SCHEMA,
    requestId: value.requestId,
    consumer: value.consumer,
    ...(value.label === undefined ? {} : { label: value.label }),
    ...(value.handle === undefined ? {} : { handle: normalizeHandle(value.handle) }),
    createdAt: value.createdAt,
    baselineIdentityIds: [...new Set(value.baselineIdentityIds)].sort(),
    ...(value.reference === undefined ? {} : { reference: value.reference }),
  }
}

export function normalizeHandle(value: string): string {
  if (value !== value.trim() || value.length < 1 || value.length > 128
    || !/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/u.test(value.toLowerCase())) {
    throw pluginError('invalid_request')
  }
  return value.toLowerCase()
}

function cloneCatalog(catalog: IdentityCatalog): IdentityCatalog {
  return {
    ...catalog,
    entries: catalog.entries.map((entry) => ({
      ...entry,
      grantedConsumers: [...entry.grantedConsumers],
    })),
  }
}

function assertId(value: string): void {
  if (!/^[A-Za-z0-9_-]{1,128}$/u.test(value)) throw pluginError('invalid_request')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 4096
}

function isOptionalString(value: unknown): value is string | undefined {
  return value === undefined || isString(value)
}

function isNonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0
}

function isOptionalReference(value: unknown): value is IdentityReference | undefined {
  return value === undefined || (isRecord(value)
    && isString(value.storeId)
    && isString(value.identityId)
    && isString(value.did))
}

function isMissing(error: unknown): boolean {
  return isNodeError(error, 'ENOENT')
}

function isNodeError(error: unknown, code: string): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === code
}

function isPluginCatalogError(error: unknown): boolean {
  return typeof error === 'object'
    && error !== null
    && 'name' in error
    && error.name === 'AnpIdentityPluginError'
    && 'code' in error
    && error.code === 'catalog_corrupt'
}
