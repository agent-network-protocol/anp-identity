import { spawn } from 'node:child_process'
import { writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  CatalogStore,
  CATALOG_SCHEMA,
  CREATE_INTENT_SCHEMA,
  emptyCatalog,
  type CatalogFaultPoint,
} from '../src/catalog.js'

describe('catalog-v1 persistence', () => {
  it('atomically stores catalog generations and create intents', async () => {
    await using fixture = await catalogFixture()
    await fixture.catalog.writeIntent({
      schema: CREATE_INTENT_SCHEMA,
      requestId: 'request-1',
      consumer: 'third-party-demo',
      label: 'Demo identity',
      handle: 'Alice.Demo',
      createdAt: '2026-08-23T00:00:00.000Z',
      baselineIdentityIds: ['before'],
    })
    const intent = await fixture.catalog.updateIntent('request-1', (current) => ({
      ...current,
      reference: {
        storeId: 'store-1',
        identityId: 'identity-1',
        did: 'did:wba:example.test:alice',
      },
    }))
    expect(intent.handle).toBe('alice.demo')
    expect(await fixture.catalog.listIntents()).toEqual([intent])

    const updated = await fixture.catalog.mutate((current) => ({
      ...current,
      entries: [{
        identityId: 'identity-1',
        did: 'did:wba:example.test:alice',
        storeId: 'store-1',
        label: 'Demo identity',
        handle: 'alice.demo',
        createdByConsumer: 'third-party-demo',
        grantedConsumers: ['third-party-demo'],
        createdAt: intent.createdAt,
        lastUsedAt: intent.createdAt,
        state: 'active',
      }],
    }))
    expect(updated.catalogGeneration).toBe(1)
    await expect(fixture.catalog.mutate(current => current, 0)).rejects.toMatchObject({
      code: 'catalog_conflict',
    })
    await fixture.catalog.deleteIntent('request-1')
    expect(await fixture.catalog.listIntents()).toEqual([])
  })

  it('keeps the previous value before rename and exposes a committed rename after a crash point', async () => {
    await using fixture = await catalogFixture()
    let point: CatalogFaultPoint | undefined = 'after_catalog_temp_sync'
    const faulting = new CatalogStore(fixture.root, {
      fault(candidate) {
        if (candidate === point) throw new Error(`fault:${candidate}`)
      },
    })
    await expect(faulting.mutate(current => ({
      ...current,
      entries: [entry('before-rename')],
    }))).rejects.toThrow('fault:after_catalog_temp_sync')
    expect((await fixture.catalog.load()).entries).toEqual([])

    point = 'after_catalog_rename'
    await expect(faulting.mutate(current => ({
      ...current,
      entries: [entry('after-rename')],
    }))).rejects.toThrow('fault:after_catalog_rename')
    expect((await fixture.catalog.load()).entries.map(value => value.identityId)).toEqual(['after-rename'])
  })

  it('serializes catalog mutations from separate processes without lost updates', async () => {
    await using fixture = await catalogFixture()
    const worker = join(import.meta.dirname, 'catalog-worker.mjs')
    await Promise.all([
      runWorker(worker, fixture.root, 'one', 12),
      runWorker(worker, fixture.root, 'two', 12),
    ])
    const catalog = await fixture.catalog.load()
    expect(catalog.catalogGeneration).toBe(24)
    expect(catalog.entries).toHaveLength(24)
    expect(new Set(catalog.entries.map(value => value.identityId)).size).toBe(24)
  })

  it('fails closed on corrupt metadata and permits an explicit unclaimed rebuild', async () => {
    await using fixture = await catalogFixture()
    await writeFile(fixture.catalog.catalogPath, '{not-json', 'utf8')
    await expect(fixture.catalog.load()).rejects.toMatchObject({ code: 'catalog_corrupt' })
    const rebuilt = await fixture.catalog.replace({
      ...emptyCatalog(),
      entries: [{ ...entry('recovered'), state: 'unclaimed', grantedConsumers: [] }],
    })
    expect(rebuilt.entries).toMatchObject([{ identityId: 'recovered', state: 'unclaimed' }])
  })
})

function entry(identityId: string) {
  return {
    identityId,
    did: `did:wba:example.test:${identityId}`,
    storeId: 'store-1',
    createdByConsumer: 'test',
    grantedConsumers: ['test'],
    createdAt: '2026-08-23T00:00:00.000Z',
    lastUsedAt: '2026-08-23T00:00:00.000Z',
    state: 'active' as const,
  }
}

async function catalogFixture() {
  const { mkdtemp, rm } = await import('node:fs/promises')
  const root = await mkdtemp(join(tmpdir(), 'dsh-anp-identity-catalog-'))
  const catalog = new CatalogStore(root)
  await catalog.initialize()
  return {
    root,
    catalog,
    async [Symbol.asyncDispose]() {
      await rm(root, { recursive: true, force: true })
    },
  }
}

function runWorker(script: string, root: string, name: string, count: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script, root, name, String(count)], {
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stderr = ''
    child.stderr.setEncoding('utf8')
    child.stderr.on('data', chunk => { stderr += chunk })
    child.once('error', reject)
    child.once('exit', (code) => {
      if (code === 0) resolve()
      else reject(new Error(`catalog worker exited with ${code}: ${stderr}`))
    })
  })
}
