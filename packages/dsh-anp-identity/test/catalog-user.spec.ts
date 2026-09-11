import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { CatalogStore, CATALOG_SCHEMA, CREATE_INTENT_SCHEMA, emptyCatalog, type CatalogFaultPoint } from '../src/catalog.js'

describe('user creation catalog compatibility', () => {
  it.each<CatalogFaultPoint>(['before_backup_temp_write', 'after_backup_temp_sync', 'after_backup_rename', 'after_catalog_temp_sync'])('retries migration after interruption at %s without losing the original bytes', async point => {
    const root = await mkdtemp(join(tmpdir(), 'anp-catalog-backup-fault-'))
    try {
      const store = new CatalogStore(root, { fault: current => { if (current === point) throw new Error('simulated-migration-interruption') } })
      const legacy = { ...emptyCatalog(), schema: 'anp-identity-catalog/1', catalogGeneration: 3 }
      const bytes = JSON.stringify(legacy, null, 1) + '\n'
      await writeFile(store.catalogPath, bytes)
      await expect(store.initialize()).rejects.toThrow('simulated-migration-interruption')
      expect(await readFile(store.catalogPath, 'utf8')).toBe(bytes)
      const restarted = new CatalogStore(root)
      await restarted.initialize()
      expect(await readFile(`${store.catalogPath}.before-v2`, 'utf8')).toBe(bytes)
      expect(await restarted.load()).toEqual({ ...legacy, schema: CATALOG_SCHEMA, catalogGeneration: 4 })
    } finally { await rm(root, { recursive: true, force: true }) }
  })

  it('never replaces a backup using a corrupt live catalog', async () => {
    const root = await mkdtemp(join(tmpdir(), 'anp-catalog-invalid-backup-'))
    try {
      const store = new CatalogStore(root)
      await writeFile(store.catalogPath, '{"schema":"anp-identity-catalog/1","entries":"invalid"}')
      await writeFile(`${store.catalogPath}.before-v2`, 'preserve-existing-evidence')
      await expect(store.initialize()).rejects.toThrow()
      expect(await readFile(`${store.catalogPath}.before-v2`, 'utf8')).toBe('preserve-existing-evidence')
    } finally { await rm(root, { recursive: true, force: true }) }
  })

  it.each(['', '{"schema":', '{"different":"old backup"}'])('repairs an interrupted migration backup from the validated live v1 catalog: %j', async partial => {
    const root = await mkdtemp(join(tmpdir(), 'anp-catalog-partial-backup-'))
    try {
      const store = new CatalogStore(root)
      const legacy = { ...emptyCatalog(), schema: 'anp-identity-catalog/1', catalogGeneration: 7 }
      const bytes = JSON.stringify(legacy)
      await writeFile(store.catalogPath, bytes)
      await writeFile(`${store.catalogPath}.before-v2`, partial)
      await store.initialize()
      expect(await readFile(`${store.catalogPath}.before-v2`, 'utf8')).toBe(bytes)
      expect(await store.load()).toEqual({ ...legacy, schema: CATALOG_SCHEMA, catalogGeneration: 8 })
      await new CatalogStore(root).initialize()
      expect((await store.load()).catalogGeneration).toBe(8)
    } finally { await rm(root, { recursive: true, force: true }) }
  })

  it('upgrades and backs up legacy associations without inventing ordinary grants', async () => {
    const root = await mkdtemp(join(tmpdir(), 'anp-catalog-upgrade-'))
    try {
      const store = new CatalogStore(root)
      const legacy = { ...emptyCatalog(), schema: 'anp-identity-catalog/1', catalogGeneration: 9,
        entries: [{ identityId: 'identity', storeId: 'store', did: 'did:wba:example.com:alice',
          label: 'Alice', handle: 'alice', grantedConsumers: ['legacy'], createdByConsumer: 'legacy',
          createdAt: '2026-01-01', lastUsedAt: '2026-01-01', state: 'active' }] }
      const bytes = JSON.stringify(legacy)
      await writeFile(store.catalogPath, bytes)
      await store.initialize()
      expect(await readFile(`${store.catalogPath}.before-v2`, 'utf8')).toBe(bytes)
      expect(await store.load()).toEqual({ ...legacy, schema: CATALOG_SCHEMA, catalogGeneration: 10 })
      // A crash after the backup but before the migration rename remains recoverable.
      await writeFile(store.catalogPath, bytes)
      await store.initialize()
      expect((await store.load()).schema).toBe('anp-identity-catalog/2')
    } finally { await rm(root, { recursive: true, force: true }) }
  })

  it('records an approved operation as provenance without implicitly granting the creator access', async () => {
    const root = await mkdtemp(join(tmpdir(), 'anp-catalog-user-'))
    try {
      const store = new CatalogStore(root)
      await store.initialize()
      await store.reserveIntent({ schema: CREATE_INTENT_SCHEMA, requestId: 'approved-operation', consumer: 'ordinary',
        label: 'Work', createdAt: '2026-01-01', baselineIdentityIds: [], authorizationMode: 'user',
        reference: { identityId: 'identity', storeId: 'store', did: 'did:wba:example.com:work' } })
      const entry = await store.commitIntent('approved-operation')
      expect(entry).toMatchObject({ creationOperationId: 'approved-operation', createdByConsumer: 'ordinary', grantedConsumers: [] })
      await store.deleteIntent('approved-operation')
      const reopened = new CatalogStore(root)
      await reopened.initialize()
      expect((await reopened.load()).entries).toEqual([entry])
    } finally { await rm(root, { recursive: true, force: true }) }
  })
})
