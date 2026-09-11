import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { CatalogStore, CATALOG_SCHEMA, CREATE_INTENT_SCHEMA, emptyCatalog } from '../src/catalog.js'

describe('user creation catalog compatibility', () => {
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
