import { CatalogStore, CATALOG_SCHEMA } from '../lib/catalog.js'

const [stateRoot, worker, countText] = process.argv.slice(2)
if (stateRoot === undefined || worker === undefined || countText === undefined) {
  throw new Error('catalog worker arguments are required')
}
const count = Number.parseInt(countText, 10)
const catalog = new CatalogStore(stateRoot)
for (let index = 0; index < count; index += 1) {
  await catalog.mutate((current) => ({
    schema: CATALOG_SCHEMA,
    catalogGeneration: current.catalogGeneration,
    entries: [...current.entries, {
      identityId: `${worker}-${index}`,
      did: `did:wba:example.test:worker:${worker}-${index}`,
      storeId: 'store-1',
      grantedConsumers: [worker],
      createdByConsumer: worker,
      createdAt: '2026-08-23T00:00:00.000Z',
      lastUsedAt: '2026-08-23T00:00:00.000Z',
      state: 'active',
    }],
  }))
}
