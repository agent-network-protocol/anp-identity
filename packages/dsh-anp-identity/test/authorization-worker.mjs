import { AuthorizationEngine, freezeOperation } from '../lib/authorization.js'

const [root, grantId, executionId] = process.argv.slice(2)
const caller = { consumer: 'documents', displayName: 'Documents' }
const engine = new AuthorizationEngine(root, {
  validateCaller: async source => { if (source.consumer !== caller.consumer) throw new Error('unknown caller') },
  resolveSnapshot: async () => ({ version: 'v1', capabilities: ['identity:read', 'identity:sign', 'identity:http-auth'], signingPurposes: ['assertion'], httpOrigins: ['https://api.example.test'] }),
  createIdentity: async () => { throw new Error('worker cannot create') },
})
try {
  const lease = await engine.open(caller, grantId)
  const operation = freezeOperation({ capability: 'identity:read', summary: 'Read public DID document' }, { method: 'publicIdentity' })
  await engine.admit(caller, lease, operation, executionId)
  process.stdout.write('admitted')
} catch (error) {
  if (!['grant_inactive', 'grant_conflict'].includes(error.code)) throw error
  process.stdout.write('denied')
}
