import { spawn } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { expect, it } from 'vitest'
import { IdentityProvider } from '@agent-network-protocol/anp-identity/provider'
import { CatalogStore } from '../src/catalog.js'
import { PublicationCoordinator } from '../src/publication.js'
import { createPublicationBackend } from '../src/publication-http.js'

const source = process.env.DSH_IDENTITY_USER_SERVICE_SOURCE
const python = process.env.DSH_IDENTITY_PYTHON

it.skipIf(!source || !python)('uses the actual User Service REST/SQL publisher with the actual native identity through the TS transport', async () => {
  const child = spawn(python!, [join(source!, 'tests/app/cimd/stdio_bridge.py')], {
    cwd: source!, env: { ...process.env, PYTHONPATH: join(source!, 'src') }, stdio: ['pipe', 'pipe', 'pipe'],
  })
  const replies: Array<{ resolve(value: any): void; reject(error: Error): void }> = []
  const exited = new Promise<void>((resolve, reject) => {
    child.once('exit', code => {
      const error = new Error('Component bridge exited')
      while (replies.length) replies.shift()!.reject(error)
      if (code === 0) resolve(); else reject(error)
    })
    child.once('error', reject)
  })
  void exited.catch(() => {})
  createInterface({ input: child.stdout }).on('line', line => {
    const response = JSON.parse(line)
    const next = replies.shift()
    if (response.error) next?.reject(new Error(response.error)); else next?.resolve(response)
  })
  child.stderr.resume() // SDK initialization warnings are not protocol replies.
  const call = (value: unknown) => new Promise<any>((resolve, reject) => {
    replies.push({ resolve, reject }); child.stdin.write(JSON.stringify(value) + '\n')
  })
  const root = await mkdtemp(join(tmpdir(), 'identity-service-contract-'))
  try {
    const provider = await IdentityProvider.initialize({ stateRoot: root, rootKeyKind: 'injected', keyId: 'contract', rootKey: Buffer.alloc(32, 93) })
    const native = provider.acquireLease({ consumer: 'component', capabilities: ['IDENTITY_READ', 'IDENTITY_CREATE', 'IDENTITY_DOCUMENT_UPDATE'], ttlSeconds: 300 })
    try {
      const identity = await native.create({ profile: 'e1', domain: 'identity.example', pathSegments: ['component'], capabilities: { didWba: true }, managedKeys: [{ fragment: 'root', role: 'root_control' }, { fragment: 'request', role: 'request_signing' }] })
      await call({ action: 'register', document: identity.document })
      const store = new CatalogStore(root)
      await store.initialize()
      await store.mutate(catalog => ({ ...catalog, entries: [{ storeId: identity.reference.storeId, identityId: identity.reference.identityId, did: identity.reference.did, state: 'active', grantedConsumers: [], createdAt: new Date().toISOString(), lastUsedAt: new Date().toISOString() }] }))
      const fetch = async (request: Request) => {
        const result = await call({ action: 'request', method: request.method, url: request.url, headers: Object.fromEntries(request.headers), body: request.body ? await request.text() : null })
        return new Response(result.body, { status: result.status, headers: result.headers })
      }
      const backend = createPublicationBackend({ origin: 'https://identity.example', publicFetch: fetch,
        authenticatedFetch: request => { request.headers.set('authorization', 'Bearer component-fixture'); return fetch(request) },
        publishDocument: async (_, session, assertActive) => {
          const candidate = await session.candidate()
          await assertActive()
          const attempt = await session.beginPublication()
          await call({ action: 'authorized_document', document: candidate.candidateDocument })
          await session.complete(attempt, { result: 'confirmed', evidence: { documentVersion: 2, registryVersion: 2, documentDigest: candidate.candidateDigest } })
        },
      })
      const coordinator = new PublicationCoordinator(store, { withNative: async operation => operation(native) })
      const result = await coordinator.publish(identity.reference, { backend: 'contract', documentId: 'one', clientName: '模块身份 🚀', redirectUris: ['https://client.example/callback'] }, backend, async () => {})
      expect(result.state).toBe('published')
      expect((await coordinator.requirePublished(identity.reference)).version).toBe(1)
      const before = await coordinator.status(identity.reference)
      const reopened = new PublicationCoordinator(new CatalogStore(root), { withNative: async operation => operation(native) })
      expect(await reopened.status(identity.reference)).toEqual(before)
    } finally { native.dispose() }
    await call({ action: 'close' })
    await exited
  } finally {
    if (child.exitCode === null) child.kill('SIGTERM')
    await exited.catch(() => {})
    await rm(root, { recursive: true, force: true })
  }
}, 20000)
