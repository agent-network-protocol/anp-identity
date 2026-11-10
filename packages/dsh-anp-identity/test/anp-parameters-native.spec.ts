/** Native signing and independent service verification with isolated identities and no external writes. */
import { expect, it } from 'vitest'
import { pathToFileURL } from 'node:url'
import { join } from 'node:path'
import type { AnpReadEvidence } from '../src/anp-domain.js'
import { createNativeProtocolFixture } from './helpers/native-protocol-fixture.js'

const source = process.env.DSH_SHARED_ANP_SOURCE
const server = process.env.DSH_SHARED_SERVICE_SOURCE
interface Client {
  discover(domain: string): Promise<{ agents: { agentRef: string }[] }>
  describe(ref: string): Promise<{ links: { resourceRef: string }[] }>
  read(ref: string): Promise<{ operations: { operationId: string; operationRef: string }[] }>
  call(ref: string, args?: { query?: Record<string, string>; body?: object }): Promise<unknown>
}
interface ClientOptions {
  allowedOrigins: string[]
  publicDispatch(request: Request): Promise<Response>
  authenticatedDispatch(request: Request, evidence: AnpReadEvidence): Promise<Response>
}
interface Verifier { verify(method: string, url: string, headers: Record<string, string>, body?: Uint8Array): Promise<{ did: string }> }

it.skipIf(!source || !server)('query parameters and multiline JSON pass native signing and the independent service verifier unchanged', async () => {
  const { AnpClient } = await import(/* @vite-ignore */ pathToFileURL(join(source!, 'lib/index.js')).href) as { AnpClient: new (options: ClientOptions) => Client }
  const { AnpVerifier } = await import(/* @vite-ignore */ pathToFileURL(join(server!, 'dist/packages/anp/index.js')).href) as { AnpVerifier: new (resolve: (did: string) => Promise<object>) => Verifier }
  const f = await createNativeProtocolFixture({ consumer: '@agent-network-protocol/dsh-anp/plugin',
    domainAccess: { enabled: true, scopes: [] } })
  const host = f.service.bindAnpDomainConsumer(f.context)
  const user = f.service.bindUserConsumer(f.context)
  const internal: { host: {
    dispatch(request: Request, check: () => Promise<void>, onSend: () => void): Promise<Response>
  } } = Reflect.get(f.service, 'anpReads')
  const transport = internal.host.dispatch
  let writes = 0
  try {
    const document = await f.publicDocument()
    if (!document || typeof document !== 'object' || Array.isArray(document)) throw new Error('Invalid fixture public document')
    const verifier = new AnpVerifier(async did => { expect(did).toBe(f.reference.did); return document })
    internal.host.dispatch = async (request, check, onSend) => {
      await check(); onSend()
      const body = request.body ? Buffer.from(await request.clone().arrayBuffer()) : undefined
      expect(await verifier.verify(request.method, request.url, Object.fromEntries(request.headers), body)).toEqual({ did: f.reference.did })
      const path = new URL(request.url).pathname
      if (path === '/ad.json') return Response.json({ protocolType: 'ANP', type: 'AgentDescription', interfaces: [{ url: '/openapi.json', protocol: 'OpenAPI' }] })
      if (path === '/openapi.json') return Response.json({ openapi: '3.1.0', paths: { '/draft': {
        get: { operationId: 'get', parameters: [{ name: 'request_id', in: 'query', required: true }, { name: 'note', in: 'query' }] },
        post: { operationId: 'create', requestBody: {} },
      } } })
      if (request.method === 'GET') {
        expect(new URL(request.url).searchParams.get('note')).toBe('中文 + / ?')
        return Response.json({ code: 'request_not_found' }, { status: 404 })
      }
      writes++
      expect(body?.toString('utf8')).toBe(JSON.stringify({ text: '第一行\n第二行', structured: { skills: ['Python', 'TypeScript'] } }))
      return Response.json({ created: true })
    }
    let decisions = 0
    const client = new AnpClient({ allowedOrigins: ['https://service.example'],
      publicDispatch: async () => Response.json({ '@type': 'CollectionPage', items: [{ '@id': 'https://service.example/ad.json', name: 'Isolated' }] }),
      authenticatedDispatch: async (request, evidence) => {
        const admission = await host.prepareOperation(request.clone(), evidence)
        let grantId: string | undefined
        if (admission.decision === 'ask') {
          const pending = await user.requestAccess({ requestId: 'isolated-body-' + decisions++, purpose: 'Verify exact isolated request', identity: f.reference, operation: { action: 'http', request: request.clone() } })
          const review = await f.management.getRequest(pending.id)
          const approved = await f.management.decide({ requestId: pending.id, expectedVersion: pending.version, decision: 'approve', mode: 'once', reviewedSnapshot: review.snapshot! })
          grantId = approved.kind === 'access' ? approved.grantId : undefined
        }
        return host.dispatchOperation(request, evidence, { policyVersion: admission.version, ...(grantId ? { grantId } : {}) })
      } })
    const directory = await client.discover('service.example')
    const description = await client.describe(directory.agents[0]!.agentRef)
    const api = await client.read(description.links[0]!.resourceRef)
    const refs = Object.fromEntries(api.operations.map(operation => [operation.operationId, operation.operationRef]))
    await expect(client.call(refs.get!, { query: { request_id: '00000000-0000-0000-0000-000000000000', note: '中文 + / ?' } })).rejects.toMatchObject({ code: 'http_request_failed', response: { status: 404 } })
    await client.call(refs.create!, { body: { text: '第一行\n第二行', structured: { skills: ['Python', 'TypeScript'] } } })
    expect(decisions).toBe(1); expect(writes).toBe(1)
  } finally { internal.host.dispatch = transport; await f.dispose() }
}, 30000)
