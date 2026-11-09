/** Local C/A fixture. Publication acceptance is simulated; this supplies no B control-plane evidence. */
import { Context } from '@deepseek-ai/cordis'
import { createHash } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { IdentityProvider } from '../../../../bindings/node/provider.js'
import AnpIdentityService, {type Config} from '../../src/index.js'
import { CatalogStore } from '../../src/catalog.js'
import { publicationProfile, type PublicationBackend, type PreparedClientMaterials, type PublicationCapabilities } from '../../src/publication-types.js'
import type { NativeProviderRegistry } from '../../src/provider-api.js'
import type { ProtocolIdentityClient, ProtocolUsePolicy } from '../../src/protocol-client.js'

interface FixtureConsumer {
  consumer: string
  profiles?: ProtocolUsePolicy['profiles']
  scopes?: string[]
  issuers?: string[]
  resources?: string[]
}

/** Publish one real native ES256 identity for independently installed C protocol consumers.
 * @param options - Primary consumer and optional additional consumers, each with its own bounded policy.
 * @returns Primary client/context, installed peers, test-only manager review, and shared Host teardown.
 */
export async function createNativeProtocolFixture(options: {
  redirectUris?: string[]; publicationOrigin?: string; publicationCapabilities?: PublicationCapabilities; consumer?: string; profiles?: ProtocolUsePolicy['profiles']; scopes?: string[]; issuers?: string[]; resources?: string[]
  additionalConsumers?: FixtureConsumer[]
  domainAccess?: Config["domainAccess"]
  httpAllowedOrigins?: Record<string, string[]>
} = {}) {
  const consumer = options.consumer ?? '@fixture/pap-consumer'
  const consumers = [{ ...options, consumer, policyRef: 'fixture-policy' }, ...(options.additionalConsumers ?? []).map((additional, index) => ({
    ...options, ...additional, policyRef: `fixture-policy-additional-${index + 1}`,
  }))]
  if (new Set(consumers.map(item => item.consumer)).size !== consumers.length) throw new Error('fixture_duplicate_consumer')
  if (consumers.some(item => (item.scopes ?? ['agent.self.read', 'pap.read']).length === 0)) throw new Error('fixture_empty_policy_scope_ceiling')
  const root = await mkdtemp(join(tmpdir(), 'c-native-protocol-'))
  let failureContext: Context | undefined
  try {
    const provider = await IdentityProvider.initialize({ stateRoot: root, rootKeyKind: 'injected', keyId: 'protocol-test', rootKey: Buffer.alloc(32, 117) })
    const native = provider.acquireLease({ consumer: 'fixture-create', capabilities: ['IDENTITY_CREATE', 'IDENTITY_READ'], ttlSeconds: 300 })
    const identity = await native.create({ profile: 'e1', domain: 'identity.example', pathSegments: ['fixture'], capabilities: { didWba: true },
      managedKeys: [{ fragment: 'root', role: 'root_control' }, { fragment: 'request', role: 'request_signing' }, { fragment: 'oauth', role: 'oauth_authentication' }] }).catch(error => { throw new Error('fixture_native_create', { cause: error }) })
    native.dispose()
    const catalog = new CatalogStore(root); await catalog.initialize()
    await catalog.mutate(current => ({ ...current, entries: [{ ...identity.reference, state: 'active', createdAt: new Date().toISOString(), lastUsedAt: new Date().toISOString(), grantedConsumers: [] }] }))
    const publicationOrigin = options.publicationOrigin ?? 'https://identity.example'
    const capabilities = options.publicationCapabilities ?? { mcpMachine: true, papSession: true, papAccount: true }
    const ctx = new Context()
    failureContext = ctx
    const entries: Array<{ options: { name: string }; disabled: boolean; fiber: Context['fiber'] }> = []
    ctx.provide('loader', { *entries() { yield* entries } })
    await ctx.plugin(AnpIdentityService, { stateRoot: root, ...(options.domainAccess ? {domainAccess:options.domainAccess} : {}), allowConsumers: consumers.map(item => item.consumer), userConsumers: consumers.map(item => item.consumer),
      ...(options.httpAllowedOrigins === undefined ? {} : { httpAllowedOrigins: options.httpAllowedOrigins }),
      protocolPolicies: consumers.map(item => ({ id: item.policyRef, version: 1, consumer: item.consumer, owner: '@agent-network-protocol/dsh-anp-identity', identity: identity.reference,
        profiles: item.profiles ?? ['pap_session', 'pap_account', 'mcp_machine'], issuers: item.issuers ?? ['https://company.example'],
        resources: item.resources ?? ['https://company.example/api'], publicTargets: false, scopes: item.scopes ?? ['agent.self.read', 'pap.read'], expiresAt: Date.now() + 3600000 })) })
    const service = ctx.anpIdentity as AnpIdentityService
    ;(service as unknown as NativeProviderRegistry).registerProvider({ protocol: 'anp-identity-node-provider/1', provider })
    await service.health()
    const installed = async (name: string) => {
      let context!: Context
      await ctx.plugin(Object.assign((value: Context) => { context = value }, { inject: ['anpIdentity'] }))
      entries.push({ options: { name }, disabled: false, fiber: context.fiber }); return context
    }
    const managerContext = await installed('@agent-network-protocol/dsh-anp-identity/management-remote')
    const installedContexts = new Map<string, { context: Context; policyRef: string }>()
    for (const item of consumers) {
      const context = await installed(item.consumer)
      installedContexts.set(item.consumer, { context, policyRef: item.policyRef })
    }
    const consumerContext = installedContexts.get(consumer)!.context
    let row: PreparedClientMaterials | undefined
    const sha = (text: string) => createHash('sha256').update(text).digest('hex')
    const backend: PublicationBackend = {
      origin: publicationOrigin, clientId: id => `${publicationOrigin}/user-service/v1/agent-clients/${id}/client.json`,
      async prepare(id, input) {
        if (!('schema_version' in input)) throw new Error('fixture_requires_v2')
        const clientId = await backend.clientId(id)
        const metadata = JSON.stringify({ client_id: clientId, jwks_uri: clientId.replace('client.json', 'jwks.json'), client_name: input.client_name,
          redirect_uris: input.redirect_uris, grant_types: [...(input.capabilities.mcp_machine ? ['client_credentials'] : []), ...(input.capabilities.pap_account ? ['authorization_code', 'refresh_token'] : [])],
          response_types: input.capabilities.pap_account ? ['code'] : [], token_endpoint_auth_method: 'private_key_jwt', token_endpoint_auth_signing_alg: 'ES256' })
        const jwks = JSON.stringify({ keys: input.signing_keys })
        row = { state: 'prepared', schema_version: 2, profile: publicationProfile({ mcpMachine: input.capabilities.mcp_machine, papSession: input.capabilities.pap_session, papAccount: input.capabilities.pap_account }),
          capabilities: input.capabilities, active_kid: input.active_kid, key_set_digest: sha(jwks), client_id: clientId, operation_id: input.operation_id,
          version: input.expected_version + 1, metadata, jwks, metadata_sha256: sha(metadata) }; return row
      },
      async activate() { row = { ...row!, state: 'published' }; return row },
      async readPublic(_, part) { return (part === 'client.json' ? row!.metadata : row!.jwks)! },
      async publishDocument(_, session, check) {
        await check(); const candidate = await session.candidate(); const attempt = await session.beginPublication()
        await session.complete(attempt, { result: 'confirmed', evidence: { documentVersion: 2, registryVersion: 2, documentDigest: candidate.candidateDigest } })
      },
    }
    const managerService = managerContext.anpIdentity as AnpIdentityService
    managerService.registerPublicationBackend(managerContext, 'fixture', backend)
    await managerService.acquireManagement(managerContext).publishIdentity({ reference: identity.reference, config: { backend: 'fixture', documentId: 'one', clientName: 'Protocol fixture',
      redirectUris: options.redirectUris ?? (capabilities.papAccount ? [publicationOrigin + '/callback'] : []), activeKid: identity.reference.did + '#oauth', capabilities } }).catch(error => { throw new Error('fixture_publication', { cause: error }) })
    const installedConsumers = new Map([...installedContexts].map(([name, installed]) => [name, {
      ...installed, client: (installed.context.anpIdentity as AnpIdentityService).bindProtocolConsumer(installed.context),
    }]))
    const client: ProtocolIdentityClient = installedConsumers.get(consumer)!.client
    return { get publicMaterials() { return { metadata: row!.metadata!, jwks: row!.jwks! } },
      getConsumer(name: string) { const installed = installedConsumers.get(name); if (!installed) throw new Error('fixture_unknown_consumer'); return installed },
      async publicDocument() { const read = provider.acquireLease({ consumer: 'fixture-public-read', capabilities: ['IDENTITY_READ'], ttlSeconds: 60 }); try { return (await read.publicIdentity(identity.reference)).document } finally { read.dispose() } },
      root, rootContext: ctx, service, client, reference: identity.reference, policyRef: 'fixture-policy', provider, context: consumerContext, managerContext,
      management: managerService.acquireManagement(managerContext),
      async dispose() { await ctx.fiber.dispose(); await rm(root, { recursive: true, force: true }) } }
  } catch (error) {
    const errors: unknown[] = [error]
    try { await failureContext?.fiber.dispose() } catch (cleanupError) { errors.push(cleanupError) }
    try { await rm(root, { recursive: true, force: true }) } catch (cleanupError) { errors.push(cleanupError) }
    if (errors.length > 1) throw new AggregateError(errors, 'fixture_setup_and_cleanup_failed')
    throw error
  }

}
