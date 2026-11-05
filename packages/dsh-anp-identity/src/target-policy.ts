/** Context-bound protocol authorization with opaque target, scope and temporary-key references. */
import type { Context } from '@deepseek-ai/cordis'
import type { IdentityReference } from '@agent-network-protocol/anp-identity'
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import type { VerifiedCaller } from './authorization-types.js'
import type { PublicationCoordinator } from './publication.js'
import type { ProtocolUsePolicy, ProtocolIdentityClient, ProtocolSignerLease, ProtocolKeyReference, ValidatedTargetEvidence } from './protocol-client.js'
import { exactHttps } from './publication-http.js'
import { pluginError } from './errors.js'

interface Scope { owner: string; company_id: string; user_id: string; account_slot?: string }
interface NativeKey { handle: string; purpose: 'pap_session' | 'pap_dpop'; generation: number; public_jwk: ProtocolKeyReference['publicJwk']; thumbprint: string }
/** Runtime capability checks precede every optional native method. A missing implementation is incompatible. */
async function invoke(native: ProviderLease, name: string, reference: IdentityReference, request: unknown): Promise<unknown> {
  const method = (native as unknown as Record<string, unknown>)[name]
  if (typeof method !== 'function') throw pluginError('provider_incompatible')
  return Reflect.apply(method, native, [reference, request])
}
const same = (a: IdentityReference, b: IdentityReference) => a.storeId === b.storeId && a.identityId === b.identityId && a.did === b.did

export interface ProtocolAuthorityHost {
  resolveCaller(context: Context): VerifiedCaller
  assertCaller(caller: VerifiedCaller): void
  providerGeneration(): unknown
  withNative<T>(operation: (native: ProviderLease) => Promise<T>): Promise<T>
}
/** The trusted adapter validates public discovery; this authority enforces identity and permission policy. */
export class ProtocolIdentityAuthority {
  constructor(private readonly policies: readonly ProtocolUsePolicy[], private readonly host: ProtocolAuthorityHost,
    private readonly publications: PublicationCoordinator) {
    this.policies = structuredClone(policies)
    const ids = new Set<string>()
    for (const policy of this.policies) {
      if (ids.has(policy.id) || !policy.id || !Number.isSafeInteger(policy.version) || policy.version < 1
        || !policy.consumer || policy.owner !== '@agent-network-protocol/dsh-anp-identity' || !policy.profiles.length || !Number.isSafeInteger(policy.expiresAt)
        || !policy.scopes.length || !policy.publicTargets && (!policy.issuers.length || !policy.resources.length)) throw pluginError('invalid_request')
      ids.add(policy.id)
      policy.issuers.forEach(value => exactHttps(value)); policy.resources.forEach(value => exactHttps(value))
    }
  }
  bind(context: Context): ProtocolIdentityClient {
    const caller = this.host.resolveCaller(context)
    if (!this.policies.some(policy => policy.consumer === caller.consumer)) throw pluginError('consumer_forbidden')
    const contextGeneration = this.host.providerGeneration()
    return Object.freeze<ProtocolIdentityClient>({ registerValidatedTarget: async input => {
      const evidence = structuredClone(input.discovery)
      const policy = this.policies.find(value => value.id === input.policyRef && value.consumer === caller.consumer && same(value.identity, input.identityRef))
      const checkCaller = () => {
        const current = this.host.resolveCaller(context)
        if (current.consumer !== caller.consumer || this.host.providerGeneration() !== contextGeneration) throw pluginError('provider_disposed')
        this.host.assertCaller(current)
      }
      checkCaller()
      this.validateEvidence(evidence)
      if (!policy || Date.now() >= policy.expiresAt || !policy.profiles.includes(evidence.profile)
        || (!policy.publicTargets && (!policy.issuers.includes(evidence.issuer) || !policy.resources.includes(evidence.resource)))
        || input.requestedScopes.some(scope => !policy.scopes.includes(scope))) throw pluginError('capability_forbidden')
      let disposed = false
      let publicationVersion: number | undefined
      let publicationKid: string | undefined
      const targetRef = Object.freeze({})
      const scopes = new WeakMap<object, Scope>()
      const keys = new WeakMap<object, { scopeRef: object; native: NativeKey }>()
      const check = async () => {
        checkCaller()
        if (disposed || Date.now() >= policy.expiresAt || Date.now() >= evidence.expiresAt) throw pluginError('capability_forbidden')
        const record = await this.publications.requirePublished(input.identityRef)
        if (publicationVersion !== undefined && (record.version !== publicationVersion || record.key.kid !== publicationKid)) throw pluginError('capability_forbidden')
        if (record.key.alg !== 'ES256' || !record.config.capabilities
          || evidence.profile === 'mcp_machine' && !record.config.capabilities.mcpMachine
          || evidence.profile === 'pap_session' && !record.config.capabilities.papSession
          || evidence.profile === 'pap_account' && !record.config.capabilities.papAccount) throw pluginError('provider_incompatible')
        return record
      }
      const scope = (ref: object): Scope => {
        const value = scopes.get(ref)
        if (!value) throw pluginError('capability_forbidden')
        return value
      }
      const key = (scopeRef: object, keyRef: object, purpose?: NativeKey['purpose']) => {
        scope(scopeRef)
        const value = keys.get(keyRef)
        if (!value || value.scopeRef !== scopeRef || purpose && value.native.purpose !== purpose) throw pluginError('capability_forbidden')
        return value.native
      }
      const run = async (method: string, request: unknown) => {
        await check()
        const result = await this.host.withNative(native => invoke(native, method, input.identityRef, request))
        await check()
        return result
      }
      const create = async (scopeRef: object, operationId: string, purpose: NativeKey['purpose']): Promise<ProtocolKeyReference> => {
        const result = await run(purpose === 'pap_session' ? 'createDelegatedKey' : 'createDpopKey', { scope: scope(scopeRef), operation_id: operationId }) as NativeKey
        if (result.purpose !== purpose || typeof result.handle !== 'string' || !Number.isSafeInteger(result.generation)
          || result.public_jwk?.kty !== 'EC' || result.public_jwk.crv !== 'P-256' || typeof result.thumbprint !== 'string') throw pluginError('provider_incompatible')
        const keyRef = Object.freeze({})
        keys.set(keyRef, { scopeRef, native: result })
        return Object.freeze({ handle: result.handle, keyRef, purpose, generation: result.generation, publicJwk: structuredClone(result.public_jwk), thumbprint: result.thumbprint })
      }
      const lease = Object.freeze<ProtocolSignerLease>({
        targetRef, policyGeneration: policy.version,
        assertActive: async () => { await check() },
        getOAuthClientIdentity: async () => { const record = await check(); return { clientId: record.clientId, keyId: record.key.kid, algorithm: 'ES256' as const, version: record.version, signerMode: 'local' as const, publicJwk: { kty: 'EC' as const, crv: 'P-256' as const, x: record.key.x, y: 'y' in record.key ? record.key.y : '' }, redirectUris: [...record.config.redirectUris] } },
        signOAuthClientAssertion: async ref => {
          if (ref !== targetRef || !evidence.tokenEndpoint) throw pluginError('capability_forbidden')
          const record = await check()
          return await run('signOAuthClientAssertion', { client_id: record.clientId, audience: evidence.issuer, key: { kid: record.key.kid } }) as string
        },
        bindPapScope: input => {
          checkCaller()
          if (disposed || evidence.profile === 'mcp_machine' || !evidence.companyId || !input.userId
            || input.accountSlot !== undefined && evidence.profile !== 'pap_account') throw pluginError('capability_forbidden')
          const ref = Object.freeze({})
          scopes.set(ref, { owner: policy.owner, company_id: evidence.companyId, user_id: input.userId,
            ...(input.accountSlot === undefined ? {} : { account_slot: input.accountSlot }) })
          return ref
        },
        restorePapKey: async (ref, request) => {
          const result = await run('describeTemporaryKey', { ...request, scope: scope(ref) }) as NativeKey
          if (result.handle !== request.handle || result.generation !== request.generation || result.purpose !== request.purpose
            || result.public_jwk?.kty !== 'EC' || result.public_jwk.crv !== 'P-256') throw pluginError('provider_incompatible')
          const keyRef = Object.freeze({}); keys.set(keyRef, { scopeRef: ref, native: result })
          return { handle: result.handle, keyRef, purpose: result.purpose, generation: result.generation, publicJwk: structuredClone(result.public_jwk), thumbprint: result.thumbprint }
        },
        createDelegatedKey: (ref, id) => create(ref, id, 'pap_session'),
        createDpopKey: (ref, id) => create(ref, id, 'pap_dpop'),
        issuePapDelegation: async (ref, request) => {
          const selected = key(ref, request.keyRef, 'pap_session'); const record = await check()
          return await run('issuePapDelegation', { client_id: record.clientId, key: { kid: record.key.kid },
            delegated_key: { handle: selected.handle, generation: selected.generation }, scope: scope(ref), ttl_seconds: request.ttlSeconds }) as string
        },
        signPapSessionRequest: async (ref, request) => {
          const selected = key(ref, request.keyRef, 'pap_session'); const record = await check()
          this.validateRequest(evidence, request.httpUri)
          if (request.clientId !== record.clientId || request.sub !== scope(ref).user_id) throw pluginError('capability_forbidden')
          return await run('signPapSessionRequest', { handle: selected.handle, generation: selected.generation, scope: scope(ref),
            delegation: request.delegation, client_id: record.clientId, sid: request.sid, sub: request.sub,
            ...(request.agentId === undefined ? {} : { agent_id: request.agentId }), http_method: request.httpMethod, http_uri: request.httpUri,
            ...(request.accessToken === undefined ? {} : { access_token: request.accessToken }) }) as string
        },
        signDpopProof: async (ref, request) => {
          const selected = key(ref, request.keyRef, 'pap_dpop')
          if (evidence.profile !== 'pap_account') throw pluginError('capability_forbidden')
          this.validateRequest(evidence, request.httpUri)
          return await run('signDpopProof', { handle: selected.handle, generation: selected.generation, scope: scope(ref),
            http_method: request.httpMethod, http_uri: request.httpUri,
            ...(request.accessToken === undefined ? {} : { access_token: request.accessToken }), ...(request.nonce === undefined ? {} : { nonce: request.nonce }) }) as string
        },
        retireTemporaryKey: async (ref, keyRef) => { const selected = key(ref, keyRef); await run('retireTemporaryKey', { handle: selected.handle, generation: selected.generation, scope: scope(ref) }); keys.delete(keyRef) },
        dispose: () => { disposed = true },
      })
      const initial = await check()
      publicationVersion = initial.version; publicationKid = initial.key.kid
      return lease
    } })
  }
  private validateEvidence(evidence: ValidatedTargetEvidence): void {
    for (const value of [evidence.issuer, evidence.resource, evidence.sources.resource, evidence.sources.authorizationServer,
      ...(evidence.tokenEndpoint ? [evidence.tokenEndpoint] : []), ...(evidence.allowedEndpoints ?? [])]) exactHttps(value)
    if (!/^[a-f0-9]{64}$/u.test(evidence.metadataDigest) || !Number.isSafeInteger(evidence.expiresAt)
      || evidence.expiresAt <= Date.now() || evidence.expiresAt > Date.now() + 3600000) throw pluginError('invalid_request')
  }
  private validateRequest(evidence: ValidatedTargetEvidence, uri: string): void {
    const request = new URL(uri)
    if (request.username || request.password || request.hash || request.protocol !== 'https:'
      || ![evidence.resource, evidence.tokenEndpoint, ...(evidence.allowedEndpoints ?? [])].includes(`${request.origin}${request.pathname}`)) throw pluginError('capability_forbidden')
  }
}
