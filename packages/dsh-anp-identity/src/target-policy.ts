/** Context-bound protocol authorization with opaque target, scope and temporary-key references. */
import type { Context } from '@deepseek-ai/cordis'
import type { IdentityReference } from '@agent-network-protocol/anp-identity'
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import type { VerifiedCaller } from './authorization-types.js'
import type { PublicationCoordinator } from './publication.js'
import type { PublicationRecord } from './publication-types.js'
import type { ProtocolUsePolicy, ProtocolIdentityClient, ProtocolSignerLease, ProtocolKeyReference, ValidatedTargetEvidence, PapHostConsumer } from './protocol-client.js'
import { PapCallbackManagementError, PapCallbackOperationSchema } from './pap-callback.js'
import type { PapCallbackManagementOperations, PapCallbackOperation, PapCallbackRegisterOperation, PapCallbackClaimOperation,
  PapCallbackRegistrationResult, PapCallbackClaimResult } from './pap-callback.js'
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
  /** Recheck durable default selection for Host-installed domain policies, including retained native leases. */
  assertDomainPolicy?(context: Context, policy: ProtocolUsePolicy, profile: ValidatedTargetEvidence['profile']): Promise<void>
}
/** Private manager-owned driver and encrypted public transaction bindings. No credential value is returned. */
export interface PapCallbackHostAuthority {
  assertActive(): Promise<void>
  operations: PapCallbackManagementOperations
  reserve(transactionId: string, binding: Record<string, unknown>): Promise<Record<string, unknown>>
  read(transactionId: string): Promise<Record<string, unknown> | undefined>
}
interface PapTarget {
  fiber: Context['fiber']; identity: IdentityReference; policy: ProtocolUsePolicy
  evidence: ValidatedTargetEvidence; scopes: string[]; check(): Promise<PublicationRecord>
}
/** The trusted adapter validates public discovery; this authority enforces identity and permission policy. */
export class ProtocolIdentityAuthority {
  private readonly targets = new WeakMap<object, PapTarget>()
  private readonly domainPolicies = new Map<string, ProtocolUsePolicy>()
  /** Called only by the Host's explicitly enabled domain resolver, never by a consumer facade. */
  installDomainPolicy(policy: ProtocolUsePolicy): void {
    if (this.policies.some(value => value.id === policy.id)) throw pluginError('invalid_request')
    if (!this.domainPolicies.has(policy.id)) this.domainPolicies.set(policy.id, structuredClone(policy))
  }
  /** Retire a Host-owned temporary policy after its exact operation finishes. */
  removeDomainPolicy(id: string): void { this.domainPolicies.delete(id) }
  private allPolicies(): readonly ProtocolUsePolicy[] { return [...this.policies, ...this.domainPolicies.values()] }
  constructor(private readonly policies: readonly ProtocolUsePolicy[], private readonly host: ProtocolAuthorityHost,
    private readonly publications: PublicationCoordinator) {
    this.policies = structuredClone(policies)
    const ids = new Set<string>()
    for (const policy of this.policies) {
      if (ids.has(policy.id) || !policy.id || !Number.isSafeInteger(policy.version) || policy.version < 1
        || !policy.consumer || policy.owner !== '@agent-network-protocol/dsh-anp-identity' || !policy.profiles.length || !Number.isSafeInteger(policy.expiresAt)
        || !policy.scopes.length && !policy.profiles.every(profile => profile === 'pap_session')
        || !policy.publicTargets && (!policy.issuers.length || !policy.resources.length)) throw pluginError('invalid_request')
      ids.add(policy.id)
      policy.issuers.forEach(value => exactHttps(value)); policy.resources.forEach(value => exactHttps(value))
    }
  }
  bind(context: Context): ProtocolIdentityClient {
    const caller = this.host.resolveCaller(context)
    if (!this.allPolicies().some(policy => policy.consumer === caller.consumer)) throw pluginError('consumer_forbidden')
    const contextGeneration = this.host.providerGeneration()
    return Object.freeze<ProtocolIdentityClient>({ registerValidatedTarget: async input => {
      const evidence = structuredClone(input.discovery)
      const policy = this.allPolicies().find(value => value.id === input.policyRef && value.consumer === caller.consumer && same(value.identity, input.identityRef))
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
      const dynamic = this.domainPolicies.get(policy.id) === policy
      let disposed = false
      let publicationVersion: number | undefined
      let publicationKid: string | undefined
      const targetRef = Object.freeze({})
      const scopes = new WeakMap<object, Scope>()
      const keys = new WeakMap<object, { scopeRef: object; native: NativeKey }>()
      const checkCurrent = () => {
        checkCaller()
        if (disposed || Date.now() >= policy.expiresAt || Date.now() >= evidence.expiresAt
          || dynamic && this.domainPolicies.get(policy.id) !== policy) throw pluginError('capability_forbidden')
      }
      const check = async () => {
        checkCurrent()
        if (dynamic) await this.host.assertDomainPolicy?.(context, policy, evidence.profile)
        checkCurrent()
        const record = await this.publications.requirePublished(input.identityRef)
        checkCurrent()
        if (publicationVersion !== undefined && (record.version !== publicationVersion || record.key.kid !== publicationKid)) throw pluginError('capability_forbidden')
        if (record.key.alg !== 'ES256' || !record.config.capabilities
          || evidence.profile === 'mcp_machine' && !record.config.capabilities.mcpMachine
          || evidence.profile === 'pap_session' && !record.config.capabilities.papSession
          || evidence.profile === 'pap_account' && !record.config.capabilities.papAccount) throw pluginError('provider_incompatible')
        // Keep the live custody observation after metadata awaits; cached OAuth tokens still require it.
        await this.host.withNative(async native => {
          checkCurrent()
          const info = await native.info()
          checkCurrent()
          if (typeof info.backendAvailable !== 'boolean') throw pluginError('provider_incompatible')
          if (!info.backendAvailable || info.storeId !== input.identityRef.storeId || !info.schemaCompatible
            || info.health !== 'ready') throw pluginError('provider_unavailable')
        })
        checkCurrent()
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
        const result = await this.host.withNative(async native => {
          await check()
          const value = await invoke(native, method, input.identityRef, request)
          await check(); return value
        })
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
      this.targets.set(targetRef, { fiber: context.fiber, identity: structuredClone(input.identityRef), policy,
        evidence, scopes: [...new Set(input.requestedScopes)].sort(), check })
      return lease
    } })
  }
  /** Bind the exact installed PAP plugin; publication and callback data never replace its Host policy. */
  bindPapHost(context: Context, callbackAuthority: (identity: IdentityReference, backend: string) => Promise<PapCallbackHostAuthority>): PapHostConsumer {
    const caller = this.host.resolveCaller(context)
    if (!['@awiki/dsh-pap/plugin', '@agentconnect/dsh-pap/plugin'].includes(caller.consumer)) throw pluginError('consumer_forbidden')
    const generation = this.host.providerGeneration()
    const selectedPolicies = new Set<ProtocolUsePolicy>()
    let disposed = false
    const checkActive = () => {
      const current = this.host.resolveCaller(context)
      if (disposed || current.consumer !== caller.consumer || this.host.providerGeneration() !== generation) throw pluginError('provider_disposed')
      this.host.assertCaller(current)
      if ([...selectedPolicies].some(policy => Date.now() >= policy.expiresAt
        || !this.policies.includes(policy) && this.domainPolicies.get(policy.id) !== policy)) throw pluginError('capability_forbidden')
    }
    const assertActive = async () => {
      checkActive()
      for (const policy of selectedPolicies) if (!this.policies.includes(policy)) await this.host.assertDomainPolicy?.(context, policy, 'pap_session')
      checkActive()
    }
    const policyFor = (identity: IdentityReference, policyRef: string, profile: 'pap_session' | 'pap_account') => {
      const policy = this.allPolicies().find(value => value.id === policyRef && value.consumer === caller.consumer && same(value.identity, identity))
      if (!policy || !policy.profiles.includes(profile) || Date.now() >= policy.expiresAt) throw pluginError('capability_forbidden')
      selectedPolicies.add(policy); return policy
    }
    const publishedFor = async (identity: IdentityReference, profile: 'pap_session' | 'pap_account') => {
      const record = await this.publications.requirePublished(identity)
      if (record.key.alg !== 'ES256' || !record.config.capabilities?.papSession
        || profile === 'pap_account' && !record.config.capabilities.papAccount) throw pluginError('provider_incompatible')
      return record
    }
    const relay = (record: PublicationRecord): string | undefined => {
      const uri = new URL(record.clientId).origin + '/user-service/v1/pap-callback'
      return record.config.redirectUris.includes(uri) ? uri : undefined
    }
    return Object.freeze<PapHostConsumer>({
      assertActive,
      dispose: () => { disposed = true },
      resolveBinding: async (identity, policyRef, profile) => {
        checkActive(); const policy = policyFor(identity, policyRef, profile)
        const record = await publishedFor(identity, profile)
        checkActive()
        await this.host.withNative(async native => { checkActive(); await native.publicIdentity(identity); checkActive() })
        checkActive()
        const current = await publishedFor(identity, profile)
        await assertActive()
        if (record.version !== current.version || record.key.kid !== current.key.kid) throw pluginError('capability_forbidden')
        const redirectUri = profile === 'pap_account' ? relay(current) : undefined
        return { binding: { identityRef: structuredClone(identity), ownerRef: policy.owner, clientId: current.clientId },
          ...(redirectUri ? { redirectUri } : {}) }
      },
      callbackManagementFor: async input => {
        await assertActive(); const policy = policyFor(input.identityRef, input.policyRef, 'pap_account')
        const target = this.targets.get(input.targetRef)
        if (!target || target.fiber !== context.fiber || !same(target.identity, input.identityRef)
          || target.policy !== policy || target.evidence.profile !== 'pap_account') throw pluginError('capability_forbidden')
        const record = await target.check(); const redirectUri = relay(record)
        if (!redirectUri) throw new PapCallbackManagementError('callback_redirect_mismatch')
        const authority = await callbackAuthority(input.identityRef, record.config.backend)
        let released = false
        const check = async () => {
          await assertActive()
          if (released) throw pluginError('provider_disposed')
          await target.check(); await authority.assertActive()
          checkActive()
        }
        await check()
        const binding = { schema: 'pap-host-target/1', consumer: caller.consumer, policyRef: policy.id,
          issuer: target.evidence.issuer, resource: target.evidence.resource, scopes: target.scopes,
          clientId: record.clientId, redirectUri }
        function execute(command: PapCallbackRegisterOperation): Promise<PapCallbackRegistrationResult>
        function execute(command: PapCallbackClaimOperation): Promise<PapCallbackClaimResult>
        async function execute(command: PapCallbackOperation): Promise<PapCallbackRegistrationResult | PapCallbackClaimResult> {
          const parsed = PapCallbackOperationSchema.safeParse(command)
          if (!parsed.success) throw pluginError('invalid_request')
          const operation = parsed.data
          await check()
          if (operation.action === 'pap-callback-register') {
            if (operation.callback.client_id !== record.clientId || operation.callback.issuer !== target!.evidence.issuer
              || operation.callback.redirect_uri !== redirectUri) throw pluginError('capability_forbidden')
            const saved = await authority.reserve(operation.callback.transaction_id, binding)
            if (JSON.stringify(saved) !== JSON.stringify(binding)) throw pluginError('capability_forbidden')
            await check()
            const result = await authority.operations.execute(operation)
            await check(); checkActive(); return result
          }
          const saved = await authority.read(operation.callback.transaction_id)
          if (!saved || JSON.stringify(saved) !== JSON.stringify(binding)) throw pluginError('capability_forbidden')
          await check()
          checkActive()
          const result = await authority.operations.execute(operation)
          await check()
          if (result.iss !== target!.evidence.issuer) throw pluginError('capability_forbidden')
          return result
        }
        return Object.freeze({ execute, dispose: () => { released = true } })
      },
    })
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
