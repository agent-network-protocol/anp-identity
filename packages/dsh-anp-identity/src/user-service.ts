import type { PublicationCoordinator } from './publication.js'
import { randomUUID, createHash } from 'node:crypto'
import type { RequestReview } from './management-types.js'
import type { Context } from '@deepseek-ai/cordis'
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import type { IdentityReference, PublicIdentity } from './types.js'
import { AuthorizationEngine } from './authorization.js'
import type { AuthorizedLease, CapabilitySnapshot, CreateParameters, CreateResult, VerifiedCaller } from './authorization-types.js'
import { DomainConsentError } from './domain-consent.js'
import type { AuthorizedIdentity, UserIdentityClient, UserOperation } from './user-client.js'
import { normalizeOperation } from './user-operation.js'
import { createAuthenticatedHttp } from './http-auth.js'
import { pluginError } from './errors.js'

export interface UserServiceHost {
  /** Optional Host-owned network lane; domain mode uses public-address-pinned HTTPS. */
  httpTransport?: (request: Request, caller: VerifiedCaller, assertBeforeSend: () => Promise<void>) => Promise<Response>;
  exactOperationCaller?(caller: VerifiedCaller): boolean
  ensureReady(): Promise<void>
  resolveCaller(context: Context): VerifiedCaller
  validateCaller(caller: VerifiedCaller): Promise<void>
  resolveSnapshot(caller: VerifiedCaller, identity: IdentityReference): Promise<CapabilitySnapshot>
  createIdentity(operationId: string, caller: VerifiedCaller, parameters: CreateParameters): Promise<CreateResult>
  reconcileCreation(operationId: string, caller: VerifiedCaller, parameters: CreateParameters): Promise<CreateResult | undefined>
  withNative<T>(operation: (lease: ProviderLease) => Promise<T>): Promise<T>
}

/** Host boundary. The engine is never exposed on the ordinary client or management Remote. */
export class UserIdentityService {
  readonly engine: AuthorizationEngine
  readonly ready: Promise<void>
  private readonly previews = new Map<string, NonNullable<RequestReview['operationPreview']>>()
  operationPreview(requestId: string): RequestReview['operationPreview'] { return this.previews.get(requestId) }

  constructor(stateRoot: string, readonly host: UserServiceHost, readonly publications?: PublicationCoordinator) {
    this.engine = new AuthorizationEngine(stateRoot, host)
    this.ready = this.engine.initialize()
    void this.ready.catch(() => {})
  }

  bind(context: Context): UserIdentityClient {
    const source = this.host.resolveCaller(context)
    const submitted = new Set<string>()
    const teardownRequests = new Set<string>()
    let disposed = false
    context.effect(() => async () => {
      disposed = true
      await this.ready.catch(() => undefined)
      for (const id of teardownRequests) {
        try { const request = await this.engine.getRequest(source, id); if (request.status === 'pending') await this.engine.cancel(source, id, request.version) }
        catch { /* Decisions and cancellation race through the ledger CAS; teardown never grants or refunds. */ }
      }
    }, 'anp-identity: cancel owned pending requests')
    const check = async () => {
      await this.ready
      // Provider startup may need the ledger lock; never wait for it inside a transaction.
      await this.host.ensureReady()
      const current = this.host.resolveCaller(context)
      if (current.consumer !== source.consumer) throw pluginError('consumer_forbidden')
      await this.host.validateCaller(current)
    }
    const get = async (id: string, kind: 'create' | 'access') => {
      await check()
      let request = await this.engine.getRequest(source, id)
      if (request.kind !== kind) throw pluginError('invalid_request')
      if (request.kind === 'create' && request.status === 'approved'
        && (request.executionStatus === 'running' || request.executionStatus === 'unknown')) {
        request = await this.engine.reconcileCreation(id)
      }
      return request
    }
    const cancel = async (id: string, version: number, kind: 'create' | 'access') => {
      await get(id, kind)
      return this.engine.cancel(source, id, version)
    }
    return Object.freeze({
      findAccessGrant: async input => {
        await check()
        const normalized = await normalizeOperation(input.operation)
        return this.engine.findPermanentGrant(source, input.identity, normalized.frozen)
      },
      requestCreateIdentity: async input => { await check(); return this.engine.requestCreate(source, input) },
      getCreateRequest: (id: string) => get(id, 'create'),
      cancelCreateRequest: (id: string, version: number) => cancel(id, version, 'create'),
      requestAccess: async input => {
        await check()
        const normalized = input.operation === undefined ? undefined : await normalizeOperation(input.operation)
        let preview: RequestReview['operationPreview']
        if (normalized?.input.action === 'http') preview = await operationPreview(normalized.input.request)
        const previousPreview = this.previews.get(input.requestId)
        if (preview) {
          if (this.previews.size >= 256 && !this.previews.has(input.requestId)) this.previews.delete(this.previews.keys().next().value!)
          // Publish preview before its request can become visible to an owner poll.
          this.previews.set(input.requestId,preview)
        }
        let request
        try {
          request = await this.engine.requestAccess(source, {
            requestId: input.requestId, purpose: input.purpose,
            ...(this.host.exactOperationCaller?.(source) ? {approvalProfile:'exact-operation/1' as const} : {}),
            ...(input.identity === undefined ? {} : { identity: structuredClone(input.identity) }),
            ...(normalized === undefined ? {} : { operation: normalized.frozen }),
          })
        } catch (error) {
          if (previousPreview) this.previews.set(input.requestId,previousPreview)
          else this.previews.delete(input.requestId)
          throw error
        }
        submitted.add(request.id)
        if (request.approvalProfile === 'exact-operation/1') teardownRequests.add(request.id)
        if (preview) {
          this.previews.set(request.id,preview)
          if (request.id !== input.requestId && !previousPreview) this.previews.delete(input.requestId)
        }
        if (disposed) {
          try { if (request.status === 'pending' && request.approvalProfile === 'exact-operation/1') await this.engine.cancel(source,request.id,request.version) }
          catch { /* Approval may win the CAS; a disposed caller still cannot execute it. */ }
          throw pluginError('consumer_forbidden')
        }
        await check()
        return request
      },
      getAccessRequest: (id: string) => get(id, 'access'),
      cancelAccessRequest: async (id: string, version: number) => {
        if (!submitted.has(id)) await check()
        await this.ready
        return this.engine.cancel(source, id, version)
      },
      openAuthorizedIdentity: async (id: string) => {
        await check()
        const lease = await this.engine.open(source, id)
        const grant = (await this.engine.listGrants(lease.identity)).find(grant => grant.id === id)
        if (grant && ['anp-domain/1','domain-operation/1'].includes(grant.snapshot.version) && !this.previews.has(grant.requestId)) throw pluginError('capability_forbidden')
        return this.managed(source, lease, check)
      },
      getExecution: async (id: string) => { await check(); return this.engine.getExecution(source, id) },
      subscribeRequestChanges: (listener: () => void) => {
        if (typeof listener !== 'function') throw pluginError('invalid_request')
        const dispose = this.engine.subscribeRequestChanges(() => {
          void check().then(() => { listener() }).catch(() => {})
        })
        context.effect(() => dispose, 'anp-identity: request notifications')
        return dispose
      },
    } satisfies UserIdentityClient)
  }

  /** Host-only execution gate: it never signs or sends on behalf of its effect. */
  async executeApprovedOperation<T>(context: Context, grantId: string, request: Request, identity: IdentityReference,
    effect: (assertActive: () => Promise<void>) => Promise<T>): Promise<T> {
    const source = this.host.resolveCaller(context)
    const checkCaller = async () => {
      await this.ready
      await this.host.ensureReady()
      const current = this.host.resolveCaller(context)
      if (current.consumer !== source.consumer) throw pluginError('consumer_forbidden')
      await this.host.validateCaller(current)
    }
    await checkCaller()
    const grant = (await this.engine.listGrants(identity)).find(grant=>grant.id===grantId)
    if (!grant || grant.mode!=='once' || !['domain-operation/1','anp-domain/1'].includes(grant.snapshot.version)
      || !this.previews.has(grant.requestId) || JSON.stringify(grant.identity)!==JSON.stringify(identity)) throw pluginError('capability_forbidden')
    const normalized = await normalizeOperation({action:'http',request})
    const lease = await this.engine.open(source,grantId)
    const executionId = randomUUID()
    await this.engine.admit(source,lease,normalized.frozen,executionId)
    const assertActive = async () => { request.signal.throwIfAborted(); await checkCaller(); await this.engine.assertExecutionActive(source,lease,executionId) }
    try {
      await assertActive()
      const result = await effect(assertActive)
      try { await assertActive() } catch { throw new DomainConsentError('operation_result_unknown') }
      await this.engine.recordExecution(source,executionId,'succeeded')
      return result
    } catch (error) {
      await this.engine.recordExecution(source,executionId,'unknown').catch(()=>undefined)
      throw error
    }
  }

  private managed(source: VerifiedCaller, lease: AuthorizedLease, checkCaller: () => Promise<void>): AuthorizedIdentity {
    const run = async <T>(raw: UserOperation, id: string | undefined,
      execute: (native: ProviderLease, frozen: UserOperation, assertActive: () => Promise<void>) => Promise<T>): Promise<T> => {
      await checkCaller()
      const { frozen, input } = await normalizeOperation(raw)
      if (id !== undefined && (typeof id !== 'string' || !id || id.length > 256)) throw pluginError('invalid_request')
      if (input.action === 'sign') {
        await this.host.withNative(async native => {
          const identity = await native.publicIdentity(lease.identity)
          const keys = identity.activeKeys.filter(key => key.algorithm === 'ed25519'
            && key.purposes.includes(input.request.purpose)
            && (input.request.kid === undefined || key.kid === input.request.kid))
          if (keys.length !== 1) throw pluginError('invalid_request')
        })
      }
      const executionId = id ?? randomUUID()
      await this.engine.admit(source, lease, frozen, executionId)
      const assertActive = async () => {
        await checkCaller()
        await this.engine.assertExecutionActive(source, lease, executionId)
      }
      try {
        const result = await this.host.withNative(async native => {
          await assertActive()
          return execute(native, input, assertActive)
        })
        await this.engine.recordExecution(source, executionId, 'succeeded')
        return result
      } catch (error) {
        // Once admission is durable; neither transport errors nor lost results refund it.
        await this.engine.recordExecution(source, executionId, 'unknown').catch(() => {})
        throw error
      }
    }
    return Object.freeze({
      publicIdentity: (executionId?: string) => run({ action: 'read' }, executionId,
        native => native.publicIdentity(lease.identity)),
      sign: (request, executionId?: string) => run({ action: 'sign', request }, executionId,
        (native, operation) => {
          if (operation.action !== 'sign') throw pluginError('invalid_request')
          return native.sign(lease.identity, operation.request)
        }),
      oauthClientIdentity: (executionId?: string) => run({ action: 'read' }, executionId, async () => {
        if (!this.publications) throw pluginError('provider_unavailable')
        return this.publications.status(lease.identity)
      }),
      signOAuthClientAssertion: (audience: string, executionId?: string) => run({ action: 'oauth', audience }, executionId,
        async (native, operation, assertActive) => {
          if (operation.action !== 'oauth' || !this.publications) throw pluginError('provider_unavailable')
          const record = await this.publications.requirePublished(lease.identity)
          await assertActive()
          const result = await native.signOAuthClientAssertion(lease.identity, {
            client_id: record.clientId, audience: operation.audience, key: { kid: record.key.kid },
          })
          await assertActive()
          return result
        }),
      authenticatedHttp: Object.freeze({
        dispatch: async (request: Request, executionId?: string) => {
          return run({ action: 'http', request }, executionId, async (native, operation, assertActive) => {
            if (operation.action !== 'http') throw pluginError('invalid_request')
            const identity = await native.publicIdentity(lease.identity)
            const signing = httpSigningKey(identity)
            if (signing.httpOnly && identityControlPath(new URL(operation.request.url).pathname)) {
              throw pluginError('capability_forbidden')
            }
            const origins = new Set([new URL(operation.request.url).origin])
            return createAuthenticatedHttp(lease.identity, native, origins, assertActive, async () => {
              const current = await native.publicIdentity(lease.identity)
              return httpSigningKey(current).kid
            }).dispatch(operation.request, outgoing => this.host.httpTransport ? this.host.httpTransport(outgoing, source, assertActive) : fetch(outgoing))
          })
        },
      }),
    } satisfies AuthorizedIdentity)
  }
}

/** Reject control-plane paths even when intermediaries decode separators or dot segments. */
export function identityControlPath(pathname: string): boolean {
  let current = pathname
  for (let depth = 0; depth < 5; depth++) {
    const normalized = new URL('https://http-policy.invalid' + current.replace(/\\/gu, '/').replace(/\/+/gu, '/')).pathname
    if (/^\/user-service(?:\/|$)/iu.test(normalized) || /^\/did-auth(?:\/|$)/iu.test(normalized)
      || /^\/agent-clients\/device(?:\/|$)/iu.test(normalized)) return true
    if (!/%[0-9a-f]{2}/iu.test(current)) return false
    try { current = decodeURIComponent(current) } catch { throw pluginError('invalid_request') }
  }
  throw pluginError('invalid_request')
}

export function requestSigningKid(identity: PublicIdentity): string {
  const keys = identity.activeKeys.filter(key => key.algorithm === 'ed25519'
    && key.purposes.includes('authentication') && key.purposes.includes('application_assertion') && !key.purposes.includes('device_assertion'))
  if (keys.length !== 1) throw pluginError('provider_incompatible')
  return keys[0]!.kid
}

/** Select an authentication key for exact HTTP requests, never for raw assertions. */
export function httpSigningKey(identity: PublicIdentity): { kid: string; httpOnly: boolean } {
  const ordinary = identity.activeKeys.filter(key => key.algorithm === 'ed25519'
    && key.purposes.includes('authentication') && key.purposes.includes('application_assertion') && !key.purposes.includes('device_assertion'))
  if (ordinary.length) return { kid: requestSigningKid(identity), httpOnly: false }
  const devices = identity.activeKeys.filter(key => key.algorithm === 'ed25519'
    && key.purposes.includes('authentication') && key.purposes.includes('device_assertion'))
  if (devices.length !== 1) throw pluginError('provider_incompatible')
  return { kid: devices[0]!.kid, httpOnly: true }
}

/** Owner previews never persist credential values or arbitrary HTTP body bytes. */
function previewValue(value: unknown, depth=0): unknown {
  if(depth>5)return '[Nested value]'
  if(typeof value==='number' && !Number.isFinite(value))return '[Non-finite number]'
  if(typeof value==='string') {
    if(/-----BEGIN|(?:Bearer|DPoP)\s+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./u.test(value))return '[redacted]'
    return value.length>240?value.slice(0,240)+'…':value
  }
  if(Array.isArray(value))return value.slice(0,16).map(item=>previewValue(item,depth+1))
  if(value && typeof value==='object')return Object.fromEntries(Object.entries(value).filter(([,item])=>item!==undefined).slice(0,16).map(([key,item])=>[key,/token|secret|password|api.?key|credentials|passphrase|private.?key|authorization|signature|assertion|otp|verifier|challenge|cookie|^code$/iu.test(key)?'[redacted]':previewValue(item,depth+1)]))
  return value
}

async function operationPreview(outgoing: Request): Promise<NonNullable<RequestReview['operationPreview']>> {
  const bytes = Buffer.from(await outgoing.clone().arrayBuffer())
  const text = bytes.toString('utf8')
  const url = new URL(outgoing.url)
  let parameters: unknown
  try { parameters = text ? JSON.parse(text) : undefined } catch { parameters = text ? '[Non-JSON body; full content is bound]' : undefined }
  if (url.search) parameters = {query:Object.fromEntries(url.searchParams),body:parameters}
  parameters = previewValue(parameters)
  const encoded = JSON.stringify(parameters)
  if (encoded && encoded.length > 4096) parameters = encoded.slice(0,4096) + '…'
  return {method:outgoing.method,target:url.origin+url.pathname,bodyDigest:createHash('sha256').update(bytes).digest('hex'),...(parameters===undefined?{}:{parameters})}
}
