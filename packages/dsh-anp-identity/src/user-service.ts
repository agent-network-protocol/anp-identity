import { randomUUID } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import type { IdentityReference, PublicIdentity } from './types.js'
import { AuthorizationEngine } from './authorization.js'
import type { AuthorizedLease, CapabilitySnapshot, CreateParameters, CreateResult, VerifiedCaller } from './authorization-types.js'
import type { AuthorizedIdentity, UserIdentityClient, UserOperation } from './user-client.js'
import { normalizeOperation } from './user-operation.js'
import { createAuthenticatedHttp } from './http-auth.js'
import { pluginError } from './errors.js'

export interface UserServiceHost {
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
  constructor(stateRoot: string, readonly host: UserServiceHost) {
    this.engine = new AuthorizationEngine(stateRoot, host)
    this.ready = this.engine.initialize()
    void this.ready.catch(() => {})
  }

  bind(context: Context): UserIdentityClient {
    const source = this.host.resolveCaller(context)
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
      requestCreateIdentity: async input => { await check(); return this.engine.requestCreate(source, input) },
      getCreateRequest: (id: string) => get(id, 'create'),
      cancelCreateRequest: (id: string, version: number) => cancel(id, version, 'create'),
      requestAccess: async input => {
        await check()
        const normalized = input.operation === undefined ? undefined : await normalizeOperation(input.operation)
        return this.engine.requestAccess(source, {
          requestId: input.requestId, purpose: input.purpose,
          ...(input.identity === undefined ? {} : { identity: structuredClone(input.identity) }),
          ...(normalized === undefined ? {} : { operation: normalized.frozen }),
        })
      },
      getAccessRequest: (id: string) => get(id, 'access'),
      cancelAccessRequest: (id: string, version: number) => cancel(id, version, 'access'),
      openAuthorizedIdentity: async (id: string) => {
        await check()
        return this.managed(source, await this.engine.open(source, id), check)
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
      authenticatedHttp: Object.freeze({
        dispatch: async (request: Request, executionId?: string) => {
          return run({ action: 'http', request }, executionId, async (native, operation, assertActive) => {
            if (operation.action !== 'http') throw pluginError('invalid_request')
            const origins = new Set([new URL(operation.request.url).origin])
            return createAuthenticatedHttp(lease.identity, native, origins, assertActive, async () => {
              const identity = await native.publicIdentity(lease.identity)
              return requestSigningKid(identity)
            }).dispatch(operation.request, outgoing => fetch(outgoing))
          })
        },
      }),
    } satisfies AuthorizedIdentity)
  }
}

export function requestSigningKid(identity: PublicIdentity): string {
  const keys = identity.activeKeys.filter(key => key.algorithm === 'ed25519'
    && key.purposes.includes('authentication') && key.purposes.includes('application_assertion'))
  if (keys.length !== 1) throw pluginError('provider_incompatible')
  return keys[0]!.kid
}
