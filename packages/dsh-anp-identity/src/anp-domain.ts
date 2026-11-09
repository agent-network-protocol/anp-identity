/** Exact HTTP reads under the Host's global domain-access policy. */
import type { Context } from '@deepseek-ai/cordis'
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import type { DomainBinding } from './domain-access.js'
import { createAuthenticatedHttp } from './http-auth.js'
import { httpSigningKey, identityControlPath } from './user-service.js'
import { normalizeOperation } from './user-operation.js'
import { pluginError } from './errors.js'

/** Produced only by the installed discovery adapter, never by model arguments. */
export interface AnpReadEvidence {
  profile: 'anp-discovered/1'
  kind: 'agent' | 'information' | 'interface' | 'operation'
  source: string
  url: string
  requiresApproval: boolean
}
export interface AnpDomainReadClient {
  dispatchRead(request: Request, evidence: AnpReadEvidence): Promise<Response>
}
export interface AnpDomainReadHost {
  assertCaller(context: Context): void
  generation(): unknown
  resolve(context: Context): Promise<DomainBinding>
  withNative<T>(operation: (native: ProviderLease) => Promise<T>): Promise<T>
  dispatch(request: Request, assertBeforeSend: () => Promise<void>): Promise<Response>
}
/** No raw signature, generic write permission, or caller-provided transport is exposed. */
export class AnpDomainReadAuthority {
  constructor(private readonly host: AnpDomainReadHost) {}
  bind(context: Context): AnpDomainReadClient {
    this.host.assertCaller(context)
    const generation = this.host.generation()
    const checkCaller = () => {
      this.host.assertCaller(context)
      if (generation !== this.host.generation()) throw pluginError('provider_disposed')
    }
    return Object.freeze({ dispatchRead: async (request: Request, evidence: AnpReadEvidence) => {
      checkCaller()
      request.signal.throwIfAborted()
      if (evidence.profile !== 'anp-discovered/1' || !['agent','information','interface','operation'].includes(evidence.kind)
        || evidence.requiresApproval !== false || evidence.url !== request.url || !['GET','HEAD'].includes(request.method)
        || request.body || ['cookie','proxy-authorization','poppy-session','dpop'].some(header => request.headers.has(header))) throw pluginError('capability_forbidden')
      const source = new URL(evidence.source), destination = new URL(request.url)
      if (source.protocol !== 'https:' || source.username || source.password || source.hash
        || identityControlPath(destination.pathname)) throw pluginError('capability_forbidden')
      const normalized = await normalizeOperation({ action: 'http', request })
      if (normalized.input.action !== 'http') throw pluginError('invalid_request')
      const outgoing = normalized.input.request
      const binding = await this.host.resolve(context)
      const check = async () => {
        request.signal.throwIfAborted()
        checkCaller()
        const current = await this.host.resolve(context)
        checkCaller()
        if (current.policyRef !== binding.policyRef || JSON.stringify(current.identityRef) !== JSON.stringify(binding.identityRef)) throw pluginError('capability_forbidden')
      }
      await check()
      const response = await this.host.withNative(async native => {
        await check()
        return createAuthenticatedHttp(binding.identityRef, native, new Set([destination.origin]), check, async () => {
          const identity = await native.publicIdentity(binding.identityRef)
          await check()
          return httpSigningKey(identity).kid
        }).dispatch(outgoing, value => this.host.dispatch(value, check))
      })
      try { await check() } catch (error) { await response.body?.cancel(); throw error }
      return response
    } })
  }
}
