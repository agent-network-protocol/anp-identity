/** One owner-approved effect, distinct from global protocol read permission. */
import type { Context } from '@deepseek-ai/cordis'
import type { AccessAuthorizationRequest } from './authorization-types.js'
import type { DomainBinding } from './domain-access.js'
import type { UserIdentityClient } from './user-client.js'
import type { ProtocolIdentityClient, ProtocolSignerLease, ProtocolUsePolicy } from './protocol-client.js'
import { randomUUID } from 'node:crypto'
import { exactHttps } from './publication-http.js'

export class DomainConsentError extends Error {
  constructor(readonly code: string) { super(code) }
}
export interface DomainMachineSigner {
  readonly targetRef: object
  readonly policyGeneration: number
  assertActive(): Promise<void>
  getOAuthClientIdentity(): ReturnType<ProtocolSignerLease['getOAuthClientIdentity']>
  signOAuthClientAssertion(targetRef: object): Promise<string>
  dispose(): void
}
export interface DomainMachineIdentity {
  registerValidatedTarget(input: Parameters<ProtocolIdentityClient['registerValidatedTarget']>[0]): Promise<DomainMachineSigner>
}
export interface DomainConsentCapabilities { machineIdentity?: DomainMachineIdentity }
export interface DomainOperationClient {
  request(input: { requestId: string; purpose: string; request: Request }): Promise<AccessAuthorizationRequest>
  status(id: string): Promise<AccessAuthorizationRequest>
  cancel(id: string, version: number): Promise<AccessAuthorizationRequest>
  execute<T>(grantId: string, request: Request, effect: (assertActive: () => Promise<void>, capabilities: DomainConsentCapabilities) => Promise<T>): Promise<T>
}
export interface DomainConsentHost {
  assertCaller(context: Context): string
  resolve(context: Context): Promise<DomainBinding>
  user(context: Context): UserIdentityClient
  run<T>(context: Context, grantId: string, request: Request, identity: DomainBinding['identityRef'], effect: (assertActive: () => Promise<void>) => Promise<T>): Promise<T>
  protocol(context: Context): ProtocolIdentityClient
  install(policy: ProtocolUsePolicy): void
  retire(id: string): void
}
/** Only the installed adapters may bind this facade; model tools never receive it. */
export class DomainOperationAuthority {
  constructor(private readonly host: DomainConsentHost) {}
  bind(context: Context): DomainOperationClient {
    const consumer = this.host.assertCaller(context)
    const user = this.host.user(context)
    const owned = new Set<string>()
    const check = () => { if (this.host.assertCaller(context) !== consumer) throw new DomainConsentError('consumer_forbidden') }
    return Object.freeze<DomainOperationClient>({
      request: async input => {
        check()
        const binding = await this.host.resolve(context)
        check()
        if (['authorization','cookie','proxy-authorization','poppy-session','dpop'].some(header=>input.request.headers.has(header))) throw new DomainConsentError('invalid_request')
        const request = await user.requestAccess({requestId:input.requestId,purpose:input.purpose,identity:binding.identityRef,operation:{action:'http',request:input.request}})
        if (request.kind !== 'access') throw new DomainConsentError('invalid_request')
        owned.add(request.id)
        return request
      },
      status: async id => {
        check()
        if (!owned.has(id)) throw new DomainConsentError('consumer_forbidden')
        const request = await user.getAccessRequest(id)
        if (request.kind !== 'access') throw new DomainConsentError('invalid_request')
        return request
      },
      cancel: async (id,version) => {
        // Cancellation is still available during teardown, but cannot create or use a grant.
        if (!owned.has(id)) throw new DomainConsentError('consumer_forbidden')
        const request = await user.cancelAccessRequest(id,version)
        if (request.kind !== 'access') throw new DomainConsentError('invalid_request')
        return request
      },
      execute: async <T>(grantId: string, request: Request, effect: (check: () => Promise<void>, capabilities: DomainConsentCapabilities) => Promise<T>) => {
        check()
        const binding = await this.host.resolve(context)
        return this.host.run(context,grantId,request,binding.identityRef,async assertExecution => {
          const assertActive = async () => {
            check()
            const current = await this.host.resolve(context)
            if (current.policyRef !== binding.policyRef || JSON.stringify(current.identityRef) !== JSON.stringify(binding.identityRef)) throw new DomainConsentError('capability_forbidden')
            await assertExecution()
            check()
          }
          const leases = new Set<ProtocolSignerLease>(), policies = new Set<string>()
          let finished = false
          try {
            const capabilities: DomainConsentCapabilities = {}
            if (consumer === '@deepseek-ai/dsh-mcp-client/domain') {
              const spec = await mcpConsentSpec(request)
              capabilities.machineIdentity = {registerValidatedTarget: async input => {
                if (finished) throw new DomainConsentError('capability_forbidden')
                await assertActive()
                if (JSON.stringify(input.identityRef) !== JSON.stringify(binding.identityRef) || input.discovery.profile !== 'mcp_machine'
                  || input.discovery.resource !== spec.resource || spec.issuer && input.discovery.issuer !== spec.issuer
                  || input.requestedScopes.some(scope=>!spec.scopes.includes(scope))) throw new DomainConsentError('capability_forbidden')
                const id = 'domain-once-'+randomUUID()
                this.host.install({id,version:1,consumer,identity:binding.identityRef,owner:'@agent-network-protocol/dsh-anp-identity',
                  profiles:['mcp_machine'],issuers:[input.discovery.issuer],resources:[spec.resource],publicTargets:false,
                  scopes:[...input.requestedScopes],expiresAt:input.discovery.expiresAt})
                policies.add(id)
                const raw = await this.host.protocol(context).registerValidatedTarget({...input,policyRef:id,identityRef:binding.identityRef})
                try { await assertActive(); if (finished) throw new DomainConsentError('capability_forbidden'); leases.add(raw) }
                catch (error) { raw.dispose(); throw error }
                const active = async () => { if (finished) throw new DomainConsentError('capability_forbidden'); await assertActive(); await raw.assertActive(); if (finished) throw new DomainConsentError('capability_forbidden') }
                return Object.freeze({targetRef:raw.targetRef,policyGeneration:raw.policyGeneration,
                  assertActive:active,
                  getOAuthClientIdentity:async()=>{await active();const result=await raw.getOAuthClientIdentity();await active();return result},
                  signOAuthClientAssertion:async (ref: object)=>{await active();const result=await raw.signOAuthClientAssertion(ref);await active();return result},
                  dispose:()=>{raw.dispose();leases.delete(raw)},
                })
              }}
            }
            await assertActive()
            const result = await effect(assertActive,capabilities)
            try { await assertActive() } catch { throw new DomainConsentError('operation_result_unknown') }
            return result
          } finally {
            finished = true
            for (const lease of leases) lease.dispose()
            for (const id of policies) this.host.retire(id)
          }
        })
      },
    })
  }
}

async function mcpConsentSpec(request: Request): Promise<{resource:string;issuer?:string;scopes:string[]}> {
  let value: unknown
  try { value = JSON.parse(await request.clone().text()) } catch { throw new DomainConsentError('invalid_request') }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new DomainConsentError('invalid_request')
  const spec = value as {protocol?:unknown;resource?:unknown;issuer?:unknown;tool?:unknown;scopes?:unknown}
  if (request.method !== 'POST' || spec.protocol !== 'mcp' || typeof spec.resource !== 'string'
    || new URL(exactHttps(spec.resource)).href !== request.url || !Array.isArray(spec.scopes) || !spec.scopes.length || spec.scopes.length>64
    || !spec.scopes.every(scope=>typeof scope==='string' && /^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/u.test(scope))
    || !spec.tool || typeof spec.tool !== 'object' || !('name' in spec.tool) || typeof spec.tool.name !== 'string') throw new DomainConsentError('invalid_request')
  if (spec.issuer !== undefined && typeof spec.issuer !== 'string') throw new DomainConsentError('invalid_request')
  if (typeof spec.issuer === 'string') exactHttps(spec.issuer)
  return {resource:spec.resource,scopes:spec.scopes,...(typeof spec.issuer==='string'?{issuer:spec.issuer}:{})}
}
