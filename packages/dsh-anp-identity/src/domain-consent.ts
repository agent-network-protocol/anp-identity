/** One owner-approved effect, distinct from global protocol read permission. */
import type { Context } from '@deepseek-ai/cordis'
import type { AccessAuthorizationRequest } from './authorization-types.js'
import type { DomainBinding } from './domain-access.js'
import type { UserIdentityClient } from './user-client.js'
import type { ProtocolIdentityClient, ProtocolSignerLease, ProtocolUsePolicy } from './protocol-client.js'
import { randomUUID } from 'node:crypto'
import { exactHttps } from './publication-http.js'
import type { ProtocolPolicyClient, ProtocolTarget } from './protocol-policy.js'
import { ProtocolPolicyError } from './protocol-policy-types.js'
import { normalizeOperation } from './user-operation.js'

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
  executeAllowed<T>(request:Request,authorization:{target:ProtocolTarget;policyVersion:number;annotations?:unknown;metadataOnly:boolean},effect:(assertActive:()=>Promise<void>,capabilities:DomainConsentCapabilities)=>Promise<T>):Promise<T>
}
export interface DomainConsentHost {
  assertCaller(context: Context): string
  resolve(context: Context): Promise<DomainBinding>
  user(context: Context): UserIdentityClient
  run<T>(context: Context, grantId: string, request: Request, identity: DomainBinding['identityRef'], effect: (assertActive: () => Promise<void>) => Promise<T>): Promise<T>
  protocol(context: Context): ProtocolIdentityClient
  install(policy: ProtocolUsePolicy): void
  retire(id: string): void
  policy(context:Context):ProtocolPolicyClient
}
/** Only the installed adapters may bind this facade; model tools never receive it. */
export class DomainOperationAuthority {
  constructor(private readonly host: DomainConsentHost) {}
  bind(context: Context): DomainOperationClient {
    const consumer = this.host.assertCaller(context)
    const user = this.host.user(context)
    const owned = new Set<string>()
    const check = () => { if (this.host.assertCaller(context) !== consumer) throw new DomainConsentError('consumer_forbidden') }
    const runEffect = async <T>(binding:DomainBinding,request:Request,assertExecution:()=>Promise<void>,effect:(check:()=>Promise<void>,caps:DomainConsentCapabilities)=>Promise<T>):Promise<T> => {
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
                  || input.requestedScopes.length!==spec.scopes.length||new Set(input.requestedScopes).size!==input.requestedScopes.length
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
    }
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
      executeAllowed: async <T>(raw:Request,authorization:{target:ProtocolTarget;policyVersion:number;annotations?:unknown;metadataOnly:boolean},effect:(check:()=>Promise<void>,caps:DomainConsentCapabilities)=>Promise<T>)=>{
        check()
        if(consumer!=='@deepseek-ai/dsh-mcp-client/domain')throw new DomainConsentError('consumer_forbidden')
        if(['authorization','cookie','proxy-authorization','poppy-session','dpop'].some(header=>raw.headers.has(header)))throw new DomainConsentError('invalid_request')
        const normalized=await normalizeOperation({action:'http',request:raw})
        if(normalized.input.action!=='http')throw new DomainConsentError('invalid_request')
        const request=normalized.input.request,spec=await mcpConsentSpec(request)
        if(typeof authorization.metadataOnly!=='boolean'||authorization.metadataOnly!==(spec.tool==='__mcp_tools_list__'))throw new DomainConsentError('invalid_request')
        const policy=this.host.policy(context),scope=policy.classifyScopes(spec.scopes)
        const admissions=[await policy.evaluate(authorization.target,{url:request.url,...scope})]
        if(!authorization.metadataOnly)admissions.push(await policy.evaluate(authorization.target,{url:request.url,...policy.classifyMcp(authorization.annotations)}))
        if(admissions.some(admission=>admission.decision==='deny'))throw new ProtocolPolicyError('protocol_permission_denied')
        if(admissions.some(admission=>admission.decision!=='allow'))throw new ProtocolPolicyError('identity_authorization_required')
        if(admissions.some(admission=>admission.version!==authorization.policyVersion))throw new ProtocolPolicyError('protocol_policy_changed')
        const assertPermission=async()=>{
          for(const admission of admissions)await admission.assertActive()
          await policy.assertNoDenial(request.clone())
          for(const admission of admissions)await admission.assertActive()
        }
        await assertPermission()
        const binding=await this.host.resolve(context)
        return runEffect(binding,request,assertPermission,effect)
      },
      execute: async <T>(grantId: string, request: Request, effect: (check: () => Promise<void>, capabilities: DomainConsentCapabilities) => Promise<T>) => {
        check()
        const binding = await this.host.resolve(context)
        return this.host.run(context,grantId,request,binding.identityRef,async assertExecution => {
          return runEffect(binding,request,assertExecution,effect)
        })
      },
    })
  }
}

async function mcpConsentSpec(request: Request): Promise<{resource:string;issuer?:string;scopes:string[];tool:string}> {
  let value: unknown
  try { value = JSON.parse(await request.clone().text()) } catch { throw new DomainConsentError('invalid_request') }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new DomainConsentError('invalid_request')
  const spec = value as {protocol?:unknown;resource?:unknown;issuer?:unknown;tool?:unknown;scopes?:unknown}
  if (Object.keys(value).some(key=>!['protocol','resource','issuer','tool','scopes'].includes(key))||request.method !== 'POST' || spec.protocol !== 'mcp' || typeof spec.resource !== 'string'
    || new URL(exactHttps(spec.resource)).href !== request.url || !Array.isArray(spec.scopes) || !spec.scopes.length || spec.scopes.length>64
    || new Set(spec.scopes).size!==spec.scopes.length
    || !spec.scopes.every(scope=>typeof scope==='string' && /^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/u.test(scope))
    || !spec.tool || typeof spec.tool !== 'object' || Array.isArray(spec.tool)||!('name' in spec.tool) || typeof spec.tool.name !== 'string'||!spec.tool.name.length||spec.tool.name.length>256
    || Object.keys(spec.tool).some(key=>!['name','arguments'].includes(key))||!('arguments' in spec.tool)||!spec.tool.arguments||typeof spec.tool.arguments!=='object'||Array.isArray(spec.tool.arguments)) throw new DomainConsentError('invalid_request')
  if (spec.issuer !== undefined && typeof spec.issuer !== 'string') throw new DomainConsentError('invalid_request')
  if (typeof spec.issuer === 'string') exactHttps(spec.issuer)
  return {resource:spec.resource,scopes:spec.scopes,tool:spec.tool.name,...(typeof spec.issuer==='string'?{issuer:spec.issuer}:{})}
}
