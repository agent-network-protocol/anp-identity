/** Exact HTTP reads under the Host's global domain-access policy. */
import type { Context } from '@deepseek-ai/cordis'
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import type { DomainBinding } from './domain-access.js'
import { createAuthenticatedHttp } from './http-auth.js'
import { httpSigningKey, identityControlPath } from './user-service.js'
import { normalizeOperation } from './user-operation.js'
import { pluginError } from './errors.js'
import type { ProtocolPolicyClient, ProtocolTarget } from './protocol-policy.js'
import { ProtocolPolicyError, type HttpEffectEvidence, type ProtocolDecision } from './protocol-policy-types.js'

/** Produced only by the installed discovery adapter, never by model arguments. */
export interface AnpReadEvidence {
  profile: 'anp-discovered/1'
  kind: 'agent' | 'information' | 'interface' | 'operation'
  source: string
  url: string
  requiresApproval: boolean
  discoveryOrigin?: string
  policyEvidence?: Omit<HttpEffectEvidence, 'method'>
}
export interface AnpOperationAdmission { decision: ProtocolDecision; version: number }
export interface AnpDomainReadClient {
  dispatchRead(request: Request, evidence: AnpReadEvidence): Promise<Response>
  prepareOperation(request: Request, evidence: AnpReadEvidence): Promise<AnpOperationAdmission>
  dispatchOperation(request: Request, evidence: AnpReadEvidence, admission: {policyVersion:number;grantId?:string}): Promise<Response>
}
export interface AnpDomainReadHost {
  assertCaller(context: Context): void
  generation(): unknown
  resolve(context: Context): Promise<DomainBinding>
  withNative<T>(operation: (native: ProviderLease) => Promise<T>): Promise<T>
  dispatch(request: Request, assertBeforeSend: () => Promise<void>, onSend: () => void): Promise<Response>
  policy(context: Context): ProtocolPolicyClient
  runApproved<T>(context:Context,grantId:string,request:Request,identity:DomainBinding['identityRef'],effect:(check:()=>Promise<void>)=>Promise<T>):Promise<T>
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
    const policy=this.host.policy(context)
    const targets=new Map<string,ProtocolTarget>()
    const inspect=async(request:Request,evidence:AnpReadEvidence)=>{
      checkCaller()
      request.signal.throwIfAborted()
      if (evidence.profile !== 'anp-discovered/1' || !['agent','information','interface','operation'].includes(evidence.kind)
        || evidence.url !== request.url || typeof evidence.discoveryOrigin!=='string'
        || ['authorization','cookie','proxy-authorization','poppy-session','dpop'].some(header => request.headers.has(header))) throw pluginError('capability_forbidden')
      const source = new URL(evidence.source), destination = new URL(request.url)
      if (source.protocol !== 'https:' || source.username || source.password || source.hash
        || identityControlPath(destination.pathname)) throw pluginError('capability_forbidden')
      if(evidence.kind!=='operation' && (evidence.requiresApproval!==false||!['GET','HEAD'].includes(request.method)||request.body))throw pluginError('capability_forbidden')
      const classification=evidence.kind==='operation'?(evidence.policyEvidence?policy.classifyHttp({...evidence.policyEvidence,method:request.method}):{effect:'unknown' as const,extraPermissions:true})
        :{effect:'read' as const,extraPermissions:false}
      const key=JSON.stringify([evidence.discoveryOrigin,source.href,destination.origin])
      let target=targets.get(key)
      if(!target){if(targets.size>=4096)throw new ProtocolPolicyError('protocol_policy_unavailable');target=policy.register({discoveryOrigin:evidence.discoveryOrigin,destinations:[destination.origin]});targets.set(key,target)}
      const admission=await policy.evaluate(target,{url:request.url,...classification})
      checkCaller()
      return {admission,classification,destination}
    }
    const dispatchOperation:AnpDomainReadClient['dispatchOperation']=async(request,evidence,input)=>{
      const {admission,classification,destination}=await inspect(request,evidence)
      if(admission.decision==='deny')throw new ProtocolPolicyError('protocol_permission_denied')
      if(admission.version!==input.policyVersion)throw new ProtocolPolicyError('protocol_policy_changed')
      if(admission.decision==='ask'&&!input.grantId)throw new ProtocolPolicyError('identity_authorization_required')
      if(admission.decision==='allow'&&input.grantId)throw pluginError('capability_forbidden')
      const normalized = await normalizeOperation({ action: 'http', request })
      if (normalized.input.action !== 'http') throw pluginError('invalid_request')
      const outgoing = normalized.input.request
      const binding = await this.host.resolve(context)
      let attempted=false
      const execute=async(assertGrant?:()=>Promise<void>)=>{
      const check = async () => {
        request.signal.throwIfAborted()
        checkCaller()
        const current = await this.host.resolve(context)
        checkCaller()
        if (current.policyRef !== binding.policyRef || JSON.stringify(current.identityRef) !== JSON.stringify(binding.identityRef)) throw pluginError('capability_forbidden')
        await admission.assertActive()
        await policy.assertNoDenial(outgoing.clone())
        await assertGrant?.()
        await admission.assertActive()
      }
      await check()
      const response = await this.host.withNative(async native => {
        await check()
        return createAuthenticatedHttp(binding.identityRef, native, new Set([destination.origin]), check, async () => {
          const identity = await native.publicIdentity(binding.identityRef)
          await check()
          return httpSigningKey(identity).kid
        }).dispatch(outgoing, value => this.host.dispatch(value, check, () => { attempted = true }))
      })
      try { await check() } catch (error) { await response.body?.cancel(); throw error }
      return response
      }
      try{return input.grantId?await this.host.runApproved(context,input.grantId,outgoing,binding.identityRef,check=>execute(check)):await execute()}
      catch(error){if(attempted&&(classification.effect!=='read'||!['GET','HEAD'].includes(request.method)))throw new ProtocolPolicyError('operation_result_unknown');throw error}
    }
    return Object.freeze<AnpDomainReadClient>({
      prepareOperation:async(request,evidence)=>{const {admission}=await inspect(request,evidence);await policy.assertNoDenial(request.clone());return {decision:admission.decision,version:admission.version}},
      dispatchOperation,
      dispatchRead:async(request,evidence)=>{
        if(evidence.requiresApproval!==false||!['GET','HEAD'].includes(request.method)||request.body)throw pluginError('capability_forbidden')
        const {admission,classification}=await inspect(request,evidence)
        if(classification.effect!=='read'||classification.extraPermissions)throw pluginError('capability_forbidden')
        return dispatchOperation(request,evidence,{policyVersion:admission.version})
      },
    })
  }
}
