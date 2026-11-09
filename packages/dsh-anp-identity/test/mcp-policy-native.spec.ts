/** Actual Harness permission/wire checks and native Identity custody; remote HTTP is isolated, not live acceptance. */
import { expect, it } from 'vitest'
import { pathToFileURL } from 'node:url'
import { join } from 'node:path'
import type AnpIdentityService from '../src/index.js'
import type { DomainConsentCapabilities, DomainMachineSigner } from '../src/domain-consent.js'
import { createNativeProtocolFixture } from './helpers/native-protocol-fixture.js'

const source=process.env.DSH_SHARED_HARNESS_SOURCE
interface Guard {
  approve<T>(tool:string,args:Record<string,unknown>,signal:AbortSignal,effect:(check:()=>Promise<void>,caps?:DomainConsentCapabilities)=>Promise<T>,annotations?:object):Promise<T>
  withWireCall<T>(tool:string,args:Record<string,unknown>,signal:AbortSignal,metadataOnly:boolean,check:()=>Promise<void>,effect:()=>Promise<T>):Promise<T>
  fetch(request:Request):Promise<Response>
  dispose():void
}
it.skipIf(!source)('MCP shared policy controls the actual Harness wire checker and temporary native signer without granting permanent scope expansion',async()=>{
  const {McpDomainConsent}=await import(/* @vite-ignore */ pathToFileURL(join(source!,'packages/mcp/mcp-client/src/domain-consent.ts')).href) as {McpDomainConsent:new(options:object)=>Guard}
  const f=await createNativeProtocolFixture({consumer:'@deepseek-ai/dsh-mcp-client/domain',domainAccess:{enabled:true,scopes:[],secretStore:'local-file'}})
  let guard:Guard|undefined,physical=0,assertions=0,retained:DomainMachineSigner|undefined
  const controller=new AbortController()
  try{
    const manager=f.managerContext.anpIdentity as AnpIdentityService
    const policy=f.service.bindProtocolPolicy(f.context,'mcp'),target=policy.register({discoveryOrigin:'https://website.example',destinations:['https://company.example']})
    const resource='https://company.example/mcp',issuer='https://company.example'
    guard=new McpDomainConsent({resource,issuer,scopes:['intent:write'],policy,target,consent:f.service.bindDomainOperationConsumer(f.context),signal:controller.signal,
      approvalWaitMs:15000,approvalPollMs:25,assertActive:async()=>{controller.signal.throwIfAborted()},
      send:async(request:Request,_init:RequestInit,beforeSend?:()=>Promise<void>)=>{await beforeSend?.();expect((await request.json()).params.name).toBe('message_send');physical++;return Response.json({sent:true})}})
    const args={text:'Native MCP policy component'},annotations={readOnlyHint:false,destructiveHint:true}
    const invoke=()=>guard!.approve('message_send',args,controller.signal,async(check,caps)=>{
      const discovery={profile:'mcp_machine' as const,issuer,resource,tokenEndpoint:issuer+'/token',metadataDigest:'c'.repeat(64),expiresAt:Date.now()+60000,sources:{resource:issuer+'/.well-known/oauth-protected-resource/mcp',authorizationServer:issuer+'/.well-known/oauth-authorization-server'}}
      const signer=await caps!.machineIdentity!.registerValidatedTarget({identityRef:f.reference,policyRef:'not-authority',discovery,requestedScopes:['intent:write']})
      retained=signer;expect((await signer.signOAuthClientAssertion(signer.targetRef)).split('.')).toHaveLength(3);assertions++
      return guard!.withWireCall('message_send',args,controller.signal,false,check,()=>guard!.fetch(new Request(resource,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:'isolated',method:'tools/call',params:{name:'message_send',arguments:args}})})))
    },annotations)
    const pending=invoke();const result=pending.then(value=>({value}),error=>({error}))
    let requests=await f.management.listRequests()
    const deadline=Date.now()+10000
    while(!requests.length&&Date.now()<deadline){await new Promise(resolve=>setTimeout(resolve,25));requests=await f.management.listRequests()}
    expect(requests).toHaveLength(1);expect(physical).toBe(0);expect(assertions).toBe(0)
    const review=await f.management.getRequest(requests[0]!.id)
    await f.management.decide({requestId:review.request.id,expectedVersion:review.request.version,decision:'approve',mode:'once',reviewedSnapshot:review.snapshot!})
    const approved=await result;if('error'in approved)throw approved.error
    expect(await approved.value.json()).toEqual({sent:true});expect(physical).toBe(1);expect(assertions).toBe(1)
    await expect(retained!.getOAuthClientIdentity()).rejects.toThrow()
    const {policy:{schema:_schema,version,...input}}=await manager.protocolManagement(f.managerContext)
    input.write.mode='allow_all'
    const saved=await manager.configureProtocolPolicy(f.managerContext,{expectedVersion:version,policy:input})
    expect(await (await invoke()).json()).toEqual({sent:true});expect(physical).toBe(2);expect(assertions).toBe(2)
    expect(await f.management.listRequests(true)).toHaveLength(1)
    input.write.mode='deny'
    await manager.configureProtocolPolicy(f.managerContext,{expectedVersion:saved.version,policy:input})
    await expect(invoke()).rejects.toMatchObject({code:'protocol_permission_denied'})
    expect(physical).toBe(2);expect(assertions).toBe(2)
  }finally{controller.abort();guard?.dispose();await f.dispose()}
// Native publication, ledger polling and real signatures share the integration budget.
},30000)
