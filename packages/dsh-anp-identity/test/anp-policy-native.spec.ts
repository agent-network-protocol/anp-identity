/** Real ANP client, Host policy/ledger and native signatures with isolated remote HTTP; not live or UI acceptance. */
import { expect, it } from 'vitest'
import { pathToFileURL } from 'node:url'
import { join } from 'node:path'
import type AnpIdentityService from '../src/index.js'
import type { AnpReadEvidence } from '../src/anp-domain.js'
import { createNativeProtocolFixture } from './helpers/native-protocol-fixture.js'

const source=process.env.DSH_SHARED_ANP_SOURCE
interface AnpClient {
  discover(domain:string):Promise<{agents:{agentRef:string}[]}>
  describe(reference:string):Promise<{links:{resourceRef:string}[]}>
  read(reference:string):Promise<{operations:{operationId:string;operationRef:string}[]}>
  call(reference:string,args?:{body?:unknown}):Promise<unknown>
}
interface ClientOptions {
  allowedOrigins:string[]
  publicDispatch(request:Request):Promise<Response>
  authenticatedDispatch(request:Request,evidence:AnpReadEvidence):Promise<Response>
}
it.skipIf(!source)('ANP native dispatch respects once approval, persistent write permission and exact original-domain whitelist',async()=>{
  const {AnpClient:Client}=await import(/* @vite-ignore */ pathToFileURL(join(source!,'lib/index.js')).href) as {AnpClient:new(options:ClientOptions)=>AnpClient}
  const f=await createNativeProtocolFixture({consumer:'@agent-network-protocol/dsh-anp/plugin',domainAccess:{enabled:true,scopes:['protocol.read'],secretStore:'local-file'}})
  // Instance-local remote substitution: the production identity/policy/signing path is unchanged.
  const internal=f.service as unknown as {anpReads:{host:{dispatch(request:Request,check:()=>Promise<void>):Promise<Response>}}}
  const original=internal.anpReads.host.dispatch
  let writes=0,signed=0,approvals=0
  internal.anpReads.host.dispatch=async(request,check)=>{
    await check()
    expect(request.headers.has('authorization')||request.headers.has('signature')).toBe(true);signed++
    const path=new URL(request.url).pathname
    if(path==='/ad.json')return Response.json({protocolType:'ANP',type:'AgentDescription',interfaces:[{url:'/openapi.json',protocol:'OpenAPI'}]})
    if(path==='/openapi.json')return Response.json({openapi:'3.1.0',paths:{'/read':{get:{operationId:'read'}},'/write':{post:{operationId:'write',requestBody:{}}}}})
    if(path==='/write'){writes++;return Response.json({created:true,id:'isolated-anp-post-'+writes})}
    if(path==='/read')return Response.json({read:true})
    throw new Error('Unexpected isolated ANP destination')
  }
  try{
    const manager=f.managerContext.anpIdentity as AnpIdentityService
    const host=f.service.bindAnpDomainConsumer(f.context),user=f.service.bindUserConsumer(f.context)
    const client=new Client({allowedOrigins:['*'],publicDispatch:async()=>Response.json({'@type':'CollectionPage',items:[{'@id':'https://agent.service.example/ad.json',name:'Isolated service'}]}),
      authenticatedDispatch:async(request,evidence)=>{
        const admission=await host.prepareOperation(request.clone(),evidence)
        let grantId:string|undefined
        if(admission.decision==='ask'){
          const pending=await user.requestAccess({requestId:'isolated-anp-'+approvals++,purpose:'Isolated exact ANP approval',identity:f.reference,operation:{action:'http',request:request.clone()}})
          const review=await f.management.getRequest(pending.id)
          const approved=await f.management.decide({requestId:pending.id,expectedVersion:pending.version,decision:'approve',mode:'once',reviewedSnapshot:review.snapshot!})
          grantId=approved.kind==='access'?approved.grantId:undefined
        }
        return host.dispatchOperation(request,evidence,{policyVersion:admission.version,...(grantId?{grantId}:{})})
      }})
    const operations=async(domain:string)=>{
      const directory=await client.discover(domain),description=await client.describe(directory.agents[0]!.agentRef)
      return (await client.read(description.links[0]!.resourceRef)).operations
    }
    const first=await operations('website.example'),write=first.find(operation=>operation.operationId==='write')!,read=first.find(operation=>operation.operationId==='read')!
    await client.call(read.operationRef);expect(approvals).toBe(0)
    await client.call(write.operationRef,{body:{content:'Approved once'}});expect(writes).toBe(1);expect(approvals).toBe(1)
    let {policy:{schema:_schema,version,...policy}}=await manager.protocolManagement(f.managerContext)
    policy.write.mode='allow_all'
    version=(await manager.configureProtocolPolicy(f.managerContext,{expectedVersion:version,policy})).version
    await client.call(write.operationRef,{body:{content:'Allowed by saved policy'}});expect(writes).toBe(2);expect(approvals).toBe(1)
    policy.write={mode:'whitelist',outside:'deny',domains:[{domain:'website.example',protocols:['anp']}]}
    version=(await manager.configureProtocolPolicy(f.managerContext,{expectedVersion:version,policy})).version
    await client.call(write.operationRef,{body:{content:'Whitelisted original discovery origin'}});expect(writes).toBe(3)
    const other=await operations('other.example')
    expect(other[0]!.operationRef).not.toBe(first[0]!.operationRef)
    await expect(client.call(other.find(operation=>operation.operationId==='write')!.operationRef,{body:{content:'Not whitelisted'}})).rejects.toMatchObject({code:'protocol_permission_denied'})
    policy.read.mode='deny'
    await manager.configureProtocolPolicy(f.managerContext,{expectedVersion:version,policy})
    await expect(client.call(read.operationRef)).rejects.toMatchObject({code:'protocol_permission_denied'})
    expect(writes).toBe(3);expect(approvals).toBe(1);expect(signed).toBeGreaterThan(3)
    // Even an explicitly approved legacy generic HTTP lease cannot bypass the managed policy boundary.
    const bypassRequest=new Request('https://agent.service.example/read',{credentials:'omit',redirect:'manual'})
    const bypass=await user.requestAccess({requestId:'isolated-legacy-bypass',purpose:'Isolated generic-lease bypass rejection',identity:f.reference,operation:{action:'http',request:bypassRequest.clone()}})
    const review=await f.management.getRequest(bypass.id)
    const approved=await f.management.decide({requestId:bypass.id,expectedVersion:bypass.version,decision:'approve',mode:'once',reviewedSnapshot:review.snapshot!})
    if(approved.kind!=='access'||!approved.grantId)throw new Error('Missing isolated grant')
    const before=signed
    await expect((await user.openAuthorizedIdentity(approved.grantId)).authenticatedHttp.dispatch(bypassRequest)).rejects.toMatchObject({code:'capability_forbidden'})
    expect(signed).toBe(before);expect(writes).toBe(3)
  }finally{internal.anpReads.host.dispatch=original;await f.dispose()}
// Native publication, authorization and signatures are integration setup, not a short latency assertion.
},30000)
