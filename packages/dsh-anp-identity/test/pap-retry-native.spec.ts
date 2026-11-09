/** Actual identity authority/native custody and PAP service; remote HTTP is an isolated fixture, not live acceptance. */
import {expect,it} from 'vitest'
import {pathToFileURL} from 'node:url'
import {join} from 'node:path'
import type {Context} from '@deepseek-ai/cordis'
import {createNativeProtocolFixture} from './helpers/native-protocol-fixture.js'

const papSource=process.env.DSH_SHARED_PRODUCT_F_SOURCE
interface Result {ok:boolean;value?:unknown;error?:{code:string}}
interface PapFacade {stop():void;acquireTools(context:Context):{connect(domain:string):Promise<Result>;operations():Promise<Result>;request(args:unknown):Promise<Result>}}

it.skipIf(!papSource)('PAP retains the real Host consent facade across timeout and retries, then sends once after owner approval',async()=>{
  // This explicit cross-repository component consumes the PAP build, not a second application launcher.
  const {PapService}=await import(/* @vite-ignore */ pathToFileURL(join(papSource!,'lib/plugin.js')).href) as {PapService:new(context:Context,config:object)=>PapFacade}
  const f=await createNativeProtocolFixture({consumer:'@awiki/dsh-pap/plugin',additionalConsumers:[{consumer:'@awiki/dsh-pap/tools'}],domainAccess:{enabled:true,scopes:['protocol.read'],secretStore:'local-file'}})
  let businessRequests=0
  const transport={async request(url:string,options:{method?:string;headers?:Record<string,string>}={}){
    const pathname=new URL(url).pathname
    const response=(body:unknown,status=200)=>({url,status,headers:{'content-type':'application/json'},body:Buffer.from(JSON.stringify(body))})
    if(pathname==='/.well-known/poppy.json')return response({protocol_version:'0.3',organization:{domain:'shop.example',name:'Isolated PAP service'},apis:[{type:'openapi',url:'https://shop.example/openapi.json'}]})
    if(pathname==='/.well-known/oauth-protected-resource')return response({},404)
    if(pathname==='/openapi.json')return response({openapi:'3.1.0',servers:[{url:'https://shop.example'}],paths:{'/posts':{post:{operationId:'post_create'}}}})
    if(pathname==='/posts'){
      expect(options.method).toBe('POST');expect(options.headers?.['poppy-session']).toBeTruthy()
      businessRequests++;return response({created:true,id:'isolated-post'})
    }
    throw new Error('Unexpected isolated destination')
  }}
  let pap: PapFacade | undefined
  try{
    f.context.provide('papHost',{transport})
    pap=new PapService(f.context,{enabled:true,autoConnect:true,approvalWaitMs:0,approvalPollMs:10})
    const tools=pap.acquireTools(f.getConsumer('@awiki/dsh-pap/tools').context)
    const connected=await tools.connect('shop.example');expect(connected.ok).toBe(true)
    const listed=await tools.operations();if(!listed.ok)throw new Error('No operation list')
    const operation=(listed.value as {operationRef:string;method:string}[]).find(op=>op.method==='POST')!
    const args={operationRef:operation.operationRef,body:{content:'Isolated native consent retry test'}}
    const first=await tools.request(args);expect(first).toMatchObject({ok:false,error:{code:'identity_authorization_required'}})
    const repeated=await tools.request(args);expect(repeated).toEqual(first)
    const pending=await f.management.listRequests();expect(pending).toHaveLength(1);expect(businessRequests).toBe(0)
    const review=await f.management.getRequest(pending[0]!.id)
    await f.management.decide({requestId:review.request.id,expectedVersion:review.request.version,decision:'approve',mode:'once',reviewedSnapshot:review.snapshot!})
    expect(await tools.request(args)).toMatchObject({ok:true,value:{status:200,body:{created:true}}})
    expect(businessRequests).toBe(1)
    expect((await f.management.listRequests(true)).filter(request=>request.status==='approved')).toHaveLength(1)
  }finally{try{pap?.stop()}finally{await f.dispose()}}
// Native publication and disk-backed consent are integration setup, not a five-second latency assertion.
},30000)
