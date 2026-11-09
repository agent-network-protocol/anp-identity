/** Independent Node writers exercise the actual cross-process lock/CAS, not an in-process mock. */
import { spawn } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { expect, it } from 'vitest'
import { ProtocolPolicyStore } from '../src/protocol-policy.js'

it('allows exactly one independent process to commit the same expected policy version and restores after both exit',async()=>{
  const root=await mkdtemp(join(tmpdir(),'protocol-policy-process-'))
  const children:ReturnType<typeof worker>[]=[]
  let timer:ReturnType<typeof setTimeout>|undefined
  try{
    const script=join(root,'writer.mjs')
    // Built runtime path: normal package test entry builds first; this child launches no application.
    const storeUrl=new URL('../lib/protocol-policy.js',import.meta.url).href
    const typesUrl=new URL('../lib/protocol-policy-types.js',import.meta.url).href
    await writeFile(script,`import {ProtocolPolicyStore} from ${JSON.stringify(storeUrl)};
import {initialProtocolPolicy} from ${JSON.stringify(typesUrl)};
const store=new ProtocolPolicyStore(process.argv[2]);
process.once('message',async()=>{
  let result;
  try{
    const {schema,version,...policy}=initialProtocolPolicy();policy.write.mode=process.argv[3];
    const value=await store.update({expectedVersion:0,policy},()=>{});result={outcome:'updated',version:value.version};
  }catch(error){result={outcome:error.code==='protocol_policy_conflict'?'conflict':'unexpected'};if(result.outcome==='unexpected')process.exitCode=1;}
  process.send(result,()=>process.disconnect());
});
process.send({outcome:'ready'});
`,{mode:0o600})
    const store=new ProtocolPolicyStore(root);expect((await store.read(()=>{})).version).toBe(0)
    children.push(worker(script,root,'allow_all'),worker(script,root,'deny'))
    const deadline=new Promise<never>((_resolve,reject)=>{timer=setTimeout(()=>reject(new Error('Policy process test timed out')),15000)})
    await Promise.race([Promise.all(children.map(child=>child.ready)),deadline])
    for(const child of children)child.process.send('start')
    const results=await Promise.race([Promise.all(children.map(child=>child.result)),deadline])
    const exits=await Promise.race([Promise.all(children.map(child=>child.closed)),deadline])
    expect(exits).toEqual([{code:0,signal:null},{code:0,signal:null}])
    expect(results.map(result=>result.outcome).sort()).toEqual(['conflict','updated'])
    expect((await new ProtocolPolicyStore(root).read(()=>{})).version).toBe(1)
  }finally{
    clearTimeout(timer)
    for(const child of children)if(child.process.exitCode===null&&child.process.signalCode===null)child.process.kill()
    await Promise.all(children.map(child=>child.closed))
    await rm(root,{recursive:true,force:true})
  }
},30000)

function worker(script:string,root:string,mode:string){
  const processChild=spawn(process.execPath,[script,root,mode],{cwd:root,env:{PATH:process.env.PATH,SystemRoot:process.env.SystemRoot},stdio:['ignore','ignore','pipe','ipc']})
  let readyResolve!:()=>void,readyReject!:(error:Error)=>void,resultResolve!:(result:{outcome:string})=>void,resultReject!:(error:Error)=>void
  const ready=new Promise<void>((resolve,reject)=>{readyResolve=resolve;readyReject=reject})
  const result=new Promise<{outcome:string}>((resolve,reject)=>{resultResolve=resolve;resultReject=reject})
  void ready.catch(()=>{});void result.catch(()=>{})
  processChild.on('message',value=>{
    if(!value||typeof value!=='object'||!('outcome'in value)||typeof value.outcome!=='string')return
    if(value.outcome==='ready')readyResolve();else resultResolve({outcome:value.outcome})
  })
  processChild.once('error',error=>{readyReject(error);resultReject(error)})
  const closed=new Promise<{code:number|null;signal:NodeJS.Signals|null}>(resolve=>processChild.once('close',(code,signal)=>{
    const error=new Error('Policy writer exited before its expected IPC result');readyReject(error);resultReject(error);resolve({code,signal})
  }))
  // Drain bounded internal diagnostics without recording arbitrary child output or credentials.
  processChild.stderr?.resume()
  return {process:processChild,ready,result,closed}
}
