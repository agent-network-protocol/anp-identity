import { expect, it, vi } from 'vitest'
import type { Context } from '@deepseek-ai/cordis'
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import { AnpDomainReadAuthority, type AnpReadEvidence } from '../src/anp-domain.js'
import { classifyHttpEffect, classifyMcpEffect, classifyMcpScopes } from '../src/protocol-policy-types.js'
import type { ProtocolPolicyClient } from '../src/protocol-policy.js'

function fixture() {
  const context = {} as Context
  let active = true, generation = 1
  let policyVersion=0,writeAllowed=false,readAllowed=true,approved=false
  const identity = {storeId:'store',identityId:'identity',did:'did:wba:identity.example'}
  const binding = {identityRef:identity,policyRef:'global-read',stateRoot:'/state',secretsRoot:'/keys',secretStore:'local-file' as const,scopes:[]}
  const signing = vi.fn(async () => ({headerPatch:[{name:'signature-input',value:'fixture-input'},{name:'signature',value:'fixture-signature'}]}))
  const native = {publicIdentity:async()=>({activeKeys:[{kid:identity.did+'#device',algorithm:'ed25519',purposes:['authentication','device_assertion']}]}),prepareHttpSignature:signing} as unknown as ProviderLease
  const dispatch = vi.fn(async (request: Request) => {expect(request.headers.get('signature')).toBe('fixture-signature');return Response.json({read:true})})
  const policy:ProtocolPolicyClient={classifyHttp:classifyHttpEffect,classifyMcp:classifyMcpEffect,classifyScopes:classifyMcpScopes,async assertNoDenial(){if(!active)throw new Error('revoked')},
    register(){return {protocolTarget:true}},forget(){},async evaluate(_target,input){const version=policyVersion,decision=input.effect==='read'?(readAllowed?'allow':'deny'):input.effect==='write'&&!input.extraPermissions&&writeAllowed?'allow':'ask';
      return {version,decision,async assertActive(){if(version!==policyVersion||decision==='deny')throw Object.assign(new Error('Changed'),{code:'protocol_policy_changed'})}};}}
  const authority = new AnpDomainReadAuthority({assertCaller:ctx=>{if(ctx!==context||!active)throw new Error('forbidden')},generation:()=>generation,
    resolve:async()=>{if(!active)throw new Error('revoked');return binding},withNative:async run=>run(native),dispatch,policy:()=>policy,
    runApproved:async(_context,grant,request,_identity,effect)=>{expect(grant).toBe('once-grant');expect(request.method).toBe('POST');if(!approved)throw new Error('No grant');approved=false;return effect(async()=>{})}})
  const evidence: AnpReadEvidence = {profile:'anp-discovered/1',kind:'agent',discoveryOrigin:'https://website.example',source:'https://website.example/.well-known/agent-descriptions',url:'https://service.example/ad.json',requiresApproval:false}
  return {client:authority.bind(context),authority,context,evidence,dispatch,signing,deactivate(){active=false},reload(){generation++},
    allowWrites(){writeAllowed=true;policyVersion++},denyReads(){readAllowed=false;policyVersion++},approve(){approved=true}}
}
it('signs only the exact discovered read without granting raw signatures or an ordinary HTTP lease', async () => {
  const f=fixture()
  const response=await f.client.dispatchRead(new Request(f.evidence.url),f.evidence)
  expect(await response.json()).toEqual({read:true})
  expect(Object.keys(f.client).sort()).toEqual(['dispatchOperation','dispatchRead','prepareOperation'])
  expect(f.signing).toHaveBeenCalledOnce()
  expect(()=>f.authority.bind({} as Context)).toThrow()
})
it('requires the exact once grant when asked, but signs allowed writes under the persistent owner policy',async()=>{
  const f=fixture(),request=new Request('https://service.example/posts',{method:'POST',body:'{}'})
  const evidence:AnpReadEvidence={...f.evidence,kind:'operation',url:request.url,requiresApproval:true,policyEvidence:{hasRequestBody:true}}
  const first=await f.client.prepareOperation(request.clone(),evidence);expect(first.decision).toBe('ask')
  await expect(f.client.dispatchOperation(request.clone(),evidence,{policyVersion:first.version})).rejects.toMatchObject({code:'identity_authorization_required'})
  expect(f.dispatch).not.toHaveBeenCalled()
  f.approve();await f.client.dispatchOperation(request.clone(),evidence,{policyVersion:first.version,grantId:'once-grant'})
  expect(f.dispatch).toHaveBeenCalledTimes(1)
  f.allowWrites()
  const allowed=await f.client.prepareOperation(request.clone(),evidence);expect(allowed.decision).toBe('allow')
  await f.client.dispatchOperation(request.clone(),evidence,{policyVersion:allowed.version})
  expect(f.dispatch).toHaveBeenCalledTimes(2)
  await expect(f.client.dispatchOperation(request.clone(),evidence,{policyVersion:first.version,grantId:'once-grant'})).rejects.toMatchObject({code:'protocol_policy_changed'})
})
it('blocks formerly allowed reads after a policy edit, including while signing',async()=>{
  const f=fixture(),request=new Request(f.evidence.url),admission=await f.client.prepareOperation(request,f.evidence)
  f.signing.mockImplementationOnce(async()=>{f.denyReads();return {headerPatch:[{name:'signature',value:'must-not-escape'}]}})
  await expect(f.client.dispatchOperation(request,f.evidence,{policyVersion:admission.version})).rejects.toMatchObject({code:'protocol_policy_changed'})
  expect(f.dispatch).not.toHaveBeenCalled()
})
it('rejects writes, extra permissions, invented destinations, cookies and identity control paths before signing', async () => {
  for(const [request,change] of [
    [new Request('https://service.example/ad.json',{method:'POST',body:'{}'}),{}],
    [new Request('https://service.example/ad.json'),{requiresApproval:true}],
    [new Request('https://other.example/ad.json'),{}],
    [new Request('https://service.example/ad.json',{headers:{cookie:'private'}}),{}],
    [new Request('https://service.example/user-service/admin'),{url:'https://service.example/user-service/admin'}],
    [new Request('https://service.example/ad.json'),{source:'http://source.example/directory'}],
  ] as const) {
    const f=fixture()
    await expect(f.client.dispatchRead(request,{...f.evidence,...change})).rejects.toThrow()
    expect(f.signing).not.toHaveBeenCalled();expect(f.dispatch).not.toHaveBeenCalled()
  }
})
it('rechecks global policy and provider generation after asynchronous signing', async () => {
  for(const change of ['revoke','reload']) {
    const f=fixture()
    f.signing.mockImplementationOnce(async()=>{if(change==='revoke')f.deactivate();else f.reload();return {headerPatch:[{name:'signature',value:'must-not-escape'}]}})
    await expect(f.client.dispatchRead(new Request(f.evidence.url),f.evidence)).rejects.toThrow()
    expect(f.dispatch).not.toHaveBeenCalled()
  }
})
