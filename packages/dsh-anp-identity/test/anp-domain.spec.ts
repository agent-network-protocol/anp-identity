import { expect, it, vi } from 'vitest'
import type { Context } from '@deepseek-ai/cordis'
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import { AnpDomainReadAuthority, type AnpReadEvidence } from '../src/anp-domain.js'

function fixture() {
  const context = {} as Context
  let active = true, generation = 1
  const identity = {storeId:'store',identityId:'identity',did:'did:wba:identity.example'}
  const binding = {identityRef:identity,policyRef:'global-read',stateRoot:'/state',secretsRoot:'/keys',secretStore:'local-file' as const,scopes:[]}
  const signing = vi.fn(async () => ({headerPatch:[{name:'signature-input',value:'fixture-input'},{name:'signature',value:'fixture-signature'}]}))
  const native = {publicIdentity:async()=>({activeKeys:[{kid:identity.did+'#device',algorithm:'ed25519',purposes:['authentication','device_assertion']}]}),prepareHttpSignature:signing} as unknown as ProviderLease
  const dispatch = vi.fn(async (request: Request) => {expect(request.headers.get('signature')).toBe('fixture-signature');return Response.json({read:true})})
  const authority = new AnpDomainReadAuthority({assertCaller:ctx=>{if(ctx!==context||!active)throw new Error('forbidden')},generation:()=>generation,
    resolve:async()=>{if(!active)throw new Error('revoked');return binding},withNative:async run=>run(native),dispatch})
  const evidence: AnpReadEvidence = {profile:'anp-discovered/1',kind:'agent',source:'https://website.example/.well-known/agent-descriptions',url:'https://service.example/ad.json',requiresApproval:false}
  return {client:authority.bind(context),authority,context,evidence,dispatch,signing,deactivate(){active=false},reload(){generation++}}
}
it('signs only the exact discovered read without granting raw signatures or an ordinary HTTP lease', async () => {
  const f=fixture()
  const response=await f.client.dispatchRead(new Request(f.evidence.url),f.evidence)
  expect(await response.json()).toEqual({read:true})
  expect(Object.keys(f.client)).toEqual(['dispatchRead'])
  expect(f.signing).toHaveBeenCalledOnce()
  expect(()=>f.authority.bind({} as Context)).toThrow()
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
