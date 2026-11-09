import {expect,it} from 'vitest'
import {createNativeProtocolFixture} from './helpers/native-protocol-fixture.js'
import type {DomainMachineSigner} from '../src/domain-consent.js'
import type AnpIdentityService from '../src/index.js'

it('PAP domain consent binds one request and never widens the reusable Session policy',async()=>{
  const f=await createNativeProtocolFixture({consumer:'@awiki/dsh-pap/plugin',domainAccess:{enabled:true,scopes:['protocol.read']}})
  try{
    const gate=f.service.bindDomainOperationConsumer(f.context)
    const body={amount:10,currency:'USD',access_token:'must-be-hidden'}
    const make=(value=body)=>new Request('https://company.example/api/pay',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(value)})
    const pending=await gate.request({requestId:'pay-once',purpose:'PAP one payment',request:make()})
    const review=await f.management.getRequest(pending.id)
    expect(review.snapshot?.version).toBe('domain-operation/1')
    expect(review.operationPreview?.parameters).toMatchObject({amount:10,currency:'USD',access_token:'[redacted]'})
    expect(JSON.stringify(review)).not.toContain('must-be-hidden')
    await expect(f.management.decide({requestId:pending.id,expectedVersion:pending.version,decision:'approve',mode:'permanent',reviewedSnapshot:review.snapshot!})).rejects.toMatchObject({code:'once_authorization_required'})
    const approved=await f.management.decide({requestId:pending.id,expectedVersion:pending.version,decision:'approve',mode:'once',reviewedSnapshot:review.snapshot!})
    if(approved.kind!=='access'||!approved.grantId)throw new Error('Missing once grant')
    let sent=0
    await expect(gate.execute(approved.grantId,make({...body,amount:11}),async()=>{sent++;})).rejects.toThrow()
    expect(sent).toBe(0)
    await gate.execute(approved.grantId,make(),async check=>{await check();sent++;})
    expect(sent).toBe(1)
    await expect(gate.execute(approved.grantId,make(),async()=>{sent++;})).rejects.toThrow()
    expect(sent).toBe(1)
  }finally{await f.dispose()}
})
it('MCP consent exposes only a temporary exact-resource/scope signer while the once effect is active',async()=>{
  const f=await createNativeProtocolFixture({consumer:'@deepseek-ai/dsh-mcp-client/domain',domainAccess:{enabled:true,scopes:['protocol.read']}})
  try{
    const gate=f.service.bindDomainOperationConsumer(f.context)
    const request=new Request('https://company.example/mcp',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({protocol:'mcp',resource:'https://company.example/mcp',issuer:'https://company.example',tool:{name:'__mcp_tools_list__',arguments:{}},scopes:['message.write']})})
    const pending=await gate.request({requestId:'mcp-once',purpose:'MCP temporary extra scope discovery',request:request.clone()})
    const review=await f.management.getRequest(pending.id)
    const approved=await f.management.decide({requestId:pending.id,expectedVersion:pending.version,decision:'approve',mode:'once',reviewedSnapshot:review.snapshot!})
    if(approved.kind!=='access'||!approved.grantId)throw new Error('Missing grant')
    let retained:DomainMachineSigner|undefined
    const discovery={profile:'mcp_machine' as const,issuer:'https://company.example',resource:'https://company.example/mcp',tokenEndpoint:'https://company.example/token',metadataDigest:'a'.repeat(64),expiresAt:Date.now()+60000,sources:{resource:'https://company.example/.well-known/oauth-protected-resource/mcp',authorizationServer:'https://company.example/.well-known/oauth-authorization-server'}}
    await gate.execute(approved.grantId,request,async(check,caps)=>{
      await check();expect(caps.machineIdentity).toBeTruthy()
      const input={identityRef:f.reference,policyRef:'not-a-model-permission',discovery,requestedScopes:['message.write']}
      await expect(caps.machineIdentity!.registerValidatedTarget({...input,requestedScopes:['admin']})).rejects.toThrow()
      await expect(caps.machineIdentity!.registerValidatedTarget({...input,requestedScopes:[]})).rejects.toThrow()
      await expect(caps.machineIdentity!.registerValidatedTarget({...input,discovery:{...discovery,resource:'https://other.example/mcp'}})).rejects.toThrow()
      retained=await caps.machineIdentity!.registerValidatedTarget(input)
      const assertion=await retained.signOAuthClientAssertion(retained.targetRef)
      expect(assertion.split('.')).toHaveLength(3)
    })
    await expect(retained!.signOAuthClientAssertion(retained!.targetRef)).rejects.toThrow()
    const binding=await f.service.resolveDomainAccess(f.context,'mcp_machine')
    await expect(f.service.bindProtocolConsumer(f.context).registerValidatedTarget({identityRef:f.reference,policyRef:binding.policyRef,discovery,requestedScopes:['message.write']})).rejects.toThrow()
  }finally{await f.dispose()}
})
it('MCP saved permission admits only exact discovered scopes with an execution-local signer, including an empty legacy scope set',async()=>{
  const f=await createNativeProtocolFixture({consumer:'@deepseek-ai/dsh-mcp-client/domain',domainAccess:{enabled:true,scopes:[]}})
  try{
    const gate=f.service.bindDomainOperationConsumer(f.context),policy=f.service.bindProtocolPolicy(f.context,'mcp')
    const target=policy.register({discoveryOrigin:'https://website.example',destinations:['https://company.example']})
    const request=new Request('https://company.example/mcp',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({protocol:'mcp',resource:'https://company.example/mcp',issuer:'https://company.example',tool:{name:'message_send',arguments:{text:'policy allowed'}},scopes:['intent:write']})})
    const manager=f.managerContext.anpIdentity as AnpIdentityService
    const state=await manager.protocolManagement(f.managerContext)
    const {schema:_schema,version,...input}=state.policy
    let effects=0
    const authorization={target,policyVersion:version,metadataOnly:false,annotations:{readOnlyHint:false,destructiveHint:true}}
    await expect(gate.executeAllowed(request.clone(),authorization,async()=>{effects++})).rejects.toMatchObject({code:'identity_authorization_required'})
    expect(effects).toBe(0)
    input.write.mode='allow_all'
    const saved=await manager.configureProtocolPolicy(f.managerContext,{expectedVersion:version,policy:input})
    const admitted={...authorization,policyVersion:saved.version}
    let retained:DomainMachineSigner|undefined
    const discovery={profile:'mcp_machine' as const,issuer:'https://company.example',resource:'https://company.example/mcp',tokenEndpoint:'https://company.example/token',metadataDigest:'b'.repeat(64),expiresAt:Date.now()+60000,sources:{resource:'https://company.example/.well-known/oauth-protected-resource/mcp',authorizationServer:'https://company.example/.well-known/oauth-authorization-server'}}
    await gate.executeAllowed(request.clone(),admitted,async(check,caps)=>{
      await check();effects++
      const options={identityRef:f.reference,policyRef:'not-authority',discovery,requestedScopes:['intent:write']}
      await expect(caps.machineIdentity!.registerValidatedTarget({...options,requestedScopes:[]})).rejects.toThrow()
      await expect(caps.machineIdentity!.registerValidatedTarget({...options,requestedScopes:['intent:write','admin']})).rejects.toThrow()
      retained=await caps.machineIdentity!.registerValidatedTarget(options)
      expect((await retained.signOAuthClientAssertion(retained.targetRef)).split('.')).toHaveLength(3)
    })
    expect(effects).toBe(1);expect(await f.management.listRequests(true)).toHaveLength(0)
    await expect(retained!.getOAuthClientIdentity()).rejects.toThrow()
    await expect(gate.executeAllowed(request.clone(),{...admitted,annotations:undefined},async()=>{effects++})).rejects.toMatchObject({code:'identity_authorization_required'})
    await expect(gate.executeAllowed(request.clone(),{...admitted,annotations:{paymentHint:true}},async()=>{effects++})).rejects.toMatchObject({code:'identity_authorization_required'})
    input.write.mode='deny'
    await manager.configureProtocolPolicy(f.managerContext,{expectedVersion:saved.version,policy:input})
    await expect(gate.executeAllowed(request.clone(),admitted,async()=>{effects++})).rejects.toMatchObject({code:'protocol_permission_denied'})
    expect(effects).toBe(1)
  }finally{await f.dispose()}
},30000)
