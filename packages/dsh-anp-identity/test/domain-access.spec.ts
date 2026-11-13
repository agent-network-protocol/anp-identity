import { expect, it, vi } from 'vitest'
import { DomainAccessResolver } from '../src/domain-access.js'
import type { ProtocolUsePolicy } from '../src/protocol-client.js'
import { isPublicDomainAddress } from '../src/public-http.js'

const identity = { storeId: 'store', identityId: 'identity', did: 'did:wba:identity.example' }
const consumer = '@awiki/dsh-pap/plugin'
it('resolves one published identity without a domain and installs only the Host scope ceiling', async () => {
  const policies: ProtocolUsePolicy[] = []
  const resolver = new DomainAccessResolver({ enabled: true, scopes: ['protocol.read'] }, '/isolated', async () => [identity], policy => policies.push(policy))
  const binding = await resolver.resolve(consumer, 'pap_session')
  expect(binding).toMatchObject({ identityRef: identity, scopes: [], secretStore: 'keyring' })
  expect(binding.stateRoot).not.toEqual(binding.secretsRoot)
  expect(policies[0]).toMatchObject({ consumer, publicTargets: true, scopes: [], profiles: ['pap_session'] })
  expect(await resolver.resolve(consumer, 'pap_session')).toEqual(binding)
  await resolver.resolve('@deepseek-ai/dsh-mcp-client/domain', 'mcp_machine')
  expect(policies.at(-1)).toMatchObject({ scopes: ['protocol.read'], profiles: ['mcp_machine'], consumer: '@deepseek-ai/dsh-mcp-client/domain' })
  const count = policies.length
  await resolver.resolve('@agent-network-protocol/dsh-anp/plugin', 'anp')
  expect(policies).toHaveLength(count)
  await expect(resolver.resolve('untrusted', 'pap_session')).rejects.toMatchObject({ code: 'consumer_forbidden' })
})
it('never silently chooses between identities or substitutes a missing selected identity', async () => {
  const other = { ...identity, identityId: 'other' }
  const install = vi.fn()
  const multiple = new DomainAccessResolver({ enabled: true, scopes: [] }, '/isolated', async () => [identity, other], install)
  await expect(multiple.resolve(consumer, 'pap_session')).rejects.toMatchObject({ code: 'default_identity_required' })
  const selected = new DomainAccessResolver({ enabled: true, scopes: [], identity: other }, '/isolated', async () => [identity], install)
  await expect(selected.resolve(consumer, 'pap_session')).rejects.toMatchObject({ code: 'published_identity_required' })
  expect(install).not.toHaveBeenCalled()
})
it('does not replace missing Host permission, scope permission, or expired permission with discovery', async () => {
  const candidates = vi.fn(async () => [identity])
  for (const config of [undefined, { enabled: false, scopes: [] }]) {
    await expect(new DomainAccessResolver(config, '/isolated', candidates, vi.fn()).resolve(consumer, 'pap_session')).rejects.toMatchObject({ code: 'domain_access_disabled' })
  }
  await expect(new DomainAccessResolver({ enabled: true, scopes: [], expiresAt: 1 }, '/isolated', candidates, vi.fn()).resolve(consumer, 'pap_session')).rejects.toMatchObject({ code: 'domain_access_expired' })
  expect(candidates).not.toHaveBeenCalled()
  const install=vi.fn()
  expect(await new DomainAccessResolver({ enabled: true, scopes: [] }, '/isolated', candidates, install).resolve('@deepseek-ai/dsh-mcp-client/domain', 'mcp_machine')).toMatchObject({scopes:[]})
  expect(install).not.toHaveBeenCalled() // Discovery may request a policy-bounded temporary signer, not a permanent scope expansion.
})
it('rejects private, mapped and special network destinations in domain mode', () => {
  for (const address of ['127.0.0.1', '10.0.0.1', '169.254.169.254', '192.168.1.1', '::1', '::ffff:8.8.8.8', '2001:db8::1', '2002::1']) expect(isPublicDomainAddress(address)).toBe(false)
  expect(isPublicDomainAddress('8.8.8.8')).toBe(true)
  expect(isPublicDomainAddress('2606:4700:4700::1111')).toBe(true)
})

it('keeps storage and disconnect fences stable when the Host extends expiry or changes scopes', async () => {
  const first = new DomainAccessResolver({enabled:true,scopes:['protocol.read'],expiresAt:Date.now()+60000},'/isolated',async()=>[identity],()=>{})
  const next = new DomainAccessResolver({enabled:true,scopes:['protocol.read','message.write'],expiresAt:Date.now()+120000},'/isolated',async()=>[identity],()=>{})
  const a=await first.resolve('@deepseek-ai/dsh-mcp-client/domain','mcp_machine')
  const b=await next.resolve('@deepseek-ai/dsh-mcp-client/domain','mcp_machine')
  expect(a.stateRoot).toBe(b.stateRoot)
  expect(a.secretsRoot).toBe(b.secretsRoot)
  expect(a.policyRef).not.toBe(b.policyRef)
})
