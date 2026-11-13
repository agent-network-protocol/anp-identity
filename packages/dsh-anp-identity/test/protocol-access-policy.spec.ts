import { mkdtemp, rm, readFile, writeFile, stat, symlink } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, expect, it } from 'vitest'
import { initialProtocolPolicy, protocolDomain, protocolDecision, updateProtocolPolicySchema, classifyHttpEffect, classifyMcpEffect } from '../src/protocol-policy-types.js'
import { ProtocolPolicyStore, ProtocolPolicyAuthority } from '../src/protocol-policy.js'

const roots: string[] = []
const active = () => {}
it('classifies protocol semantics, bodies, explicit conflicts and extra privileges instead of names or POST transport alone', () => {
  expect(classifyHttpEffect({method:'GET',hasRequestBody:false})).toEqual({effect:'read',extraPermissions:false})
  expect(classifyHttpEffect({method:'GET',hasRequestBody:true})).toEqual({effect:'unknown',extraPermissions:false})
  expect(classifyHttpEffect({method:'POST',hasRequestBody:true,declaredEffect:'read'})).toEqual({effect:'read',extraPermissions:false})
  expect(classifyHttpEffect({method:'GET',hasRequestBody:false,declaredEffect:'write'})).toEqual({effect:'write',extraPermissions:false})
  expect(classifyHttpEffect({method:'GET',hasRequestBody:false,security:[{oauth:['private.read']}]})).toEqual({effect:'read',extraPermissions:true})
  expect(classifyHttpEffect({method:'GET',hasRequestBody:false,security:null})).toEqual({effect:'read',extraPermissions:true})
  expect(classifyHttpEffect({method:'GET',hasRequestBody:false,declaredEffect:'read',annotations:{destructiveHint:true}}).effect).toBe('unknown')
  expect(classifyHttpEffect({method:'POST',hasRequestBody:true,declaredEffect:'payment'}).effect).toBe('payment')
  expect(classifyHttpEffect({method:'GET',hasRequestBody:false,annotations:'invalid'}).effect).toBe('unknown')
  expect(classifyHttpEffect({method:'GET',hasRequestBody:false,declaredEffect:'invalid'}).effect).toBe('unknown')
  expect(classifyMcpEffect({readOnlyHint:true,destructiveHint:false}).effect).toBe('read')
  expect(classifyMcpEffect({readOnlyHint:false}).effect).toBe('write')
  expect(classifyMcpEffect({readOnlyHint:true,destructiveHint:true}).effect).toBe('unknown')
  expect(classifyMcpEffect({readOnlyHint:true}).effect).toBe('unknown')
  expect(classifyMcpEffect({paymentHint:true}).effect).toBe('payment')
  expect(classifyMcpEffect(undefined).effect).toBe('unknown')
})
afterEach(async () => { for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true }) })
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'protocol-policy-')); roots.push(root)
  const store = new ProtocolPolicyStore(root)
  let installed = true
  const assertCaller = () => { if (!installed) throw new Error('consumer_forbidden') }
  const authority = new ProtocolPolicyAuthority(store, 'pap', assertCaller)
  const target = authority.register({ discoveryOrigin: 'https://service.example', destinations: ['https://agent.service.example'] })
  return { root, store, authority, target, uninstall: () => { installed = false } }
}

it('defaults to declared reads without granting writes, payment, unknown effects or extra privileges', () => {
  const p = initialProtocolPolicy()
  for (const protocol of ['anp', 'pap', 'mcp'] as const) {
    expect(protocolDecision(p, protocol, 'service.example', 'read')).toBe('allow')
    for (const effect of ['write', 'unknown', 'payment'] as const) expect(protocolDecision(p, protocol, 'service.example', effect)).toBe('ask')
    expect(protocolDecision(p, protocol, 'service.example', 'read', true)).toBe('ask')
  }
})
it('all-write permission does not open payment, extra permissions or unknown effects', () => {
  const p = initialProtocolPolicy(); p.write.mode = 'allow_all'
  expect(protocolDecision(p, 'pap', 'service.example', 'write')).toBe('allow')
  expect(protocolDecision(p, 'pap', 'service.example', 'write', true)).toBe('ask')
  expect(protocolDecision(p, 'pap', 'service.example', 'payment')).toBe('ask')
  expect(protocolDecision(p, 'pap', 'service.example', 'unknown')).toBe('ask')
  p.write.mode = 'deny'
  expect(protocolDecision(p, 'pap', 'service.example', 'payment')).toBe('deny')
})
it('whitelists are exact domains with explicit protocol and outside behavior', () => {
  const p = initialProtocolPolicy()
  p.write = { mode: 'whitelist', outside: 'deny', domains: [{ domain: 'service.example', protocols: ['pap', 'anp'] }] }
  expect(protocolDecision(p, 'pap', 'service.example', 'write')).toBe('allow')
  expect(protocolDecision(p, 'anp', 'service.example', 'write')).toBe('allow')
  for (const domain of ['sub.service.example', 'evilservice.example', 'service.example.evil.test']) expect(protocolDecision(p, 'pap', domain, 'write')).toBe('deny')
  expect(protocolDecision(p, 'mcp', 'service.example', 'write')).toBe('deny')
  p.write.outside = 'ask'
  expect(protocolDecision(p, 'mcp', 'service.example', 'write')).toBe('ask')
  // Displayed service cards are deliberately not a built-in permission list.
  expect(protocolDecision(p, 'pap', 'agent-network-protocol.com', 'write')).toBe('ask')
  expect(protocolDecision(p, 'pap', 'matchall.net', 'write')).toBe('ask')
})
it('read and write rules are independent, including all-deny', () => {
  const p = initialProtocolPolicy(); p.read.mode = 'deny'; p.write.mode = 'allow_all'
  expect(protocolDecision(p, 'mcp', 'service.example', 'read')).toBe('deny')
  expect(protocolDecision(p, 'mcp', 'service.example', 'write')).toBe('allow')
})
it('normalizes IDNA and case without silently creating suffix rules', () => {
  expect(protocolDomain('SERVICE.EXAMPLE')).toBe('service.example')
  expect(protocolDomain('例子.测试')).toBe('xn--fsqu00a.xn--0zwm56d')
  const p = initialProtocolPolicy(); p.write = { mode: 'whitelist', outside: 'deny', domains: [{ domain: protocolDomain('例子.测试'), protocols: ['pap'] }] }
  expect(protocolDecision(p, 'pap', '例子.测试', 'write')).toBe('allow')
})
it.each(['', 'https://service.example', 'service.example/path', 'service.example:443', '*.example.com', '.example.com', 'example.com.', 'user@example.com', 'example.com?x=1', 'example.com#x', '127.0.0.1', 'localhost', '[::1]', 'a..example', 'a_thing.example', 'example%2ecom', ' example.com'])('rejects non-domain whitelist input: %s', domain => {
  expect(() => protocolDomain(domain)).toThrow('protocol_policy_invalid_domain')
})
it('validates strict settings and refuses unsafe model-shaped additions', () => {
  const policy = initialProtocolPolicy()
  expect(() => updateProtocolPolicySchema.parse({ expectedVersion: 0, policy, caller: 'owner' })).toThrow()
  const { schema: _schema, version: _version, ...input } = policy
  expect(updateProtocolPolicySchema.parse({ expectedVersion: 0, policy: input }).policy).toEqual(input)
  expect(() => updateProtocolPolicySchema.parse({ expectedVersion: -1, policy: input })).toThrow()
})
it('persists preferences across instances with exclusive CAS and private file modes', async () => {
  const { root, store } = await fixture()
  expect(await store.read(active)).toEqual(initialProtocolPolicy())
  const { schema: _s, version: _v, ...policy } = initialProtocolPolicy(); policy.write.mode = 'allow_all'
  expect((await store.update({ expectedVersion: 0, policy }, active)).version).toBe(1)
  const restarted = new ProtocolPolicyStore(root)
  expect((await restarted.read(active)).write.mode).toBe('allow_all')
  await expect(restarted.update({ expectedVersion: 0, policy }, active)).rejects.toThrow('protocol_policy_conflict')
  if (process.platform !== 'win32') {
    expect((await stat(join(root, 'manager-settings'))).mode & 0o777).toBe(0o700)
    expect((await stat(join(root, 'manager-settings/protocol-access.json'))).mode & 0o777).toBe(0o600)
  }
})
it('admits exactly one concurrent owner update without losing the winning version', async () => {
  const { root, store } = await fixture(); await store.read(active)
  const { schema: _s, version: _v, ...policy } = initialProtocolPolicy()
  const outcomes = await Promise.allSettled([store.update({ expectedVersion: 0, policy }, active), new ProtocolPolicyStore(root).update({ expectedVersion: 0, policy }, active)])
  expect(outcomes.filter(outcome => outcome.status === 'fulfilled')).toHaveLength(1)
  expect((await store.read(active)).version).toBe(1)
})
it('never resets corrupt files or persists a preference after owner authority disappears', async () => {
  const { root, store } = await fixture(); await store.read(active)
  const { schema: _s, version: _v, ...policy } = initialProtocolPolicy()
  await expect(store.update({ expectedVersion: 0, policy }, () => { throw new Error('inactive') })).rejects.toThrow('inactive')
  const path = join(root, 'manager-settings/protocol-access.json')
  await writeFile(path, 'corrupt', { mode: 0o600 })
  await expect(store.read(active)).rejects.toThrow('protocol_policy_unavailable')
  expect(await readFile(path, 'utf8')).toBe('corrupt')
})
it.skipIf(process.platform === 'win32')('does not follow a settings symlink or expose a wide-readable settings file', async () => {
  const { root, store } = await fixture(); await store.read(active)
  const outside = join(root, 'outside.json'), path = join(root, 'manager-settings/protocol-access.json')
  await writeFile(outside, JSON.stringify(initialProtocolPolicy()), { mode: 0o600 })
  await symlink(outside, path)
  await expect(store.read(active)).rejects.toThrow('protocol_policy_unavailable')
  await rm(path)
  await writeFile(path, JSON.stringify(initialProtocolPolicy()), { mode: 0o644 })
  await expect(store.read(active)).rejects.toThrow('protocol_policy_unavailable')
})
it('uses the validated discovery source domain for a cross-origin endpoint without granting sibling origins', async () => {
  const { store, authority, target } = await fixture()
  const { schema: _s, version: _v, ...policy } = initialProtocolPolicy()
  policy.write = { mode: 'whitelist', outside: 'deny', domains: [{ domain: 'service.example', protocols: ['pap'] }] }
  await store.update({ expectedVersion: 0, policy }, active)
  const admitted = await authority.evaluate(target, { url: 'https://agent.service.example/posts', effect: 'write' })
  expect(admitted.decision).toBe('allow'); await admitted.assertActive()
  await expect(authority.evaluate(target, { url: 'https://evil.service.example/posts', effect: 'write' })).rejects.toThrow('protocol_policy_invalid_target')
  await expect(authority.evaluate(target, { url: 'https://agent.service.example.evil.test/posts', effect: 'write' })).rejects.toThrow('protocol_policy_invalid_target')
  await expect(authority.evaluate({ protocolTarget: true }, { url: 'https://agent.service.example/posts', effect: 'write' })).rejects.toThrow('protocol_policy_invalid_target')
})
it('rechecks policy immediately before sending and invalidates both allowed and pending admissions after any edit', async () => {
  const { store, authority, target } = await fixture()
  const read = await authority.evaluate(target, { url: 'https://agent.service.example/posts', effect: 'read' })
  const write = await authority.evaluate(target, { url: 'https://agent.service.example/posts', effect: 'write' })
  expect(read.decision).toBe('allow'); expect(write.decision).toBe('ask')
  const { schema: _s, version: _v, ...policy } = initialProtocolPolicy(); policy.read.mode = 'deny'; policy.write.mode = 'deny'
  await store.update({ expectedVersion: 0, policy }, active)
  await expect(read.assertActive()).rejects.toThrow('protocol_policy_changed')
  await expect(write.assertActive()).rejects.toThrow('protocol_policy_changed')
  const blocked = await authority.evaluate(target, { url: 'https://agent.service.example/posts', effect: 'write' })
  expect(blocked.decision).toBe('deny'); await expect(blocked.assertActive()).rejects.toThrow('protocol_policy_changed')
})
it('never borrows an opaque target from another adapter instance and revokes forgotten targets', async () => {
  const { store, authority, target } = await fixture()
  const other = new ProtocolPolicyAuthority(store, 'anp', active)
  await expect(other.evaluate(target, { url: 'https://agent.service.example/posts', effect: 'read' })).rejects.toThrow('protocol_policy_invalid_target')
  const admitted = await authority.evaluate(target, { url: 'https://agent.service.example/posts', effect: 'read' })
  authority.forget(target)
  await expect(admitted.assertActive()).rejects.toThrow('protocol_policy_target_revoked')
})
it('checks installed caller liveness before returning or using a decision', async () => {
  const { authority, target, uninstall } = await fixture()
  const admitted = await authority.evaluate(target, { url: 'https://agent.service.example/posts', effect: 'read' })
  uninstall()
  await expect(admitted.assertActive()).rejects.toThrow('consumer_forbidden')
  await expect(authority.evaluate(target, { url: 'https://agent.service.example/posts', effect: 'read' })).rejects.toThrow('consumer_forbidden')
})
