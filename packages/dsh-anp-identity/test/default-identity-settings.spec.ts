import { afterEach, expect, it, vi } from 'vitest'
import { mkdtemp, readFile, rm, writeFile, chmod } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DefaultIdentitySettingsStore } from '../src/default-identity-settings.js'
import { DomainAccessResolver } from '../src/domain-access.js'

const roots: string[] = []
afterEach(async () => { await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true }))) })
const identity = { storeId: 'store', identityId: 'one', did: 'did:wba:identity.example:one' }
const other = { ...identity, identityId: 'two', did: 'did:wba:identity.example:two' }
const check = () => {}
async function fixture() { const root = await mkdtemp(join(tmpdir(), 'default-identity-')); roots.push(root); return { root, store: new DefaultIdentitySettingsStore(root, identity) } }

it('preserves the profile pin until an owner saves a durable selection or automatic mode', async () => {
  const { root, store } = await fixture()
  expect(await store.read(check)).toEqual({ schema: 1, version: 0, identity })
  expect(await store.update({ expectedVersion: 0, identity: other }, check)).toMatchObject({ version: 1, identity: other })
  const reopened = new DefaultIdentitySettingsStore(root, identity)
  expect(await reopened.read(check)).toMatchObject({ version: 1, identity: other })
  await reopened.update({ expectedVersion: 1, identity: null }, check)
  expect(await new DefaultIdentitySettingsStore(root, identity).read(check)).toMatchObject({ version: 2, identity: null })
  await expect(store.update({ expectedVersion: 0, identity }, check)).rejects.toThrow('default_identity_conflict')
})
it('serializes independent store instances and keeps corruption closed rather than resetting preferences', async () => {
  const { root, store } = await fixture()
  const writers = [store, new DefaultIdentitySettingsStore(root, identity)]
  const results = await Promise.allSettled(writers.map(writer => writer.update({ expectedVersion: 0, identity: other }, check)))
  expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1)
  expect(results.filter(result => result.status === 'rejected')).toHaveLength(1)
  const path = join(root, 'manager-settings', 'default-identity.json')
  await writeFile(path, '{broken', { mode: 0o600 })
  await expect(store.read(check)).rejects.toThrow('default_identity_settings_unavailable')
  await expect(store.update({ expectedVersion: 1, identity }, check)).rejects.toThrow('default_identity_settings_unavailable')
  expect(await readFile(path, 'utf8')).toBe('{broken')
})
it('rejects unknown fields, unsafe file permissions and revoked callers before committing', async () => {
  const { root, store } = await fixture()
  expect(() => store.update({ expectedVersion: 0, identity, consumer: 'owner' } as any, check)).toThrow()
  const revoked = vi.fn(() => { throw new Error('caller_revoked') })
  await expect(store.update({ expectedVersion: 0, identity }, revoked)).rejects.toThrow('caller_revoked')
  await store.update({ expectedVersion: 0, identity }, check)
  if (process.platform !== 'win32') {
    await chmod(join(root, 'manager-settings', 'default-identity.json'), 0o644)
    await expect(store.read(check)).rejects.toThrow('default_identity_settings_unavailable')
  }
})
it('uses saved defaults for every profile, changes the admission epoch and keeps identity storage stable', async () => {
  const { store } = await fixture()
  const resolver = new DomainAccessResolver({ enabled: true, scopes: ['protocol.read'], identity }, '/isolated', async () => [identity, other], check, () => store.read(check))
  const consumer = '@awiki/dsh-pap/plugin'
  const old = await resolver.resolve(consumer, 'pap_session')
  await store.update({ expectedVersion: 0, identity: other }, check)
  expect((await resolver.resolve(consumer, 'pap_session')).identityRef).toEqual(other)
  expect((await resolver.resolve('@agent-network-protocol/dsh-anp/plugin', 'anp')).identityRef).toEqual(other)
  expect((await resolver.resolve('@deepseek-ai/dsh-mcp-client/domain', 'mcp_machine')).identityRef).toEqual(other)
  await store.update({ expectedVersion: 1, identity }, check)
  const returned = await resolver.resolve(consumer, 'pap_session')
  expect(returned.stateRoot).toBe(old.stateRoot)
  expect(returned.policyRef).not.toBe(old.policyRef)
  await store.update({ expectedVersion: 2, identity: null }, check)
  await expect(resolver.resolve(consumer, 'pap_session')).rejects.toMatchObject({ code: 'default_identity_required' })
})
it('does not substitute a missing default or resolve across a concurrent default change', async () => {
  let selection = { identity, version: 1 }
  const unavailable = new DomainAccessResolver({ enabled: true, scopes: [] }, '/isolated', async () => [other], check, async () => selection)
  await expect(unavailable.resolve('@awiki/dsh-pap/plugin', 'pap_session')).rejects.toMatchObject({ code: 'published_identity_required' })
  const raced = new DomainAccessResolver({ enabled: true, scopes: [] }, '/isolated', async () => { selection = { identity: other, version: 2 }; return [identity, other] }, check, async () => selection)
  await expect(raced.resolve('@awiki/dsh-pap/plugin', 'pap_session')).rejects.toMatchObject({ code: 'default_identity_changed' })
})
