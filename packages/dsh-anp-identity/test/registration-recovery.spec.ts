import { Context } from '@deepseek-ai/cordis'
import TypertRegistry from '@deepseek-ai/dsh-typert-registry'
import TypertGateway from '@deepseek-ai/dsh-api-gateway'
import RemoteAccessService from '@deepseek-ai/dsh-api-remote-access'
import { Peer } from '@deepseek-ai/dsh-client-connection'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, it, vi } from 'vitest'
import ManagerRemote from '../lib/management-remote.js'
import { RegistrationOnboardingStore } from '../src/registration-onboarding.js'
import { PROTOCOL_BOOTSTRAP_CONSUMER } from '../src/protocol-bootstrap.js'

async function fixture(executed: boolean, deleted = true) {
  const root = await mkdtemp(join(tmpdir(), 'registration-recovery-'))
  const store = new RegistrationOnboardingStore(root)
  const saved = await store.create({ expectedOrigin: 'https://awiki.me', expectedVersion: 0,
    label: 'Example', handle: 'test-agent', phone: '+15551234567', profile: 'e1' }, 'https://awiki.me', () => {})
  if (executed) await mkdir(join(root, 'registration-bootstrap', createHash('sha256').update(saved.config.id).digest('hex')), { recursive: true, mode: 0o700 })
  const reference = { storeId: 'store', identityId: 'deleted', did: 'did:wba:awiki.me:user:test-agent' }
  const request = { id: saved.config.requestId, kind: 'create', status: 'approved', executionStatus: deleted ? 'deleted' : 'succeeded',
    caller: { consumer: PROTOCOL_BOOTSTRAP_CONSUMER }, parameters: saved.parameters, result: { reference } }
  const manager = { getRequest: vi.fn(async () => ({ request, identities: [] })), listIdentities: vi.fn(async () => []) }
  const pin = vi.fn(async () => { throw Object.assign(new Error('Provider is not ready'), { code: 'provider_unavailable' }) })
  const ctx = new Context()
  ctx.provide('anpIdentity', { acquireManagement: () => manager, registrationBootstrapRoot: () => root,
    registrationServiceSettings: async () => ({ origin: 'https://awiki.me', version: 0 }), pinManagementContext: pin })
  ctx.provide('anpIdentityRequester', { request: vi.fn(async () => {}), available: () => true })
  const definitions = new Map<string, { execute(input: object, execution: object): Promise<unknown> }>()
  ctx.provide('tools', { register(value: { name: string; execute(input: object, execution: object): Promise<unknown> }) { definitions.set(value.name, value) } })
  await ctx.plugin(TypertRegistry)
  await ctx.plugin(RemoteAccessService)
  await ctx.plugin(TypertGateway)
  await ctx.plugin(ManagerRemote)
  const invoke = (method: string) => ctx.typertGateway.invoke({ peer: new Peer(ctx, { principal: { kind: 'owner' } }),
    namespace: 'anpIdentityManager', method, args: {} })
  return { ctx, root, saved, store, manager, pin, invoke, definitions,
    dispose: async () => { await ctx.fiber.dispose(); await rm(root, { recursive: true, force: true }) } }
}

it('recovers only a ledger-confirmed deleted and unstarted flow, without creating an identity or sending an OTP', async () => {
  const f = await fixture(false)
  try {
    expect(await f.invoke('registrationOnboardingStatus')).toMatchObject({ version: 2, archived: true, inProgress: false })
    expect(await f.invoke('registrationBootstrapStatus')).toEqual([])
    expect(await f.store.read(() => {})).toMatchObject({ version: 2, archived: true, config: f.saved.config })
    await vi.waitFor(() => expect(f.definitions.has('identity_status')).toBe(true))
    expect(await f.definitions.get('identity_status')!.execute({}, { agent: {} })).toMatchObject({ ok: true,
      value: { identities: [], registrationPhase: 'not_started', registrationArchived: true } })
    expect(await f.definitions.get('identity_request_creation')!.execute({}, { agent: {} })).toMatchObject({ ok: true,
      value: { status: 'awaiting_user_input' } })
    expect(f.pin).not.toHaveBeenCalled()
    expect(JSON.stringify(await f.invoke('registrationOnboardingStatus'))).not.toContain('+15551234567')
  } finally { await f.dispose() }
})

it('keeps initialized deleted flows blocked and exposes the reason without resetting their journal', async () => {
  const f = await fixture(true)
  try {
    expect(await f.invoke('registrationOnboardingStatus')).toMatchObject({ version: 1, archived: false, inProgress: true })
    await vi.waitFor(async () => expect(await f.invoke('registrationBootstrapStatus')).toMatchObject([{ phase: 'blocked', reason: 'identity_deleted' }]))
    expect(await f.definitions.get('identity_status')!.execute({}, { agent: {} })).toMatchObject({ ok: true,
      value: { registrationPhase: 'blocked', registrationReason: 'identity_deleted' } })
    expect(await f.store.read(() => {})).toEqual(f.saved)
    expect(f.pin).not.toHaveBeenCalled()
  } finally { await f.dispose() }
})

it('does not mistake an empty identity list or an unavailable provider for proof of deletion', async () => {
  const f = await fixture(false, false)
  try {
    await f.invoke('registrationOnboardingStatus')
    await vi.waitFor(async () => expect(await f.invoke('registrationBootstrapStatus')).toMatchObject([{ phase: 'blocked', reason: 'provider_unavailable' }]))
    expect(await f.store.read(() => {})).toEqual(f.saved)
    expect(JSON.parse(await readFile(join(f.root, 'owner-registration.json'), 'utf8')).archived).toBeUndefined()
  } finally { await f.dispose() }
})
