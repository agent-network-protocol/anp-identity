/** State-machine units use service doubles; real authority/factors/SQL belong to registration-bootstrap-live.spec.ts. */
import { Context } from '@deepseek-ai/cordis'
import CredentialsLocal from '@deepseek-ai/dsh-credentials-local'
import { credentialKey } from '@deepseek-ai/dsh-credentials'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, readdir, realpath, rm, unlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, expect, it, vi } from 'vitest'
import type AnpIdentityService from '../src/index.js'
import type { IdentityManagement } from '../src/management-types.js'
import type { CreateAuthorizationRequest } from '../src/authorization-types.js'
import { RegistrationBootstrapConfigSchema, startRegistrationBootstrap } from '../src/registration-bootstrap.js'
import { PROTOCOL_BOOTSTRAP_CONSUMER } from '../src/protocol-bootstrap.js'

const installedVersion = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')).version as string
const expectedClientVersion = 'dsh-identity/1106/' + installedVersion

const roots: string[] = []
const cleanups: Array<() => Promise<void>> = []
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup()
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true })
  vi.restoreAllMocks()
})
const response = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } })
const sha = (value: string) => createHash('sha256').update(value).digest('hex')

it('rejects callback/profile misconfiguration before installing any registration work', () => {
  const base = { id: 'bootstrap', requestId: 'request', stateRoot: '/private/state', origin: 'https://identity.example', email: 'agent@example.com', clientName: 'Agent' }
  expect(RegistrationBootstrapConfigSchema.safeParse({ ...base, redirectUris: ['https://identity.example/callback'] }).success).toBe(false)
  expect(RegistrationBootstrapConfigSchema.safeParse({ ...base, capabilities: { mcpMachine: false, papSession: true, papAccount: true } }).success).toBe(false)
  expect(RegistrationBootstrapConfigSchema.safeParse({ ...base, accessToken: 'must-not-be-configured' }).success).toBe(false)
})

async function fixture(options: { missingCredentials?: boolean; uncertainRegistration?: boolean; upgrade?: boolean; registerViaTransport?: boolean; phone?: boolean; phoneRejected?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'c-bootstrap-unit-')); roots.push(root)
  const context = new Context(); cleanups.push(() => context.fiber.dispose())
  if (!options.missingCredentials) await context.plugin(CredentialsLocal, { path: join(root, '.credentials.yaml'), watch: false })
  const config = RegistrationBootstrapConfigSchema.parse({ id: 'stable', requestId: 'request', stateRoot: root,
    origin: 'https://identity.example', ...(options.phone ? { phone: '+15555550190' } : { email: 'agent@example.com' }), clientName: 'Unit protocol identity', pollIntervalMs: 100 })
  const reference = { storeId: 'store', identityId: 'identity', did: 'did:wba:identity.example:awiki:user:agent' }
  let request: CreateAuthorizationRequest = { id: 'request', kind: 'create', status: 'pending', version: 1,
    caller: { consumer: PROTOCOL_BOOTSTRAP_CONSUMER, displayName: 'Bootstrap' }, purpose: 'Create a protocol identity',
    parameters: { usage: 'protocol', profile: 'e1', label: 'Agent', domain: 'identity.example', path: '/awiki/user/agent', handle: 'agent.identity.example' },
    createdAt: 1, expiresAt: Date.now() + 60000, fingerprint: 'test', prompted: false }
  let verified = false
  let providerActive = true, managerActive = true
  let heldStatus: Promise<Response> | undefined
  const requests: Request[] = []
  const send: typeof fetch = async (input, init) => {
    const request = new Request(input, init); requests.push(request)
    if (request.url.includes('email-status') && heldStatus) return heldStatus
    if (options.upgrade) return response({ error: { message: 'private server detail', data: { awiki_code: 'client.upgrade_required' } } })
    if (request.url.endsWith('/handle/rpc')) {
      const body = await request.clone().json() as { id: string }
      return response({ jsonrpc: '2.0', id: body.id, ...(options.phoneRejected ? { error: { code: -32000, message: 'private provider detail' } } : { result: { ok: true } }) })
    }
    return request.url.includes('email-status') ? response({ verified }) : response({ message: 'Activation email sent.' })
  }
  const published = { state: 'published' as const, did: reference.did, clientId: config.origin + '/user-service/v1/agent-clients/document/client.json',
    algorithm: 'ES256' as const, signerMode: 'local' as const, capabilities: config.capabilities, version: 1, keyId: reference.did + '#oauth' }
  const manager = {
    getRequest: vi.fn(async () => ({ request: structuredClone(request), identities: [] })),
    publicationStatus: vi.fn(async () => ({ state: 'local', did: reference.did })),
    publishIdentity: vi.fn(async () => published),
  } as unknown as IdentityManagement
  const register = vi.fn<AnpIdentityService['registerLocalIdentity']>(async (_context, input) => {
    if (options.registerViaTransport) await input.fetch!(new Request(config.origin + '/user-service/v1/did-auth/rpc', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', method: 'register', params: {} }),
    }))
    if (options.uncertainRegistration) throw new Error('fixture lost registration result')
    await input.credentials.set(reference, config.origin, { accessToken: 'unit-private-device-token', deviceId: 'device', signingKeyId: reference.did + '#device' })
    return { did: reference.did, deviceId: 'device', state: 'registered' }
  })
  const backendDispose = vi.fn()
  const assertManager = () => { if (!managerActive) throw Object.assign(new Error('unit manager disposed'), { code: 'consumer_forbidden' }) }
  const service = {
    acquireManagement: () => { assertManager(); return manager },
    pinManagementContext: async (_context: Context, _reference: unknown, additionalCheck?: () => void) => {
      const check = () => { additionalCheck?.(); assertManager(); if (!providerActive) throw Object.assign(new Error('unit provider disposed'), { code: 'provider_disposed' }) }
      check(); return check
    },
    registerLocalIdentity: register,
    configureManagedPublicationBackend: vi.fn(async () => ({ backend: 'bootstrap-stable', documentId: 'document', dispose: backendDispose,
      callbackManagement: { execute: async () => { throw new Error('callback is outside this unit') } } })),
  } as unknown as AnpIdentityService
  const start = () => {
    const controller = startRegistrationBootstrap({ context, config, service, manager, fetch: send })
    cleanups.push(() => controller.dispose()); return controller
  }
  const approve = () => { request = { ...request, status: 'approved', executionStatus: 'succeeded', result: { reference, label: 'Agent' } } }
  return { root, context, config, reference, get request() { return request }, manager, service, register, requests, start, approve,
    verify: () => { verified = true }, revokeProvider: () => { providerActive = false }, revokeManager: () => { managerActive = false },
    holdStatus: (value: Promise<Response>) => { heldStatus = value } }
}

it('sends no mail or registration before approval and persists one mail attempt across restart', async () => {
  const f = await fixture(); const first = f.start()
  await vi.waitFor(() => expect(f.manager.getRequest).toHaveBeenCalled())
  expect(f.requests).toHaveLength(0); expect(f.register).not.toHaveBeenCalled()
  f.approve()
  await vi.waitFor(() => expect(f.requests.filter(request => request.url.endsWith('email-send'))).toHaveLength(1))
  await first.dispose()
  const second = f.start()
  await vi.waitFor(() => expect(second.status().phase).toBe('awaiting_email_verification'))
  expect(f.requests.filter(request => request.url.endsWith('email-send'))).toHaveLength(1)
  f.verify()
  await vi.waitFor(() => expect(second.status().phase).toBe('published'))
  expect(f.register).toHaveBeenCalledOnce()
  expect(f.requests.every(request => request.headers.get('X-AWiki-Client-Version') === expectedClientVersion)).toBe(true)
  expect(JSON.stringify(second.status())).not.toMatch(/unit-private-device-token|agent@example.com|ciphertext|key/u)
})

it('retains an uncertain registration outcome without retrying it after restart', async () => {
  const f = await fixture({ uncertainRegistration: true }); f.approve(); f.verify()
  const first = f.start()
  await vi.waitFor(() => expect(first.status().phase).toBe('registration_uncertain'))
  await first.dispose()
  const second = f.start()
  await vi.waitFor(() => expect(second.status().phase).toBe('registration_uncertain'))
  expect(f.register).toHaveBeenCalledOnce()
})

it('closes the initial journal permission when its single registration attempt finishes', async () => {
  const f = await fixture(); f.approve(); f.verify()
  const controller = f.start()
  await vi.waitFor(() => expect(controller.status().phase).toBe('published'))
  const permission = f.register.mock.calls[0]![1].assertActive!
  expect(() => permission()).toThrow('bootstrap_registration_unavailable')
})

it('does not treat product admission as verification and exposes only the stable upgrade reason', async () => {
  const f = await fixture({ upgrade: true }); f.approve()
  const controller = f.start()
  await vi.waitFor(() => expect(controller.status()).toMatchObject({ phase: 'blocked', reason: 'client_upgrade_required' }))
  expect(f.register).not.toHaveBeenCalled()
  expect(JSON.stringify(controller.status())).not.toContain('private server detail')
})

it('requires the real credential service before sending mail', async () => {
  const f = await fixture({ missingCredentials: true }); f.approve()
  const controller = f.start()
  await vi.waitFor(() => expect(controller.status()).toMatchObject({ phase: 'blocked', reason: 'credential_unavailable' }))
  expect(f.requests).toHaveLength(0); expect(f.register).not.toHaveBeenCalled()
})

it('does not regenerate a used key on restart and preserves encrypted broker bytes', async () => {
  const f = await fixture(); f.approve(); f.verify()
  const first = f.start(); await vi.waitFor(() => expect(first.status().phase).toBe('published'))
  await first.dispose()
  const brokerRoot = join(await realpath(f.root), 'registration-bootstrap', sha(f.config.id), 'credentials')
  const file = (await readdir(brokerRoot)).find(name => /^[a-f0-9]{64}\.json$/u.test(name))!
  const before = await readFile(join(brokerRoot, file), 'utf8')
  const key = credentialKey('anp-identity-manager', 'management-broker-' + sha(JSON.stringify([brokerRoot, f.config.id])))
  await f.context.credentials.deleteRecord(key)
  const second = f.start()
  await vi.waitFor(() => expect(second.status()).toMatchObject({ phase: 'blocked', reason: 'credential_unavailable' }))
  expect(await readFile(join(brokerRoot, file), 'utf8')).toBe(before)
  expect(f.register).toHaveBeenCalledOnce()
})

it('does not accept another consumer or an ordinary creation approval as the configured identity', async () => {
  for (const field of ['caller', 'usage'] as const) {
    const f = await fixture(); f.approve()
    if (field === 'caller') (f.request.caller as { consumer: string }).consumer = 'different-consumer'
    else (f.request.parameters as { usage: string }).usage = 'ordinary'
    const controller = f.start()
    await vi.waitFor(() => expect(controller.status()).toMatchObject({ phase: 'blocked', reason: 'invalid_configuration' }))
    expect(f.requests).toHaveLength(0); expect(f.register).not.toHaveBeenCalled()
  }
})

it('does not recreate a missing established key after its marker was also deleted from a used scope', async () => {
  const f = await fixture(); f.approve()
  const first = f.start()
  await vi.waitFor(() => expect(f.requests.filter(request => request.url.endsWith('email-send'))).toHaveLength(1))
  await first.dispose()
  const brokerRoot = join(await realpath(f.root), 'registration-bootstrap', sha(f.config.id), 'credentials')
  const key = credentialKey('anp-identity-manager', 'management-broker-' + sha(JSON.stringify([brokerRoot, f.config.id])))
  await f.context.credentials.deleteRecord(key)
  await unlink(join(brokerRoot, '.key-established'))
  const second = f.start()
  await vi.waitFor(() => expect(second.status()).toMatchObject({ phase: 'blocked', reason: 'credential_unavailable' }))
  expect(await f.context.credentials.readRecord(key)).toBeUndefined()
  expect(f.requests.filter(request => request.url.endsWith('email-send'))).toHaveLength(1)
  expect(f.register).not.toHaveBeenCalled()
})

it.each(['provider', 'manager'] as const)('withholds a verified response and sends no registration after %s revocation during a network await', async kind => {
  const f = await fixture(); f.approve()
  let release!: (value: Response) => void
  f.holdStatus(new Promise(resolve => { release = resolve }))
  const controller = f.start()
  await vi.waitFor(() => expect(f.requests).toHaveLength(1))
  if (kind === 'provider') f.revokeProvider(); else f.revokeManager()
  const reply = response({ verified: true })
  const cancel = vi.spyOn(reply.body!, 'cancel')
  release(reply)
  await vi.waitFor(() => expect(controller.status().phase).toBe('blocked'))
  expect(f.register).not.toHaveBeenCalled()
  expect(f.requests).toHaveLength(1)
  expect(cancel).toHaveBeenCalled()
})

it('rechecks the pinned provider after awaiting publication status before starting publication', async () => {
  const f = await fixture(); f.approve(); f.verify()
  let release!: (value: { state: 'local'; did: string }) => void
  const held = new Promise<{ state: 'local'; did: string }>(resolve => { release = resolve })
  const query = vi.spyOn(f.manager, 'publicationStatus').mockImplementation(() => held)
  const controller = f.start()
  try {
    await vi.waitFor(() => expect(query).toHaveBeenCalled())
    f.revokeProvider(); release({ state: 'local', did: f.reference.did })
    await vi.waitFor(() => expect(controller.status().phase).toBe('blocked'))
    expect(f.manager.publishIdentity).not.toHaveBeenCalled()
  } finally { release({ state: 'local', did: f.reference.did }); await controller.dispose() }
})

it('rechecks the pinned provider after the register body clone await and before the physical fetch', async () => {
  const f = await fixture({ registerViaTransport: true }); f.approve(); f.verify()
  const original = Request.prototype.clone
  let entered!: () => void, release!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  const held = new Promise<void>(resolve => { release = resolve })
  vi.spyOn(Request.prototype, 'clone').mockImplementation(function (this: Request) {
    const copy = original.call(this)
    if (new URL(this.url).pathname === '/user-service/v1/did-auth/rpc') {
      Object.defineProperty(copy, 'json', { value: async () => { entered(); await held; return { method: 'register' } } })
    }
    return copy
  })
  const controller = f.start()
  try {
    await started; f.revokeProvider(); release()
    await vi.waitFor(() => expect(controller.status().phase).toBe('registration_uncertain'))
    expect(f.requests.filter(request => request.url.endsWith('/did-auth/rpc'))).toHaveLength(0)
  } finally { release(); await controller.dispose(); vi.restoreAllMocks() }
})

it('requires exactly one contact method and never accepts a configured OTP', () => {
  const base = { id: 'phone', requestId: 'request', stateRoot: '/private/state', origin: 'https://identity.example', clientName: 'Agent' }
  expect(RegistrationBootstrapConfigSchema.safeParse(base).success).toBe(false)
  expect(RegistrationBootstrapConfigSchema.safeParse({ ...base, phone: '+15555550190' }).success).toBe(true)
  expect(RegistrationBootstrapConfigSchema.safeParse({ ...base, phone: '15555550190' }).success).toBe(false)
  expect(RegistrationBootstrapConfigSchema.safeParse({ ...base, phone: '+15555550190', email: 'agent@example.com' }).success).toBe(false)
  expect(RegistrationBootstrapConfigSchema.safeParse({ ...base, phone: '+15555550190', otp_code: '314159' }).success).toBe(false)
})

it('sends one exact Handle-bound phone challenge after approval and keeps the user code out of state', async () => {
  const f = await fixture({ phone: true }); const controller = f.start()
  expect(() => controller.submitOtp('314159')).toThrow('bootstrap_otp_unavailable')
  await vi.waitFor(() => expect(f.manager.getRequest).toHaveBeenCalled())
  expect(f.requests).toHaveLength(0)
  f.approve()
  await vi.waitFor(() => expect(controller.status().phase).toBe('awaiting_phone_verification'))
  expect(f.requests).toHaveLength(1)
  const challenge = f.requests[0]!
  expect(challenge.url).toBe('https://identity.example/user-service/v1/handle/rpc')
  expect((await challenge.clone().json()).params).toEqual({ phone: '+15555550190', purpose: 'awiki.identity.register.v1', handle: 'agent', domain: 'identity.example', full_handle: 'agent.identity.example' })
  expect(() => controller.submitOtp('invalid')).toThrow('bootstrap_otp_unavailable')
  controller.submitOtp('314159')
  expect(() => controller.submitOtp('271828')).toThrow('bootstrap_otp_unavailable')
  await vi.waitFor(() => expect(controller.status().phase).toBe('published'))
  expect(f.register).toHaveBeenCalledOnce()
  expect(f.register.mock.calls[0]![1].registration).toEqual({ handle: 'agent', phone: '+15555550190', otp_code: '314159' })
  const journal = await readFile(join(await realpath(f.root), 'registration-bootstrap', sha(f.config.id), 'state.json'), 'utf8')
  expect(journal + JSON.stringify(controller.status())).not.toMatch(/314159|15555550190/u)
  await controller.dispose()
  expect(() => controller.submitOtp('314159')).toThrow()
})

it('restores a confirmed phone challenge without resending or retaining a submitted OTP', async () => {
  const f = await fixture({ phone: true }); f.approve()
  const first = f.start()
  await vi.waitFor(() => expect(first.status().phase).toBe('awaiting_phone_verification'))
  first.submitOtp('314159'); await first.dispose()
  const second = f.start()
  await vi.waitFor(() => expect(second.status().phase).toBe('awaiting_phone_verification'))
  expect(f.requests).toHaveLength(1); expect(f.register).not.toHaveBeenCalled()
  second.submitOtp('314159')
  await vi.waitFor(() => expect(second.status().phase).toBe('published'))
})

it('does not accept an OTP or register when the SMS send has a rejected receipt', async () => {
  const f = await fixture({ phone: true, phoneRejected: true }); f.approve()
  const first = f.start()
  await vi.waitFor(() => expect(first.status()).toMatchObject({ phase: 'blocked', reason: 'phone_unavailable' }))
  expect(() => first.submitOtp('314159')).toThrow('bootstrap_otp_unavailable')
  await first.dispose()
  const second = f.start()
  await vi.waitFor(() => expect(second.status()).toMatchObject({ phase: 'blocked', reason: 'phone_unavailable' }))
  expect(f.requests).toHaveLength(1); expect(f.register).not.toHaveBeenCalled()
  expect(JSON.stringify(second.status())).not.toContain('private provider detail')
})

it('treats HTTP 200 upgrade bodies on SMS send as rejection, not a delivered challenge', async () => {
  const f = await fixture({ phone: true, upgrade: true }); f.approve()
  const controller = f.start()
  await vi.waitFor(() => expect(controller.status()).toMatchObject({ phase: 'blocked', reason: 'client_upgrade_required',
    origin: 'https://identity.example', clientVersion: expectedClientVersion }))
  expect(f.requests).toHaveLength(1)
  expect(f.requests[0]!.url).toBe('https://identity.example/user-service/v1/handle/rpc')
  expect(f.requests[0]!.headers.get('X-AWiki-Client-Version')).toBe(expectedClientVersion)
  const journal = JSON.parse(await readFile(join(await realpath(f.root), 'registration-bootstrap', sha(f.config.id), 'state.json'), 'utf8'))
  expect(journal.phoneDelivered).toBe(false)
  expect(journal.registerStarted).toBe(false)
  expect(f.register).not.toHaveBeenCalled()
  expect(() => controller.submitOtp('314159')).toThrow('bootstrap_otp_unavailable')
})
