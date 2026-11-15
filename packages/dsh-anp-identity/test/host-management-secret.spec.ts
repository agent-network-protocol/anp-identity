/** Host key custody against the actual isolated credentials-local record provider. */
import { mkdtemp, mkdir, readFile, readdir, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { Context } from '@deepseek-ai/cordis'
import { LocalCredentialProvider } from '@deepseek-ai/dsh-credentials-local'
import type { CredentialKey, CredentialRecord } from '@deepseek-ai/dsh-credentials'
import { afterEach, describe, expect, it } from 'vitest'
import { createHostManagementSecret, HostManagementSecretError } from '../src/host-management-secret.js'
import type { HostManagementSecretContext, HostManagementSecretOptions } from '../src/host-management-secret.js'
import { EncryptedManagementCredentialBroker } from '../src/management-credentials.js'

const cleanups: Array<() => Promise<unknown>> = []
afterEach(async () => { while (cleanups.length) await cleanups.pop()!() })

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'anp-host-management-secret-'))
  cleanups.push(() => rm(root, { recursive: true, force: true }))
  return root
}

async function boot(root: string): Promise<Context> {
  const context = new Context()
  const fiber = context.plugin(LocalCredentialProvider, { path: join(root, '.credentials.yaml'), dshHome: root, watch: false })
  cleanups.push(() => fiber.dispose())
  await fiber
  return context
}

function accessor(context: HostManagementSecretContext, root: string, extra: Partial<HostManagementSecretOptions> = {}) {
  const value = createHostManagementSecret({ context, stateRoot: root, bootstrapId: 'desktop-primary', hasExistingCiphertext: async () => false, ...extra })
  cleanups.push(async () => value.dispose())
  return value
}

async function recordKey(context: Context): Promise<CredentialKey> {
  const entries = await context.credentials.listRecords()
  expect(entries.length).toBe(1)
  const key = entries[0]!.key
  expect(/^anp-identity-manager\/management-broker-[a-f0-9]{64}$/u.test(key)).toBe(true)
  return key
}

function deferred() {
  let resolve!: () => void
  const promise = new Promise<void>(done => { resolve = done })
  return { promise, resolve }
}

async function expectUnavailable(request: Promise<unknown>): Promise<void> {
  const refused = await request.then(value => { if (Buffer.isBuffer(value)) value.fill(0); return false }, error => error instanceof HostManagementSecretError && error.code === 'credential_unavailable')
  expect(refused).toBe(true)
}

describe('Host management secret with actual credentials-local', () => {
  it('creates one durable key through competing provider instances and returns independent buffers without rewriting it', async () => {
    const root = await temporaryRoot()
    const firstContext = await boot(root), secondContext = await boot(root)
    let updates = 0
    firstContext.on('credentials/record-updated', () => { updates++ })
    secondContext.on('credentials/record-updated', () => { updates++ })
    const first = accessor(firstContext, root), second = accessor(secondContext, root)
    const [a, b] = await Promise.all([first.getKey(), second.getKey()])
    try {
      expect(a.length === 32 && b.length === 32).toBe(true)
      expect(a !== b && a.equals(b)).toBe(true)
      const observedUpdates = updates
      await recordKey(firstContext)
      const path = join(root, '.credentials.yaml'), before = await readFile(path)
      if (process.platform !== 'win32') expect(((await stat(path)).mode & 0o077) === 0).toBe(true)
      a.fill(0)
      const c = await first.getKey()
      try { expect(c !== b && c.equals(b) && !c.equals(a)).toBe(true) }
      finally { c.fill(0) }
      expect((await readFile(path)).equals(before)).toBe(true)
      expect(updates).toBe(observedUpdates)
    } finally { a.fill(0); b.fill(0) }
  })

  it('uses the same persisted key after a new provider and accessor boot when protected data exists', async () => {
    const root = await temporaryRoot(), context = await boot(root)
    const original = accessor(context, root), first = await original.getKey()
    original.dispose()
    const restarted = accessor(await boot(root), root, { hasExistingCiphertext: async () => true })
    const next = await restarted.getKey()
    try { expect(first !== next && first.equals(next)).toBe(true) }
    finally { first.fill(0); next.fill(0) }
  })

  it('partitions keys by the stable Host state root and bootstrap identifier', async () => {
    const root = await temporaryRoot(), context = await boot(root)
    const first = await accessor(context, root).getKey()
    const second = await accessor(context, root, { bootstrapId: 'desktop-secondary' }).getKey()
    const third = await accessor(context, join(root, 'other-state')).getKey()
    try {
      expect(!first.equals(second) && !first.equals(third) && !second.equals(third)).toBe(true)
      expect((await context.credentials.listRecords()).length).toBe(3)
    } finally { first.fill(0); second.fill(0); third.fill(0) }
  })

  it('isolates real ciphertext and missing-key checks between independent stable broker directories', async () => {
    const home = await temporaryRoot(), context = await boot(home)
    const firstRoot = join(home, 'broker-a'), secondRoot = join(home, 'broker-b')
    await mkdir(firstRoot, { mode: 0o700 }); await mkdir(secondRoot, { mode: 0o700 })
    const hasCiphertext = (root: string) => async () => (await readdir(root)).some(name => name.endsWith('.json'))
    const firstSecret = accessor(context, firstRoot, { bootstrapId: 'bootstrap-a', hasExistingCiphertext: hasCiphertext(firstRoot) })
    const first = new EncryptedManagementCredentialBroker(firstRoot, () => firstSecret.getKey())
    const reference = { storeId: 'isolated-store', identityId: 'isolated-identity', did: 'did:web:isolated.example' }
    const firstCredential = { accessToken: randomBytes(32).toString('base64url'), deviceId: 'device-a', signingKeyId: 'key-a' }
    await first.set(reference, 'https://service.example', firstCredential)
    const firstKey = await recordKey(context)
    const secondSecret = accessor(context, secondRoot, { bootstrapId: 'bootstrap-b', hasExistingCiphertext: hasCiphertext(secondRoot) })
    const second = new EncryptedManagementCredentialBroker(secondRoot, () => secondSecret.getKey())
    const secondCredential = { accessToken: randomBytes(32).toString('base64url'), deviceId: 'device-b', signingKeyId: 'key-b' }
    await second.set(reference, 'https://service.example', secondCredential)
    expect((await first.get(reference, 'https://service.example'))?.accessToken === firstCredential.accessToken).toBe(true)
    expect((await second.get(reference, 'https://service.example'))?.accessToken === secondCredential.accessToken).toBe(true)
    const secondKey = (await context.credentials.listRecords()).find(entry => entry.key !== firstKey)!.key
    await context.credentials.deleteRecord(secondKey)
    await expectUnavailable(second.get(reference, 'https://service.example'))
    expect((await first.get(reference, 'https://service.example'))?.accessToken === firstCredential.accessToken).toBe(true)
  })

  const validShape = Buffer.alloc(32, 1).toString('base64url')
  const invalidRecords: Array<{ label: string; record: CredentialRecord }> = [
    { label: 'grant kind', record: { kind: 'grant', payload: { value: 'not-an-encryption-key' } } },
    { label: 'missing key', record: { kind: 'api-key' } },
    { label: 'wrong key length', record: { kind: 'api-key', key: 'short' } },
    { label: 'noncanonical key encoding', record: { kind: 'api-key', key: validShape.slice(0, -1) + 'F' } },
    { label: 'environment-bearing record', record: { kind: 'api-key', key: validShape, env: { UNRELATED_VALUE: 'configured' } } },
  ]
  for (const { label, record } of invalidRecords) {
    it(`refuses a persisted ${label} without overwriting the record`, async () => {
      const root = await temporaryRoot(), context = await boot(root), secret = accessor(context, root)
      const initial = await secret.getKey(); initial.fill(0)
      const key = await recordKey(context)
      await context.credentials.modifyRecord(key, async () => record)
      const before = await readFile(join(root, '.credentials.yaml'))
      await expectUnavailable(secret.getKey())
      expect((await readFile(join(root, '.credentials.yaml'))).equals(before)).toBe(true)
    })
  }

  it('does not recreate a deleted key over real encrypted broker data, including after restart and a stale provider cache', async () => {
    const root = await temporaryRoot(), brokerRoot = join(root, 'broker')
    await mkdir(brokerRoot, { mode: 0o700 })
    const context = await boot(root), external = await boot(root)
    const hasExistingCiphertext = async () => (await readdir(brokerRoot)).some(name => name.endsWith('.json'))
    const secret = accessor(context, root, { hasExistingCiphertext })
    const broker = new EncryptedManagementCredentialBroker(brokerRoot, () => secret.getKey())
    const reference = { storeId: 'isolated-store', identityId: 'isolated-identity', did: 'did:web:isolated.example' }
    const credential = { accessToken: randomBytes(32).toString('base64url'), deviceId: 'device', signingKeyId: 'device-key' }
    await broker.set(reference, 'https://service.example', credential)
    const restored = await broker.get(reference, 'https://service.example')
    expect(restored?.accessToken === credential.accessToken).toBe(true)
    const file = join(brokerRoot, (await readdir(brokerRoot)).find(name => name.endsWith('.json'))!)
    const ciphertext = await readFile(file)
    expect(ciphertext.includes(Buffer.from(credential.accessToken))).toBe(false)
    const key = await recordKey(context)
    await external.credentials.deleteRecord(key)
    expect(await context.credentials.readRecord(key) !== undefined).toBe(true)
    await expectUnavailable(broker.get(reference, 'https://service.example'))
    await expectUnavailable(broker.set(reference, 'https://service.example', credential))
    const restarted = accessor(await boot(root), root, { hasExistingCiphertext })
    await expectUnavailable(restarted.getKey())
    expect((await readFile(file)).equals(ciphertext)).toBe(true)
    expect((await external.credentials.listRecords()).length).toBe(0)
  })

  it('does not regenerate a key already returned by this accessor even before ciphertext has been written', async () => {
    const root = await temporaryRoot(), context = await boot(root), secret = accessor(context, root)
    const first = await secret.getKey(); first.fill(0)
    await context.credentials.deleteRecord(await recordKey(context))
    await expectUnavailable(secret.getKey())
    expect((await context.credentials.listRecords()).length).toBe(0)
  })

  it('refuses key creation when protected broker state cannot be inspected', async () => {
    const root = await temporaryRoot(), context = await boot(root)
    const secret = accessor(context, root, { hasExistingCiphertext: async () => { throw new Error('Protected broker state is unreadable') } })
    await expectUnavailable(secret.getKey())
    expect((await context.credentials.listRecords()).length).toBe(0)
  })

  it('refuses missing or read-only providers with a stable error that excludes provider details', async () => {
    const root = await temporaryRoot(), context = await boot(root)
    const secret = accessor(context, root), first = await secret.getKey(); first.fill(0)
    const marker = randomBytes(32).toString('base64url')
    const readonlyContext: HostManagementSecretContext = { credentials: {
      readRecord: context.credentials.readRecord.bind(context.credentials),
      modifyRecord: async () => { throw new Error(marker) },
    } }
    const failedContext: HostManagementSecretContext = { get credentials(): HostManagementSecretContext['credentials'] { throw new Error(marker) } }
    for (const unavailable of [accessor({}, root), accessor(readonlyContext, root), accessor(failedContext, root)]) {
      const error = await unavailable.getKey().catch((value: unknown) => value)
      expect(error instanceof HostManagementSecretError).toBe(true)
      expect((error as HostManagementSecretError).code).toBe('credential_unavailable')
      expect(String(error).includes(marker) || JSON.stringify(error).includes(marker)).toBe(false)
      expect(Object.hasOwn(error as object, 'cause')).toBe(false)
    }
  })

  it('refuses creation if disposed while the live encrypted-state observation is pending', async () => {
    const root = await temporaryRoot(), context = await boot(root), entered = deferred(), resume = deferred()
    const secret = accessor(context, root, { hasExistingCiphertext: async () => { entered.resolve(); await resume.promise; return false } })
    const request = secret.getKey()
    const rejection = expectUnavailable(request)
    await entered.promise
    secret.dispose(); resume.resolve()
    await rejection
    expect((await context.credentials.listRecords()).length).toBe(0)
    await expectUnavailable(secret.getKey())
  })

  it('withholds an in-flight committed key after disposal, service removal or Host revocation', async () => {
    for (const mode of ['dispose', 'service-removed', 'host-revoked'] as const) {
      const root = await temporaryRoot(), context = await boot(root), committed = deferred(), resume = deferred()
      const real = context.credentials
      let active = true
      const holder: { credentials: HostManagementSecretContext['credentials'] } = { credentials: {
        readRecord: real.readRecord.bind(real),
        modifyRecord: async (key, mutate) => { const value = await real.modifyRecord(key, mutate); committed.resolve(); await resume.promise; return value },
      } }
      const secret = accessor(holder, root, { assertActive: () => { if (!active) throw new Error('Host context revoked') } }), request = secret.getKey()
      const rejection = expectUnavailable(request)
      await committed.promise
      if (mode === 'service-removed') holder.credentials = undefined
      else if (mode === 'host-revoked') active = false
      else secret.dispose()
      resume.resolve()
      await rejection
      expect((await real.listRecords()).length).toBe(1)
    }
  })
})
