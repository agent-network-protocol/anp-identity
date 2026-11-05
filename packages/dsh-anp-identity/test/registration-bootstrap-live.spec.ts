/** Opt-in Linux module composition: actual Loader/C/A and strict B middleware, factors and SQL. */
import { createHash } from 'node:crypto'
import { mkdir, readFile, readdir, realpath, stat, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, describe, expect, it } from 'vitest'
import { createProductHostFixture } from './helpers/product-host-fixture.js'

const source = process.env.DSH_IDENTITY_USER_SERVICE_SOURCE
const python = process.env.DSH_IDENTITY_PYTHON
const HEADER = { 'X-AWiki-Client-Version': 'dsh-identity/1106/0.1.6' }
const digest = (value: string | Buffer) => createHash('sha256').update(value).digest('hex')
const results: Array<Record<string, unknown>> = []
let initialSource: Record<string, string> | undefined
let runtimeEvidence: Record<string, unknown> | undefined

async function fingerprints(): Promise<Record<string, string>> {
  const cFiles = ['index.ts', 'registration-bootstrap.ts', 'protocol-bootstrap.ts', 'host-management-secret.ts', 'management-remote.ts', 'management-driver.ts', 'installed-consumer.ts', 'provider.ts', 'target-policy.ts', 'management-credentials.ts', 'publication.ts', 'publication-http.ts']
  const bFiles = ['tests/app/cimd/management_bridge.py', 'tests/app/cimd/strict_bootstrap.py', 'tests/app/cimd/isolated_redis.py', 'src/user_service/app/client_version_policy.py', 'src/user_service/app/email_verify/router.py', 'src/user_service/core/providers/email/provider.py', 'src/user_service/app/did_auth/registration_command.py']
  return Object.fromEntries(await Promise.all([
    ...cFiles.map(async name => ['C/' + name, digest(await readFile(new URL('../src/' + name, import.meta.url)))]),
    ...bFiles.map(async name => ['B/' + name, digest(await readFile(join(source!, name)))]),
    ...['registration-bootstrap-live.spec.ts', 'helpers/strict-bootstrap-bridge.ts', 'helpers/product-host-fixture.ts'].map(async name => ['fixture/' + name, digest(await readFile(new URL(name, import.meta.url)))]),
    ...['package.json', 'package-lock.json'].map(async name => ['C/' + name, digest(await readFile(new URL('../' + name, import.meta.url)))]),
  ]))
}
async function sourceGuard() {
  const current = await fingerprints()
  initialSource ??= current
  expect(current).toEqual(initialSource)
  if (!runtimeEvidence) {
    const directory = fileURLToPath(new URL('../', import.meta.url))
    const lock = JSON.parse(await readFile(join(directory, 'package-lock.json'), 'utf8')) as { packages: Record<string, { version: string; resolved?: string; integrity?: string }> }
    const registryDependencies = Object.fromEntries(await Promise.all(['@deepseek-ai/cordis', '@deepseek-ai/cordis-plugin-loader', '@deepseek-ai/dsh-credentials', '@deepseek-ai/dsh-credentials-local'].map(async name => {
      const entry = lock.packages['node_modules/' + name]!
      expect(entry.resolved?.startsWith('https://registry.npmjs.org/')).toBe(true)
      const installed = join(directory, 'node_modules', name)
      expect((await realpath(installed)).startsWith(join(directory, 'node_modules') + '/')).toBe(true)
      expect(JSON.parse(await readFile(join(installed, 'package.json'), 'utf8')).version).toBe(entry.version)
      return [name, { version: entry.version, resolved: entry.resolved, integrity: entry.integrity }]
    })))
    const nativeSha256 = digest(await readFile(new URL('../../../bindings/node/anp-identity.linux-x64-gnu.node', import.meta.url)))
    expect(nativeSha256).toBe('e2c4b86a0b3622aaefa70b44d3dc31cdab579b1237a4418d349bd294c52663ef')
    runtimeEvidence = { registryDependencies, nativeSha256, nativeStoreRoot: 'explicit-local-file-test-root-not-OS-keyring' }
  }
}
async function ciphertexts(root: string): Promise<string[]> {
  const base = join(root, 'bootstrap', 'registration-bootstrap')
  const paths: string[] = []
  for (const scope of await readdir(base).catch(() => [])) {
    const credentials = join(base, scope, 'credentials')
    for (const name of await readdir(credentials).catch(() => [])) if (/^[a-f0-9]{64}\.json$/u.test(name)) paths.push(join(credentials, name))
  }
  return paths
}
async function consumedFactor(fixture: Awaited<ReturnType<typeof createProductHostFixture>>) {
  const url = new URL(fixture.origin + '/user-service/v1/auth/email-status')
  url.searchParams.set('email', fixture.userControl.email)
  url.searchParams.set('handle', fixture.userControl.fullHandle)
  const response = await fixture.requestForTest(new Request(url, { headers: HEADER }))
  expect(await response.json()).toMatchObject({ verified: false })
}
async function cleaned(fixture: Awaited<ReturnType<typeof createProductHostFixture>>) {
  expect(fixture.evidence.cleanup.complete).toBe(true)
  await expect(stat(fixture.root)).rejects.toMatchObject({ code: 'ENOENT' })
  await sourceGuard()
  return { ...fixture.evidence.cleanup, nativeAndBrokerRootRemoved: fixture.root, nativeAndBrokerRootAbsent: true }
}

describe.skipIf(process.platform !== 'linux' || !source || !python)('fresh product Host registration', () => {
  afterAll(async () => {
    const result = { passed: results.length === 3, lane: 'actual-Loader-C-manager-native-B-strict-bootstrap', sourceSha256: initialSource, ...runtimeEvidence,
      deviceAccess: 'internal-only', cases: results, systemProductE2E: 'not-run' }
    if (process.env.DSH_IDENTITY_BOOTSTRAP_RESULT) {
      await mkdir(dirname(process.env.DSH_IDENTITY_BOOTSTRAP_RESULT), { recursive: true, mode: 0o700 })
      await writeFile(process.env.DSH_IDENTITY_BOOTSTRAP_RESULT, JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' })
    }
  })

  it('approves, verifies the real mail factor, publishes and restores without repeating registration or email', async () => {
    await sourceGuard()
    const fixture = await createProductHostFixture({ source: source!, python: python!, manual: true })
    const facts = fixture.evidence.facts
    let publicSha256: { metadata: string; jwks: string } | undefined
    try {
      expect((await fixture.userControl.review()).request.status).toBe('pending')
      expect(facts).toHaveLength(0)
      for (const clientVersion of [undefined, 'dsh-identity/1105/0.1.5']) {
        const response = await fixture.requestForTest(new Request(fixture.origin + '/user-service/v1/auth/email-send', {
          method: 'POST', headers: { 'content-type': 'application/json', ...(clientVersion ? { 'X-AWiki-Client-Version': clientVersion } : {}) },
          body: JSON.stringify({ email: fixture.userControl.email, handle: fixture.userControl.fullHandle }),
        }))
        expect(await response.json()).toMatchObject({ error: { data: { awiki_code: 'client.upgrade_required' } } })
      }
      await fixture.userControl.decide('approve')
      await fixture.waitForPhase('awaiting_email_verification')
      await expect.poll(() => facts.filter(value => value.path.endsWith('/auth/email-send') && value.clientVersion === HEADER['X-AWiki-Client-Version']).length).toBe(1)
      expect(facts.some(value => value.rpc === 'register')).toBe(false)
      expect(await fixture.userControl.confirmEmail('invalid-email-token')).toBe(false)
      expect(fixture.status().phase).toBe('awaiting_email_verification')
      expect(facts.some(value => value.rpc === 'register')).toBe(false)
      expect(await fixture.userControl.confirmEmail()).toBe(true)
      await fixture.readPublished()
      const status = fixture.status()
      expect(fixture.evidence.observations.deviceCredentialReceivedInternally).toBe(true)
      expect(fixture.evidence.observations.deviceAuthorizationRequests).toBeGreaterThan(0)
      expect(JSON.stringify(status)).not.toMatch(/access_token|accessToken|ciphertext|claim_secret|activation|@example\.com/u)
      expect(fixture.evidence.excludesInternalCredentials(status)).toBe(true)
      expect((await stat(join(fixture.root, '.credentials.yaml'))).mode & 0o077).toBe(0)
      const files = await ciphertexts(fixture.root)
      expect(files).toHaveLength(1)
      const cipher = await readFile(files[0]!, 'utf8')
      expect(JSON.parse(cipher)).toMatchObject({ schema: 1 })
      expect(fixture.evidence.excludesInternalCredentials(cipher)).toBe(true)
      expect((await stat(files[0]!)).mode & 0o077).toBe(0)
      await consumedFactor(fixture)
      const material = fixture.publicMaterials
      const metadata = JSON.parse(material.metadata) as { client_id: string; grant_types: string[] }
      const jwks = JSON.parse(material.jwks) as { keys: Array<Record<string, unknown>> }
      expect(metadata.client_id).toBe(status.clientId)
      expect(metadata.grant_types).toEqual(['client_credentials'])
      expect(jwks.keys.length).toBeGreaterThan(0)
      expect(jwks.keys.every(key => !Object.hasOwn(key, 'd') && key.kty === 'EC' && key.crv === 'P-256')).toBe(true)
      publicSha256 = { metadata: digest(material.metadata), jwks: digest(material.jwks) }
      const reference = fixture.publicRef
      await fixture.reopen()
      expect(fixture.status()).toMatchObject({ phase: 'published', clientId: status.clientId, reference })
      expect(facts.filter(value => value.rpc === 'register')).toHaveLength(1)
      expect(facts.filter(value => value.path.endsWith('/auth/email-send') && value.clientVersion === HEADER['X-AWiki-Client-Version'])).toHaveLength(1)
      const beforeDenial = facts.length
      expect(await fixture.denyFreshRequest()).toMatchObject({ phase: 'blocked', reason: 'approval_denied' })
      expect(facts).toHaveLength(beforeDenial)
    } finally { await fixture.dispose() }
    results.push({ case: 'fresh-publish-restore', passed: true, registerRequests: 1, productionEmailSends: 1, publicSha256,
      negatives: ['missing-version', 'low-version', 'invalid-email-token-with-real-siteverify', 'user-denied'], cleanup: await cleaned(fixture) })
  }, 180000)

  it('rejects a late email-status body after actual Loader provider disable before sending email or registering', async () => {
    await sourceGuard()
    const fixture = await createProductHostFixture({ source: source!, python: python!, manual: true })
    const gate = fixture.holdNextResponse('email-status')
    try {
      await fixture.userControl.decide('approve')
      await gate.entered
      await fixture.disableProvider()
      gate.release()
      await fixture.waitForPhase('blocked')
      expect(fixture.evidence.facts.filter(value => value.path.endsWith('/auth/email-send') || value.rpc === 'register' || value.rpc === 'device_registry_get')).toHaveLength(0)
      expect(fixture.evidence.observations.deviceCredentialReceivedInternally).toBe(false)
      expect(await ciphertexts(fixture.root)).toHaveLength(0)
    } finally { gate.release(); await fixture.dispose() }
    results.push({ case: 'provider-disabled-before-late-email-status', passed: true, physicalRegisterPosts: 0, subsequentEmailSends: 0, registryRequests: 0, brokerCiphertexts: 0, cleanup: await cleaned(fixture) })
  }, 180000)

  it('rejects an actual committed register response after provider disable without adopting Registry or writing a broker credential', async () => {
    await sourceGuard()
    const fixture = await createProductHostFixture({ source: source!, python: python!, manual: true })
    const gate = fixture.holdNextResponse('register-result')
    try {
      await fixture.userControl.decide('approve')
      await fixture.waitForPhase('awaiting_email_verification')
      await expect.poll(() => fixture.evidence.facts.filter(value => value.path.endsWith('/auth/email-send')).length).toBe(1)
      expect(await fixture.userControl.confirmEmail()).toBe(true)
      await gate.entered
      expect(fixture.evidence.observations.deviceCredentialReceivedInternally).toBe(true)
      await fixture.disableProvider()
      gate.release()
      await fixture.waitForPhase('registration_uncertain')
      expect(fixture.evidence.facts.filter(value => value.rpc === 'register')).toHaveLength(1)
      expect(fixture.evidence.facts.filter(value => value.rpc === 'device_registry_get')).toHaveLength(0)
      expect(await ciphertexts(fixture.root)).toHaveLength(0)
      await consumedFactor(fixture)
    } finally { gate.release(); await fixture.dispose() }
    results.push({ case: 'provider-disabled-after-committed-register-before-body', passed: true, physicalRegisterPosts: 1,
      remoteRegistration: 'committed-not-revoked-by-local-test', localPhase: 'registration_uncertain', registryRequests: 0, brokerCiphertexts: 0, cleanup: await cleaned(fixture) })
  }, 180000)
})
