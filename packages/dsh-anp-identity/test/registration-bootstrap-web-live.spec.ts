/** One opt-in Linux rootless Web fresh path, through actual C approval/native proof and strict B. */
import { createHash } from 'node:crypto'
import { mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { expect, it } from 'vitest'
import { createProductHostFixture } from './helpers/product-host-fixture.js'

const source = process.env.DSH_IDENTITY_USER_SERVICE_SOURCE
const python = process.env.DSH_IDENTITY_PYTHON
const digest = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex')
async function sources(): Promise<Record<string, string>> {
  return Object.fromEntries(await Promise.all([
    ...['index.ts', 'registration-bootstrap.ts', 'management-driver.ts', 'protocol-bootstrap.ts', 'host-management-secret.ts', 'provider.ts'].map(async name => ['C/' + name, digest(await readFile(new URL('../src/' + name, import.meta.url)))]),
    ...['registration-bootstrap-web-live.spec.ts', 'helpers/product-host-fixture.ts', 'helpers/strict-bootstrap-bridge.ts'].map(async name => ['fixture/' + name, digest(await readFile(new URL(name, import.meta.url)))]),
    ...['tests/app/cimd/management_bridge.py', 'tests/app/cimd/strict_bootstrap.py', 'src/user_service/app/did_auth/registration_command.py'].map(async name => ['B/' + name, digest(await readFile(join(source!, name)))]),
  ]))
}

it.skipIf(process.platform !== 'linux' || !source || !python)('Web fresh approval, real UUID proof, factor, publication and same-store restoration remain rootless', async () => {
  const before = await sources()
  const nativeSha256 = digest(await readFile(new URL('../../../bindings/node/anp-identity.linux-x64-gnu.node', import.meta.url)))
  expect(nativeSha256).toBe('e2c4b86a0b3622aaefa70b44d3dc31cdab579b1237a4418d349bd294c52663ef')
  const fixture = await createProductHostFixture({ source: source!, python: python!, profile: 'web', manual: true })
  let operationId: string | undefined
  let publicSha256: { metadata: string; jwks: string } | undefined
  try {
    expect((await fixture.userControl.review()).request).toMatchObject({ kind: 'create', status: 'pending', parameters: { profile: 'web', usage: 'protocol' } })
    expect(fixture.evidence.facts).toHaveLength(0)
    await fixture.approveAndConfirm()
    expect(fixture.publicRef.did).toMatch(/^did:web:identity\.example:awiki:web:/u)
    const document = await fixture.publicDocument() as { id: string; proof?: unknown; verificationMethod?: Array<{ id: string }> }
    expect(document.id).toBe(fixture.publicRef.did)
    expect(Object.hasOwn(document, 'proof')).toBe(false)
    expect(document.verificationMethod?.some(method => method.id.endsWith('#root'))).toBe(false)
    expect(JSON.stringify(document)).not.toMatch(/RootControl|root_control/u)
    const registered = fixture.evidence.facts.filter(fact => fact.rpc === 'register')
    expect(registered).toHaveLength(1)
    expect(registered[0]?.webBootstrapProofPresent).toBe(true)
    operationId = registered[0]?.registrationOperationId
    expect(operationId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u)
    const directory = join(fixture.root, 'bootstrap', 'registration-bootstrap')
    const scopes = await readdir(directory)
    expect(scopes).toHaveLength(1)
    const journalPath = join(directory, scopes[0]!, 'state.json')
    const journal = JSON.parse(await readFile(journalPath, 'utf8')) as { webOperationId?: string; registered: boolean }
    expect(journal).toMatchObject({ webOperationId: operationId, registered: true })
    const material = fixture.publicMaterials
    publicSha256 = { metadata: digest(material.metadata), jwks: digest(material.jwks) }
    const client = JSON.parse(material.metadata) as { client_id: string; grant_types: string[] }
    expect(client.client_id).toBe(fixture.status().clientId)
    expect(client.grant_types).toEqual(['client_credentials'])
    expect(fixture.evidence.observations.deviceCredentialReceivedInternally).toBe(true)
    expect(fixture.evidence.excludesInternalCredentials({ document, material, status: fixture.status() })).toBe(true)
    const reference = fixture.publicRef
    await fixture.reopen()
    expect(fixture.publicRef).toEqual(reference)
    expect(fixture.status()).toMatchObject({ phase: 'published', clientId: client.client_id })
    expect(JSON.parse(await readFile(journalPath, 'utf8')).webOperationId).toBe(operationId)
    expect(fixture.evidence.facts.filter(fact => fact.rpc === 'register')).toHaveLength(1)
    expect(fixture.evidence.facts.filter(fact => fact.path.endsWith('/auth/email-send'))).toHaveLength(1)
    expect(await sources()).toEqual(before)
  } finally { await fixture.dispose() }
  expect(fixture.evidence.cleanup.complete).toBe(true)
  await expect(stat(fixture.root)).rejects.toMatchObject({ code: 'ENOENT' })
  const result = { passed: true, lane: 'actual-fresh-rootless-Web-C-B-native', sourceSha256: before, nativeSha256,
    profile: 'web', rootControl: 'absent-from-native-Web-public-document-no-RootControl-operation-attempted',
    registrationOperationId: operationId, stableAfterRestart: true, registerRequests: 1, emailSends: 1, publicSha256,
    deviceAccess: 'internal-only', cleanup: { ...fixture.evidence.cleanup, nativeAndBrokerRootRemoved: fixture.root },
    boundaries: { systemTest: false, productE2E: false, modelRun: false, externalSMTPandSiteverify: 'fixture-transport', BOrigin: 'logical-HTTPS-ASGI' } }
  if (process.env.DSH_IDENTITY_BOOTSTRAP_WEB_RESULT) {
    await mkdir(dirname(process.env.DSH_IDENTITY_BOOTSTRAP_WEB_RESULT), { recursive: true, mode: 0o700 })
    await writeFile(process.env.DSH_IDENTITY_BOOTSTRAP_WEB_RESULT, JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' })
  }
}, 180000)
